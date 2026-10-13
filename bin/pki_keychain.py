#!/usr/bin/env python3
# PKI_KEYCHAIN_PATCH_V3
"""pki_keychain.py -- key passphrases in a KeePassXC database; its master
password in the macOS keychain, its key file on disk.

Database  $PKI_KEYCHAIN_DIR (default <PKI_ROOT>/keychain)/pki-structure.kdbx; dir 0700, file 0600.
Key file  $PKI_KEYCHAIN_KEYFILE (default <PKI_ROOT>/keyfile/pki-structure.keyx), KeePassXC
          XML v2, 0600. Required to open the database; keep a copy offline. Generated
          only when no database exists yet, never for an existing one.
Master    192 random bits, item "PKI-Structure KeePassXC Passphrase"
          ($PKI_KEYCHAIN_ITEM): System keychain as root (verified unreadable by
          other users), login keychain otherwise ($PKI_KEYCHAIN_FILE: another
          keychain file, for tests). Created only when definitively absent and
          never next to an existing database; an existing item is never replaced
          or deleted.
Entries   one per private key, found by SHA-256 of its public key, so every
          certificate of that key (same-key renewal) finds it.
          "<id16> :: <CN>": Password = key passphrase, UserName = serial,
          URL = certificate SHA-256. "<id16> :: <CN> :: p12": Password =
          .p12 export password.

  init                                   master item, key file and database; migrates pki.kdbx
  genkey --alg EC|RSA [--curve C] [--bits N] --out KEY [--label CN]
                                         encrypted key with a new passphrase; prints the key id
  id --cert CERT                         key id of a certificate
  record --cert CERT [--p12-like CERT]   attach certificate data; create the .p12 entry
  get (--id ID | --cert CERT) [--field key|p12]
                                         print a secret (stdout only)
  forget (--id ID | --cert CERT)         delete the key's entries
  verify                                 master item readable and opens the database
  export-master                          print the master password (escrow)
  import-master                          restore the master item from stdin; refuses if present
  migrate DIR [--rotate] [--remove-legacy]
                                         import DIR/private/passphrase.txt keys
  prune [-n]   list   acl-check
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import getpass
import hashlib
import os
import pty
import re
import secrets
import select
import shutil
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

PKI_ROOT = Path(__file__).resolve().parent.parent
ITEM = os.environ.get("PKI_KEYCHAIN_ITEM") or "PKI-Structure KeePassXC Passphrase"
DB_NAME = "pki-structure.kdbx"
LEGACY_DB_NAME = "pki.kdbx"
KEYFILE_NAME = "pki-structure.keyx"
SECURITY = "/usr/bin/security"
SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
ERR_NOT_FOUND = 44  # security(1) exit status for errSecItemNotFound
KDF_MS = "100"  # master is 192 random bits: a slow KDF adds nothing
TITLE_RE = re.compile(r"^[0-9a-f]{16} :: ")
os.umask(0o077)


class KeychainError(Exception):
    pass


def fail(msg: str):
    raise KeychainError(msg)


def new_secret() -> str:
    return secrets.token_urlsafe(24)  # 24 bytes = 192 bits


def openssl() -> str:
    return os.environ.get("OPENSSL") or shutil.which("openssl") or fail("openssl not found")


def kpcli() -> str:
    for c in (os.environ.get("KEEPASSXC_CLI", ""), "keepassxc-cli",
              "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli"):
        p = c and shutil.which(c)
        if p:
            return p
    return fail("keepassxc-cli not found (set KEEPASSXC_CLI)")


# ---------------------------------------------------------------- certificates
def load_cert(path) -> x509.Certificate:
    raw = Path(path).read_bytes()
    if b"-----BEGIN" in raw:
        return x509.load_pem_x509_certificate(raw)
    return x509.load_der_x509_certificate(raw)


def spki_id(pub) -> str:
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def cert_id(path) -> str:
    return spki_id(load_cert(path).public_key())


def cert_cn(c: x509.Certificate) -> str:
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        a = c.subject.get_attributes_for_oid(oid)
        if a:
            return str(a[0].value).replace("/", "_")
    return "unnamed"


def p12_opens(p12, pw: str) -> bool:
    r, w = os.pipe()
    os.write(w, (pw + "\n").encode())
    os.close(w)
    try:
        p = subprocess.run([openssl(), "pkcs12", "-legacy", "-noout", "-in", str(p12),
                            "-passin", f"fd:{r}"], pass_fds=(r,), capture_output=True)
    finally:
        os.close(r)
    return p.returncode == 0


# ---------------------------------------------------------------- macOS keychain
def sec(*args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run([SECURITY, *args], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, **kw)


def mk_target() -> str:
    f = os.environ.get("PKI_KEYCHAIN_FILE")
    if f:
        return f
    if os.geteuid() == 0:
        return SYSTEM_KEYCHAIN
    home = Path.home() / "Library" / "Keychains"
    for n in ("login.keychain-db", "login.keychain"):
        if (home / n).exists():
            return str(home / n)
    return fail("login keychain not found")


def mk_state() -> bool:
    """True if the master item exists, False only if the keychain says it is
    absent; any other failure (locked, unavailable) raises. Never infer absence."""
    r = sec("find-generic-password", "-s", ITEM, mk_target())
    if r.returncode == 0:
        return True
    if r.returncode == ERR_NOT_FOUND or "item could not be found" in r.stderr:
        return False
    return fail(f"cannot query '{ITEM}' in {mk_target()} (exit {r.returncode}): "
                f"{r.stderr.strip()}; nothing was changed")


def mk_get() -> str:
    r = sec("find-generic-password", "-s", ITEM, "-w", mk_target())
    if r.returncode:
        fail(f"cannot read '{ITEM}' from {mk_target()}: {r.stderr.strip()}")
    return r.stdout.rstrip("\n")


def mk_delete() -> None:
    """Only for an item created in this process with nothing depending on it."""
    sec("delete-generic-password", "-s", ITEM, mk_target())


def pty_security(args: list[str], secret: str) -> tuple[int, int]:
    """Run security(1) on a pty and answer its password prompts: the secret
    never appears in argv."""
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execv(SECURITY, [SECURITY, *args])
        finally:
            os._exit(127)
    buf, sent = b"", 0
    while True:
        ready, _, _ = select.select([fd], [], [], 30)
        if not ready:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            fail("security(1) timed out")
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        buf += data
        if re.search(rb"(?i)password[^\n]*: $", buf):
            os.write(fd, secret.encode() + b"\n")
            buf, sent = b"", sent + 1
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), sent


def default_keychain_ok() -> bool:
    """add-generic-password -w (prompting) takes no keychain argument and so
    writes to the default keychain; it must be the one queried."""
    if os.environ.get("PKI_KEYCHAIN_FILE"):
        return True
    r = sec("default-keychain")
    p = r.stdout.strip().strip('"')
    return r.returncode == 0 and bool(p) and os.path.realpath(p) == os.path.realpath(mk_target())


def root_only_ok() -> bool:
    """True if user 'nobody' cannot read the System keychain item."""
    if os.geteuid() != 0 or os.environ.get("PKI_KEYCHAIN_FILE"):
        return True
    r = subprocess.run([SECURITY, "find-generic-password", "-s", ITEM, "-w", SYSTEM_KEYCHAIN],
                       capture_output=True, text=True, stdin=subprocess.DEVNULL, user="nobody",
                       env={"PATH": "/usr/bin:/bin", "HOME": "/var/empty"})
    return r.returncode != 0 or not r.stdout.strip()


def mk_create(pw: str) -> None:
    """Add the master item. Never replaces or removes an existing item."""
    acct = "root" if os.geteuid() == 0 else getpass.getuser()
    base = ["add-generic-password", "-s", ITEM, "-l", ITEM, "-a", acct,
            "-D", "PKI-Structure", "-T", SECURITY]
    if os.environ.get("PKI_KEYCHAIN_FILE"):
        # test keychain only: -w must be last to prompt, so no keychain argument
        rc = sec(*base, "-w", pw, mk_target()).returncode
    else:
        if not default_keychain_ok():
            fail(f"{mk_target()} is not the default keychain; the item would be stored elsewhere")
        rc, sent = pty_security([*base, "-w"], pw)  # default keychain: System (root) / login
        if sent < 1:
            rc = rc or 1
    if rc:
        fail(f"cannot create '{ITEM}' in {mk_target()} (exit {rc}); "
             + ("it already exists and was not replaced" if mk_state() else "nothing was stored"))
    if not mk_state():
        fail(f"'{ITEM}' not found in {mk_target()} after creation")
    if not root_only_ok():
        mk_delete()  # created above; no database depends on it yet
        fail("System keychain item is readable by non-root users; removed it")


def has_item(keychain: str) -> bool:
    return sec("find-generic-password", "-s", ITEM, keychain).returncode == 0


def other_keychains() -> list[str]:
    """Existing keychains, other than the queried one, that could hold the item."""
    cand = [SYSTEM_KEYCHAIN, str(Path.home() / "Library" / "Keychains" / "login.keychain-db")]
    for dom in ("user", "system", "common"):
        cand += [ln.strip().strip('"') for ln in sec("list-keychains", "-d", dom).stdout.splitlines()
                 if ln.strip()]
    me, out = os.path.realpath(mk_target()), []
    for k in cand:
        if os.path.exists(k) and os.path.realpath(k) != me and k not in out:
            out.append(k)
    return out


def verify_open(db: Path, kf: Path | None) -> None:
    """The master item must exist, be readable, and open the database."""
    if not mk_state():
        where = [k for k in other_keychains() if has_item(k)]
        fail(f"master item '{ITEM}' is not in {mk_target()}; "
             + (f"it is in {', '.join(where)} (run as the matching user, or import-master)" if where
                else "it is in no keychain searched, so the database cannot be opened")
             + ". Restore: pki_keychain.py import-master (password on stdin). Nothing was changed")
    mp = mk_get()
    try:
        kp(["ls", *(["-k", str(kf)] if kf else []), str(db)], [mp])
    except KeychainError as e:
        fail(f"master item '{ITEM}' is readable but does not open {db.name} "
             f"(wrong item or key file): {e}")


def ensure_master() -> bool:
    """Create the master item if definitively absent; True if created."""
    if mk_state():
        return False
    mk_create(new_secret())
    print(f"Created master item '{ITEM}' in {mk_target()}. Escrow it now: "
          "pki_keychain.py export-master", file=sys.stderr)
    return True


# ---------------------------------------------------------------- key file, database
def kdir() -> Path:
    return Path(os.environ.get("PKI_KEYCHAIN_DIR") or PKI_ROOT / "keychain")


def dbfile(d: Path | None = None) -> Path:
    return (d or kdir()) / DB_NAME


def keyfile(d: Path | None = None) -> Path:
    """$PKI_KEYCHAIN_KEYFILE for this tree's keychain dir, else <dir>/../keyfile/."""
    d = d or kdir()
    env = os.environ.get("PKI_KEYCHAIN_KEYFILE")
    if env and d.resolve() == kdir().resolve():
        return Path(env).expanduser()
    return d.parent / "keyfile" / KEYFILE_NAME


def write_keyfile(path: Path) -> None:
    """KeePassXC key file v2 (XML): 256-bit key as hex, Hash = first 4 bytes of its SHA-256."""
    key = secrets.token_bytes(32)
    h = hashlib.sha256(key).hexdigest()[:8].upper()
    x = key.hex().upper()
    g = [x[i:i + 8] for i in range(0, 64, 8)]
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>2.0</Version>\n'
           f'\t</Meta>\n\t<Key>\n\t\t<Data Hash="{h}">\n\t\t\t{" ".join(g[:4])}\n\t\t\t{" ".join(g[4:])}\n'
           '\t\t</Data>\n\t</Key>\n</KeyFile>\n')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(xml)


@contextlib.contextmanager
def lock(d: Path | None = None):
    d = d or kdir()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(d / ".lock", "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def kp(args: list[str], lines: list[str], check: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run([kpcli(), *args], input="".join(ln + "\n" for ln in lines),
                       capture_output=True, text=True)
    if check and r.returncode:
        fail(f"keepassxc-cli {args[0]} failed: {(r.stderr or r.stdout).strip()}")
    return r


def _undo_new(db: Path, kf: Path, new_kf: bool) -> None:
    db.unlink(missing_ok=True)
    if new_kf:
        kf.unlink(missing_ok=True)


def migrate_legacy(d: Path) -> None:
    """Add a key file to a pre-keyfile pki.kdbx. The original is kept as pki.kdbx.pre-keyfile."""
    old, db, kf = d / LEGACY_DB_NAME, dbfile(d), keyfile(d)
    if not mk_state():
        fail(f"{old} exists but master item '{ITEM}' is not in {mk_target()}; nothing was changed")
    mp = mk_get()
    new_kf = not kf.exists()
    if new_kf:
        write_keyfile(kf)
    shutil.copy2(old, db)
    os.chmod(db, 0o600)
    try:
        kp(["db-edit", "--set-key-file", str(kf), str(db)], [mp])
        kp(["ls", "-k", str(kf), str(db)], [mp])
    except KeychainError:
        _undo_new(db, kf, new_kf)
        raise
    old.rename(d / (LEGACY_DB_NAME + ".pre-keyfile"))
    print(f"Migrated {old.name} to {db.name} with key file {kf}; original kept as "
          f"{LEGACY_DB_NAME}.pre-keyfile. Back up the key file offline.", file=sys.stderr)


def ensure_db(d: Path | None = None) -> None:
    d = d or kdir()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    db, kf = dbfile(d), keyfile(d)
    if db.exists():
        # an existing database never gets a new master item or key file
        if not kf.is_file():
            fail(f"{db} exists but key file {kf} is missing; nothing was changed. "
                 "Restore it or set PKI_KEYCHAIN_KEYFILE")
        verify_open(db, kf)
        return
    if (d / LEGACY_DB_NAME).exists():
        migrate_legacy(d)
        return
    ensure_master()
    new_kf = not kf.exists()
    if new_kf:
        write_keyfile(kf)
    mp = mk_get()
    try:
        kp(["db-create", "-p", "-t", KDF_MS, "--set-key-file", str(kf), str(db)], [mp, mp])
        os.chmod(db, 0o600)
        kp(["ls", "-k", str(kf), str(db)], [mp])
    except KeychainError:
        _undo_new(db, kf, new_kf)
        raise


class Db:
    def __init__(self, d: Path | None = None):
        d = d or kdir()
        self.file, self.keyfile = str(dbfile(d)), str(keyfile(d))
        if not Path(self.file).is_file():
            fail(f"no database {self.file}; run: pki_keychain.py init")
        if not Path(self.keyfile).is_file():
            fail(f"key file {self.keyfile} missing (PKI_KEYCHAIN_KEYFILE)")
        self.mp = mk_get()

    def kp(self, args: list[str], extra: list[str] | None = None, check: bool = True):
        return kp([args[0], "-k", self.keyfile, *args[1:]], [self.mp, *(extra or [])], check)

    def titles(self) -> list[str]:
        out = self.kp(["ls", "-R", "-f", self.file]).stdout
        return [t for t in out.splitlines() if TITLE_RE.match(t)]

    def find(self, kid: str, p12: bool = False) -> str | None:
        for t in self.titles():
            if t.startswith(kid[:16] + " :: ") and t.endswith(" :: p12") == p12:
                return t
        return None

    def show(self, title: str) -> str:
        return self.kp(["show", "-s", "-a", "Password", self.file, title]).stdout.rstrip("\n")

    def add(self, title: str, user: str, url: str, secret: str) -> None:
        args = ["add", self.file, title, "-u", user]
        if url:
            args += ["--url", url]
        self.kp([*args, "-p"], [secret])

    def rm(self, title: str) -> None:
        self.kp(["rm", self.file, title])
        self.kp(["rm", self.file, f"Recycle Bin/{title}"], check=False)  # drop it for good


def get_secret(cert=None, field: str = "key", kid: str | None = None,
               keychain_dir: Path | None = None) -> str:
    kid = kid or cert_id(cert)
    t = (db := Db(keychain_dir)).find(kid, field == "p12")
    if t is None:
        fail(f"no keychain entry for key {kid[:16]} ({field})")
    return db.show(t)


# ---------------------------------------------------------------- commands
def target(a) -> str:
    return a.id or cert_id(a.cert)


def cmd_init(a) -> None:
    with lock():
        ensure_db()


def cmd_export_master(a) -> None:
    print(mk_get())


def cmd_import_master(a) -> None:
    pw = sys.stdin.readline().rstrip("\n")
    if not pw:
        fail("no password on stdin")
    with lock():
        if mk_state():
            fail(f"'{ITEM}' already exists in {mk_target()}; not replaced")
        d = kdir()
        if dbfile(d).is_file():
            if not keyfile(d).is_file():
                fail(f"key file {keyfile(d)} missing")
            kp(["ls", "-k", str(keyfile(d)), str(dbfile(d))], [pw])  # wrong password raises
        mk_create(pw)


def cmd_genkey(a) -> None:
    alg = a.alg.upper()
    if alg == "EC":
        opts = ["-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{a.curve}"]
    elif alg == "RSA":
        opts = ["-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{a.bits}"]
    else:
        return fail(f"unknown algorithm '{a.alg}' (expected EC or RSA)")
    out = Path(a.out)
    if out.exists():
        fail(f"{out} exists")
    pw = new_secret()
    with lock():
        ensure_db()
        r, w = os.pipe()
        os.write(w, (pw + "\n").encode())
        os.close(w)
        try:
            p = subprocess.run([openssl(), "genpkey", "-out", str(out), *opts, "-aes256",
                                "-pass", f"fd:{r}"], pass_fds=(r,), capture_output=True, text=True)
        finally:
            os.close(r)
        if p.returncode:
            out.unlink(missing_ok=True)
            fail("genpkey: " + p.stderr.strip())
        key = serialization.load_pem_private_key(out.read_bytes(), pw.encode())
        kid = spki_id(key.public_key())
        try:
            Db().add(f"{kid[:16]} :: {a.label.replace('/', '_')}", "pending", "", pw)
        except KeychainError:
            out.unlink(missing_ok=True)
            raise
    print(kid)


def cmd_id(a) -> None:
    print(cert_id(a.cert))


def cmd_record(a) -> None:
    cert = load_cert(a.cert)
    kid = spki_id(cert.public_key())
    base = f"{kid[:16]} :: {cert_cn(cert)}"
    with lock():
        db = Db()
        kt = db.find(kid) or fail(f"no keychain entry for key {kid[:16]}")
        args = ["-u", f"serial {cert.serial_number:X}",
                "--url", "sha256:" + cert.fingerprint(hashes.SHA256()).hex()]
        if kt != base:
            args += ["-t", base]
        db.kp(["edit", db.file, kt, *args])
        pt = db.find(kid, True)
        if pt and pt != base + " :: p12":
            db.kp(["edit", db.file, pt, "-t", base + " :: p12"])
        if not pt:
            if a.p12_like:
                lt = db.find(cert_id(a.p12_like), True) or fail("no .p12 entry for --p12-like")
                pw = db.show(lt)
            else:
                pw = new_secret()
            db.add(base + " :: p12", "p12", "", pw)


def cmd_get(a) -> None:
    print(get_secret(kid=target(a), field=a.field))


def cmd_forget(a) -> None:
    if not dbfile().exists():
        return
    kid = target(a)
    with lock():
        db = Db()
        for p12 in (False, True):
            t = db.find(kid, p12)
            if t:
                db.rm(t)


def cmd_list(a) -> None:
    for t in Db().titles():
        print(t)


def cmd_prune(a) -> None:
    ids = set()
    for pat in ("*/certs/*.cert.pem", "*/*/certs/*.cert.pem"):
        for p in PKI_ROOT.glob(pat):
            try:
                ids.add(cert_id(p)[:16])
            except (ValueError, OSError):
                pass
    with lock():
        db = Db()
        for t in db.titles():
            if t[:16] not in ids:
                print(("would remove " if a.dry_run else "removing ") + t)
                if not a.dry_run:
                    db.rm(t)


def cmd_verify(a) -> None:
    d = kdir()
    db, kf, old = dbfile(d), keyfile(d), d / LEGACY_DB_NAME
    if db.exists():
        if not kf.is_file():
            fail(f"key file {kf} is missing")
        verify_open(db, kf)
    elif old.exists():
        verify_open(old, None)
    else:
        print("no database; nothing to verify")
        return
    print("ok: master item readable, database opens")


def cmd_acl_check(a) -> None:
    if not mk_state():
        fail(f"no '{ITEM}' in {mk_target()}")
    if not root_only_ok():
        fail("the item is readable by user 'nobody'")
    print("ok")


def cmd_migrate(a) -> None:
    base = Path(a.dir)
    priv = base / "private"
    pf = priv / "passphrase.txt"
    if not pf.is_file():
        fail(f"{pf} not found")
    lines = pf.read_text().splitlines()
    kpw, shared = lines[0], (lines[1] if len(lines) > 1 else "")
    items: dict[str, dict] = {}
    problems = 0
    for cert in sorted((base / "certs").glob("*.cert.pem")):
        stem = cert.name[:-len(".cert.pem")]
        keyf = priv / f"{stem}.key.pem"
        if not keyf.is_file():
            continue
        c = load_cert(cert)
        kid = spki_id(c.public_key())
        try:
            pk = serialization.load_pem_private_key(keyf.read_bytes(), kpw.encode())
        except (ValueError, TypeError):
            print(f"skip {keyf}: does not open with line 1 of {pf}", file=sys.stderr)
            problems += 1
            continue
        if spki_id(pk.public_key()) != kid:
            print(f"skip {keyf}: does not match {cert.name}", file=sys.stderr)
            problems += 1
            continue
        it = items.setdefault(kid, {"cert": c, "keys": [], "p12": None})
        it["keys"].append((keyf, pk))
        p12 = priv / f"{stem}.p12"
        if p12.is_file() and it["p12"] is None:
            pwf = priv / f"{stem}.p12.pass"
            cand = pwf.read_text().splitlines()[0] if pwf.is_file() else shared
            if p12_opens(p12, cand):
                it["p12"] = cand
            else:
                print(f"warning: no known password opens {p12}", file=sys.stderr)
                problems += 1
    with lock():
        ensure_db()
        db = Db()
        for kid, it in items.items():
            if db.find(kid):
                print(f"{kid[:16]}: already in the keychain")
                continue
            c = it["cert"]
            pw = new_secret() if a.rotate else kpw
            title = f"{kid[:16]} :: {cert_cn(c)}"
            db.add(title, f"serial {c.serial_number:X}",
                   "sha256:" + c.fingerprint(hashes.SHA256()).hex(), pw)
            if it["p12"]:
                db.add(title + " :: p12", "p12", "", it["p12"])
            if a.rotate:  # entry first, so a crash never strands a re-encrypted key
                enc = serialization.BestAvailableEncryption(pw.encode())
                for keyf, pk in it["keys"]:
                    tmp = keyf.with_name(keyf.name + ".tmp")
                    tmp.write_bytes(pk.private_bytes(serialization.Encoding.PEM,
                                                     serialization.PrivateFormat.PKCS8, enc))
                    os.chmod(tmp, 0o600)
                    os.replace(tmp, keyf)
            print(f"{kid[:16]}: imported {title}" + (" (rotated)" if a.rotate else ""))
    if a.remove_legacy:
        if problems:
            fail("legacy files kept: some keys or .p12 files were not imported")
        pf.unlink()
        for f in priv.glob("*.p12.pass"):
            f.unlink()


def main() -> None:
    ap = argparse.ArgumentParser(description="PKI key passphrases in a KeePassXC database.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def sel(p):
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--id")
        g.add_argument("--cert")

    sub.add_parser("init").set_defaults(func=cmd_init)
    sub.add_parser("export-master").set_defaults(func=cmd_export_master)
    sub.add_parser("import-master").set_defaults(func=cmd_import_master)
    p = sub.add_parser("genkey")
    p.add_argument("--alg", required=True)
    p.add_argument("--curve", default="P-256")
    p.add_argument("--bits", default="3072")
    p.add_argument("--out", required=True)
    p.add_argument("--label", default="pending")
    p.set_defaults(func=cmd_genkey)
    p = sub.add_parser("id")
    p.add_argument("--cert", required=True)
    p.set_defaults(func=cmd_id)
    p = sub.add_parser("record")
    p.add_argument("--cert", required=True)
    p.add_argument("--p12-like")
    p.set_defaults(func=cmd_record)
    p = sub.add_parser("get")
    sel(p)
    p.add_argument("--field", choices=("key", "p12"), default="key")
    p.set_defaults(func=cmd_get)
    p = sub.add_parser("forget")
    sel(p)
    p.set_defaults(func=cmd_forget)
    p = sub.add_parser("migrate")
    p.add_argument("dir")
    p.add_argument("--rotate", action="store_true")
    p.add_argument("--remove-legacy", action="store_true")
    p.set_defaults(func=cmd_migrate)
    p = sub.add_parser("prune")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_prune)
    sub.add_parser("list").set_defaults(func=cmd_list)
    sub.add_parser("acl-check").set_defaults(func=cmd_acl_check)
    sub.add_parser("verify").set_defaults(func=cmd_verify)

    a = ap.parse_args()
    try:
        a.func(a)
    except KeychainError as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()

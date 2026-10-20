#!/usr/bin/env python3
"""pki_keychain.py -- key passphrases in a KeePassXC database.

Layout    keepassxc/ (0700) holds keychain/, keyfile/ and master/.
Database  $PKI_KEYCHAIN_DIR (default keepassxc/keychain)/pki-structure.kdbx;
          dir 0700, file 0600. KDBX4, Argon2id, 64 MiB, 4 lanes,
          $PKI_KEYCHAIN_KDF_ROUNDS (16) rounds; written here because
          keepassxc-cli db-create makes KDBX3.
Key file  $PKI_KEYCHAIN_KEYFILE (default keepassxc/keyfile/pki-structure.keyx),
          KeePassXC XML v2, 0600. Required to open the database; keep a copy
          offline. Generated only when no database exists yet.
Master    192 random bits; created only when absent and never next to an
          existing database; never replaced or deleted.
          root: 0600 file $PKI_KEYCHAIN_MASTER (default
          keepassxc/master/pki-structure.pass); protects against other
          users only.
          other users: generic password item in the login keychain
          ($PKI_KEYCHAIN_FILE: another keychain file, for tests), service
          com.github.essandess.pki-structure.keepassxc-passphrase
          ($PKI_KEYCHAIN_ITEM), name "PKI-Structure KeePassXC Passphrase".
Installer passwords: entry "<installer file name>" (installer-set /
          installer-get).
Profiles  entry "Profile/mobileconfig :: NAME" (profile-get, -list, -rm).
Groups    root "PKI-Structure": "Password" = bare secrets (key, .p12,
          installer passwords); "Profile" = installable artifacts with
          their secrets (profiles). Encrypted files stay on disk.
Entries   one per private key, found by SHA-256 of its public key, so every
          certificate of that key (same-key renewal) finds it.
          "<id16> :: <CN>": Password = key passphrase, UserName = serial,
          URL = certificate SHA-256. "<id16> :: <CN> :: p12": Password =
          .p12 export password.

  init                      master, key file and database
  genkey --alg EC|RSA [--curve C] [--bits N] --out KEY [--label CN]
                            encrypted key, new passphrase; prints the key id
  id --cert CERT            key id of a certificate
  record --cert CERT [--p12-like CERT]
                            attach certificate data; create the .p12 entry
  get (--id ID | --cert CERT) [--field key|p12]
                            print a secret (stdout only)
  forget (--id ID | --cert CERT)
                            delete the key's entries
  verify                    master readable and opens the database
  selftest                  scratch keychain item: create, read, delete
  kdf-check                 database is KDBX4, Argon2 >= 64 MiB, 4 lanes
  installer-set --name NAME store an installer password (stdin) as entry NAME
  installer-get --name NAME print it
  profile-get --name NAME [--unsigned] --out FILE
                            extract a stored profile (--unsigned: the plist)
  profile-list | profile-rm --name NAME
  export-master             print the master password (escrow)
  import-master             restore the master from stdin; refuses if present
  prune [-n]   reap   list
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import csv
import fcntl
import getpass
import gzip
import hashlib
import hmac
import io
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import textwrap
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

PKI_ROOT = Path(__file__).resolve().parent.parent
# "Where" in Keychain Access is the service attribute, "Name" the label
ITEM_LABEL = "PKI-Structure KeePassXC Passphrase"
ITEM = os.environ.get("PKI_KEYCHAIN_ITEM") or "com.github.essandess.pki-structure.keepassxc-passphrase"
DB_NAME = "pki-structure.kdbx"
KEYFILE_NAME = "pki-structure.keyx"
SECURITY = "/usr/bin/security"
ERR_NOT_FOUND = 44  # security(1) exit status for errSecItemNotFound
KDF_ROUNDS_MIN = 16  # master is 192 random bits: a slow KDF adds nothing
KDF_ROUNDS = int(os.environ.get("PKI_KEYCHAIN_KDF_ROUNDS") or KDF_ROUNDS_MIN)
KDF_MEM_MIB, KDF_LANES = 64, 4
ROOT_GROUP = "PKI-Structure"
PASSWORD_GROUP = "Password"   # key, .p12 and installer passwords
PROFILE_GROUP = "Profile"
PASSWORD_PATH = PASSWORD_GROUP + "/"

# https://keepass.info/help/kb/kdbx.html
ARGON2D = bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c")
ARGON2ID = bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6")
AES256_CIPHER = bytes.fromhex("31c1f2e6bf714350be5805216afc5aff")

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


# ---------------------------------------------------------------- master
# Root: a 0600 file. Others (and tests, via PKI_KEYCHAIN_FILE): a generic
# password item in a keychain.
MASTER_NAME = "pki-structure.pass"


def master_file() -> Path:
    """$PKI_KEYCHAIN_MASTER, else keepassxc/master/ beside keychain/."""
    env = os.environ.get("PKI_KEYCHAIN_MASTER")
    if env:
        return Path(env).expanduser()
    return kdir().parent / "master" / MASTER_NAME


def use_file() -> bool:
    """The master is a file: as root, or when PKI_KEYCHAIN_MASTER is set."""
    if os.environ.get("PKI_KEYCHAIN_MASTER"):
        return True
    return os.geteuid() == 0 and not os.environ.get("PKI_KEYCHAIN_FILE")


def mf_state() -> bool:
    """True if the master file exists; a symlink or non-file raises."""
    p = master_file()
    if p.is_symlink() or (p.exists() and not p.is_file()):
        fail(f"{p} is not a regular file")
    return p.exists()


def mf_get(p: Path | None = None) -> str:
    p = p or master_file()
    try:
        st = p.stat()
        if st.st_uid != os.geteuid() or st.st_mode & 0o077:
            fail(f"{p} must be owned by you, mode 0600")
        return p.read_text().rstrip("\n")
    except OSError as e:
        return fail(f"cannot read {p}: {e}")


def mf_create(pw: str) -> None:
    """Write the master file (0600); never replaces an existing one."""
    p = master_file()
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as e:
        return fail(f"cannot create {p}: {e}")
    with os.fdopen(fd, "w") as f:
        f.write(pw + "\n")


def sec(*args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run([SECURITY, *args], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, **kw)


def mk_target() -> str:
    f = os.environ.get("PKI_KEYCHAIN_FILE")
    if f:
        return f
    home = Path.home() / "Library" / "Keychains"
    for n in ("login.keychain-db", "login.keychain"):
        if (home / n).exists():
            return str(home / n)
    return fail("login keychain not found")


def kc_state() -> bool:
    """True if the master item exists, False only if the keychain says it is
    absent; any other failure (locked, unavailable) raises. Never infer absence."""
    r = sec("find-generic-password", "-s", ITEM, mk_target())
    if r.returncode == 0:
        return True
    if r.returncode == ERR_NOT_FOUND or "item could not be found" in r.stderr:
        return False
    return fail(f"cannot query '{ITEM}' in {mk_target()} (exit {r.returncode}): "
                f"{r.stderr.strip()}; nothing was changed")


def kc_get() -> str:
    r = sec("find-generic-password", "-s", ITEM, "-w", mk_target())
    if r.returncode:
        fail(f"cannot read '{ITEM}' from {mk_target()}: {r.stderr.strip()}")
    return r.stdout.rstrip("\n")


def kc_delete() -> None:
    """Only for an item created in this process with nothing depending on it."""
    sec("delete-generic-password", "-s", ITEM, mk_target())


def _sq(s: str) -> str:
    """Quote a word for `security -i` (double quotes, backslash escapes)."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def kc_create(pw: str) -> None:
    """Add the master item. Never replaces or removes an existing item."""
    if any(ord(c) < 32 or ord(c) == 127 for c in pw):
        fail("password contains control characters")
    words = ["add-generic-password", "-s", ITEM, "-l", ITEM_LABEL,
             "-a", getpass.getuser(), "-D", "PKI-Structure",
             "-T", SECURITY, "-w", pw, mk_target()]
    # explicit keychain; the secret is on stdin, not in argv
    r = subprocess.run([SECURITY, "-i"], input=" ".join(map(_sq, words)) + "\n",
                       capture_output=True, text=True)
    if r.returncode or "security:" in r.stderr:
        fail(f"cannot create '{ITEM}' in {mk_target()}: {r.stderr.strip()}; "
             + ("it already exists and was not replaced" if kc_state()
                else "nothing was stored"))
    if not kc_state():
        fail(f"'{ITEM}' not found in {mk_target()} after creation")


def mk_state() -> bool:
    return mf_state() if use_file() else kc_state()


def mk_get() -> str:
    return mf_get() if use_file() else kc_get()


def mk_create(pw: str) -> None:
    if use_file():
        mf_create(pw)
    else:
        kc_create(pw)


def mk_where() -> str:
    return str(master_file()) if use_file() else mk_target()


def verify_open(db: Path, kf: Path | None) -> None:
    """The master must exist, be readable, and open the database."""
    if not mk_state():
        fail(f"master item is not in {mk_where()}; restore it with "
             "import-master (password on stdin). Nothing was changed")
    mp = mk_get()
    try:
        kp(["ls", *(["-k", str(kf)] if kf else []), str(db)], [mp])
    except KeychainError as e:
        fail(f"master item in {mk_where()} is readable but does not open "
             f"{db.name} (wrong item or key file): {e}")


def ensure_master() -> bool:
    """Create the master if definitively absent; True if created."""
    if mk_state():
        return False
    mk_create(new_secret())
    where = mk_where()
    if use_file():
        print(f"WARNING: master passphrase created in {where} (0600); "
              "it is readable by root.", file=sys.stderr)
    else:
        print(f"Created master item '{ITEM}' in {where}.", file=sys.stderr)
    print("Escrow it now: pki_keychain.py export-master", file=sys.stderr)
    return True


# ---------------------------------------------------------------- key file, database
def kdir() -> Path:
    env = os.environ.get("PKI_KEYCHAIN_DIR")
    return Path(env) if env else PKI_ROOT / "keepassxc" / "keychain"


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


def _vdict(items: list[tuple[int, str, bytes]]) -> bytes:
    """KDBX VariantDictionary."""
    out = struct.pack("<H", 0x0100)
    for typ, key, val in items:
        k = key.encode()
        out += struct.pack("<BI", typ, len(k)) + k + struct.pack("<I", len(val)) + val
    return out + b"\x00"


def keyfile_key(kf: Path) -> bytes:
    root = ET.fromstring(Path(kf).read_bytes())
    if not (root.findtext("Meta/Version") or "").startswith("2"):
        fail(f"{kf} is not a KeePassXC XML v2 key file")
    return bytes.fromhex("".join((root.findtext("Key/Data") or "").split()))


def make_kdbx4(path: Path, password: str, kf: Path) -> None:
    """Write an empty KDBX4 database (AES-256, Argon2id, KDF_MEM_MIB x KDF_LANES,
    KDF_ROUNDS iterations) keyed by password + key file."""
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    except ImportError:
        fail("cryptography >= 44 is required (Argon2id)")

    composite = hashlib.sha256(hashlib.sha256(password.encode()).digest() + keyfile_key(kf)).digest()
    seed, iv, salt = os.urandom(32), os.urandom(16), os.urandom(32)

    rounds = KDF_ROUNDS
    transformed = Argon2id(salt=salt, length=32, iterations=rounds,
                           lanes=KDF_LANES,
                           memory_cost=KDF_MEM_MIB * 1024).derive(composite)

    def field(i: int, data: bytes) -> bytes:
        return struct.pack("<BI", i, len(data)) + data

    kdfp = _vdict([(0x42, "$UUID", ARGON2ID), (0x42, "S", salt),
                   (0x04, "P", struct.pack("<I", KDF_LANES)),
                   (0x05, "M", struct.pack("<Q", KDF_MEM_MIB << 20)),
                   (0x05, "I", struct.pack("<Q", rounds)), (0x04, "V", struct.pack("<I", 0x13))])
    header = (struct.pack("<III", 0x9AA2D903, 0xB54BFB67, 0x00040000)
              + field(2, AES256_CIPHER) + field(3, struct.pack("<I", 1)) + field(4, seed)
              + field(7, iv) + field(11, kdfp) + field(0, b"\r\n\r\n"))
    cipher_key = hashlib.sha256(seed + transformed).digest()
    hmac_base = hashlib.sha512(seed + transformed + b"\x01").digest()
    hdr_mac = hmac.new(hashlib.sha512(b"\xff" * 8 + hmac_base).digest(), header, hashlib.sha256).digest()

    now = base64.b64encode(struct.pack("<q", int(
        (datetime.now(timezone.utc) - datetime(1, 1, 1, tzinfo=timezone.utc)).total_seconds()))).decode()
    def group(name: str, children: str = "") -> str:
        guid = base64.b64encode(os.urandom(16)).decode()
        times = "".join(f"<{k}>{now}</{k}>" for k in (
            "CreationTime", "LastModificationTime", "LastAccessTime",
            "ExpiryTime"))
        return (f"<Group><UUID>{guid}</UUID><Name>{name}</Name>"
                f"<IconID>48</IconID><Times>{times}<Expires>False</Expires>"
                f"<UsageCount>0</UsageCount>"
                f"<LocationChanged>{now}</LocationChanged></Times>"
                f"<IsExpanded>True</IsExpanded>{children}</Group>")

    tree = group(ROOT_GROUP, group(PASSWORD_GROUP) + group(PROFILE_GROUP))
    xml = ('<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n<KeePassFile><Meta>'
           '<Generator>pki_keychain</Generator><DatabaseName>PKI-Structure</DatabaseName>'
           '<MemoryProtection><ProtectTitle>False</ProtectTitle><ProtectUserName>False</ProtectUserName>'
           '<ProtectPassword>True</ProtectPassword><ProtectURL>False</ProtectURL>'
           '<ProtectNotes>False</ProtectNotes></MemoryProtection><RecycleBinEnabled>True</RecycleBinEnabled>'
           f'</Meta><Root>{tree}</Root></KeePassFile>').encode()
    inner = (struct.pack("<BII", 1, 4, 3) + field(2, os.urandom(64)) + struct.pack("<BI", 0, 0))
    padder = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).encryptor()
    ct = enc.update(padder.update(gzip.compress(inner + xml)) + padder.finalize()) + enc.finalize()

    def block(i: int, data: bytes) -> bytes:
        idx, size = struct.pack("<Q", i), struct.pack("<I", len(data))
        key = hashlib.sha512(idx + hmac_base).digest()
        return hmac.new(key, idx + size + data, hashlib.sha256).digest() + size + data

    tmp = Path(str(path) + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(header + hashlib.sha256(header).digest() + hdr_mac + block(0, ct) + block(1, b""))
    os.replace(tmp, path)


def kdbx_params(path) -> dict:
    """Format and KDF settings from the unencrypted KDBX header."""
    d = Path(path).read_bytes()[:65536]
    s1, s2, ver = struct.unpack_from("<III", d, 0)
    if (s1, s2) != (0x9AA2D903, 0xB54BFB67):
        fail(f"{path} is not a KDBX file")
    out: dict = {"kdbx": ver >> 16}
    if out["kdbx"] < 4:
        return out
    off, vd = 12, b""
    while off + 5 <= len(d):
        fid, size = struct.unpack_from("<BI", d, off)
        data, off = d[off + 5:off + 5 + size], off + 5 + size
        if fid == 11:
            vd = data
        if fid == 0:
            break
    pos, vals = 2, {}
    while pos < len(vd) and vd[pos] != 0:
        kl = struct.unpack_from("<I", vd, pos + 1)[0]
        key = vd[pos + 5:pos + 5 + kl].decode()
        pos += 5 + kl
        vl = struct.unpack_from("<I", vd, pos)[0]
        vals[key] = vd[pos + 4:pos + 4 + vl]
        pos += 4 + vl
    uuid = vals.get("$UUID", b"")
    out["kdf"] = {ARGON2D: "Argon2d", ARGON2ID: "Argon2id"}.get(uuid, uuid.hex())
    out["memory_mib"] = int.from_bytes(vals.get("M", b""), "little") >> 20
    out["lanes"] = int.from_bytes(vals.get("P", b""), "little")
    out["iterations"] = int.from_bytes(vals.get("I", vals.get("R", b"")), "little")
    return out


def kdf_ok(p: dict) -> bool:
    return (p.get("kdbx", 0) >= 4 and p.get("kdf") in ("Argon2d", "Argon2id")
            and p.get("memory_mib", 0) >= KDF_MEM_MIB and p.get("lanes", 0) >= KDF_LANES)


def fmt_params(p: dict) -> str:
    s = f"KDBX{p['kdbx']}"
    if "kdf" in p:
        s += f", {p['kdf']}, {p['memory_mib']} MiB, {p['lanes']} lanes, {p['iterations']} iterations"
    return s


def create_db(db: Path, kf: Path, mp: str) -> None:
    """Write the KDBX4 database and check keepassxc-cli opens it with the intended KDF."""
    make_kdbx4(db, mp, kf)
    kp(["ls", "-k", str(kf), str(db)], [mp])
    if not kdf_ok(kdbx_params(db)):
        fail("unexpected KDF parameters")


def _undo_new(db: Path, kf: Path, new_kf: bool) -> None:
    db.unlink(missing_ok=True)
    if new_kf:
        kf.unlink(missing_ok=True)


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
    ensure_master()
    new_kf = not kf.exists()
    if new_kf:
        write_keyfile(kf)
    mp = mk_get()
    try:
        create_db(db, kf, mp)
    except Exception:
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
        # a tree's own master file (extra tree) unless env forces one
        mf = d.parent / "master" / MASTER_NAME
        own = mf.is_file() and not os.environ.get("PKI_KEYCHAIN_MASTER")
        self.mp = mf_get(mf) if own else mk_get()

    def kp(self, args: list[str], extra: list[str] | None = None, check: bool = True):
        return kp([args[0], "-k", self.keyfile, *args[1:]], [self.mp, *(extra or [])], check)

    def has(self, title: str) -> bool:
        return title in self.kp(["ls", "-R", "-f", self.file]).stdout.splitlines()

    def titles(self) -> list[str]:
        """Paths of the key and .p12 entries."""
        out = self.kp(["ls", "-R", "-f", self.file]).stdout
        return [t for t in out.splitlines() if t.startswith(PASSWORD_PATH)
                and TITLE_RE.match(t[len(PASSWORD_PATH):])]

    def entries(self) -> list[dict[str, str]] | None:
        """All entries in one open (CSV export); None to use ls + show.

        Set PKI_KEYCHAIN_EXPORT=0 to disable; all secrets pass over the pipe.
        """
        if os.environ.get("PKI_KEYCHAIN_EXPORT") == "0":
            return None
        r = self.kp(["export", "-f", "csv", self.file], check=False)
        if r.returncode:
            return None
        rows = list(csv.DictReader(io.StringIO(r.stdout)))
        if rows and not {"Title", "Password"} <= set(rows[0]):
            return None
        return rows

    def find(self, kid: str, p12: bool = False,
             titles: list[str] | None = None) -> str | None:
        prefix = f"{PASSWORD_PATH}{kid[:16]} :: "
        for t in self.titles() if titles is None else titles:
            if t.startswith(prefix) and t.endswith(" :: p12") == p12:
                return t
        return None

    def show(self, title: str) -> str:
        return self.kp(["show", "-s", "-a", "Password", self.file, title]).stdout.rstrip("\n")

    def add(self, title: str, user: str, url: str, secret: str) -> None:
        """Add an entry to the Password group."""
        args = ["add", self.file, PASSWORD_PATH + title, "-u", user]
        if url:
            args += ["--url", url]
        self.kp([*args, "-p"], [secret])

    def rm(self, title: str) -> None:
        self.kp(["rm", self.file, title])
        self.kp(["rm", self.file, f"Recycle Bin/{title.rsplit('/', 1)[-1]}"], check=False)  # drop it for good


def get_secret(cert=None, field: str = "key", kid: str | None = None,
               keychain_dir: Path | None = None) -> str:
    kid = kid or cert_id(cert)
    db = Db(keychain_dir)
    t = db.find(kid, field == "p12")
    if t is None:
        fail(f"no keychain entry for key {kid[:16]} ({field})")
    return db.show(t)


# ---------------------------------------------------------------- commands
def target(a) -> str:
    return a.id or cert_id(a.cert)


def reap_pending() -> None:
    """Remove `pending` entries (key made, certificate never recorded)
    whose key file is gone: a failed issuance. Caller holds the lock."""
    if not dbfile().exists():
        return
    db = Db()
    rows = db.entries()
    if rows is None:
        return
    for r in rows:
        t, url = r["Title"], r.get("URL", "")
        if (TITLE_RE.match(t) and r.get("Username") == "pending"
                and url.startswith("file:") and not Path(url[5:]).exists()):
            print("removing orphaned entry " + t, file=sys.stderr)
            db.rm(PASSWORD_PATH + t)


def cmd_reap(a) -> None:
    with lock():
        reap_pending()


def cmd_init(a) -> None:
    with lock():
        ensure_db()
        reap_pending()


def cmd_export_master(a) -> None:
    print(mk_get())


def cmd_import_master(a) -> None:
    pw = sys.stdin.readline().rstrip("\n")
    if not pw:
        fail("no password on stdin")
    with lock():
        if mk_state():
            fail(f"master item already exists in {mk_where()}; not replaced")
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
            Db().add(f"{kid[:16]} :: {a.label.replace('/', '_')}", "pending",
                     f"file:{out.resolve()}", pw)
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
        titles = db.titles()
        kt = db.find(kid, titles=titles) or fail(f"no keychain entry for key {kid[:16]}")
        args = ["-u", f"serial {cert.serial_number:X}",
                "--url", "sha256:" + cert.fingerprint(hashes.SHA256()).hex()]
        if kt != PASSWORD_PATH + base:
            args += ["-t", base]
        db.kp(["edit", db.file, kt, *args])
        pt = db.find(kid, True, titles)
        if pt and pt != f"{PASSWORD_PATH}{base} :: p12":
            db.kp(["edit", db.file, pt, "-t", base + " :: p12"])
        if not pt:
            if a.p12_like:
                lt = db.find(cert_id(a.p12_like), True, titles) or fail("no .p12 entry for --p12-like")
                pw = db.show(lt)
            else:
                pw = new_secret()
            db.add(base + " :: p12", "p12", "", pw)


def all_secrets(field: str) -> dict[str, str]:
    """{key id16: secret} for every key passphrase (key) or .p12 password (p12)."""
    db = Db()
    rows = db.entries()
    if rows is None:   # export disabled: one `show` per entry
        rows = [{"Title": t[len(PASSWORD_PATH):], "Password": db.show(t)}
                for t in db.titles()]
    return {r["Title"][:16]: r["Password"] for r in rows
            if TITLE_RE.match(r["Title"])
            and r["Title"].endswith(" :: p12") == (field == "p12")}


def cmd_get(a) -> None:
    if a.all:
        for kid, pw in all_secrets(a.field).items():
            print(f"{kid}\t{pw}")
        return
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
        print(t[len(PASSWORD_PATH):])


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
            if t[len(PASSWORD_PATH):][:16] not in ids:
                print(("would remove " if a.dry_run else "removing ") + t)
                if not a.dry_run:
                    db.rm(t)


def cmd_selftest(a) -> None:
    """Create, read back and delete a scratch keychain item."""
    global ITEM
    if use_file():
        fail("the master is a file; nothing to test")
    ITEM += " selftest"
    if kc_state():
        fail(f"'{ITEM}' exists in {mk_target()}; remove it first")
    pw = new_secret()
    kc_create(pw)
    try:
        if kc_get() != pw:
            fail("read-back differs from the stored password")
    finally:
        kc_delete()
    print(f"ok: created, read and deleted '{ITEM}' in {mk_target()}")


NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def cmd_installer_set(a) -> None:
    """Store an installer password (stdin, line 1) as the entry NAME; replaces an entry of that name."""
    if not NAME_RE.match(a.name):
        fail("NAME must be an installer file name (letters, digits, _ . -)")
    pw = sys.stdin.readline().rstrip("\n")
    if not pw:
        fail("no password on stdin")
    with lock():
        db = Db()
        path = PASSWORD_PATH + a.name
        if db.has(path):
            db.rm(path)
        db.add(a.name, "installer", "", pw)


def cmd_installer_get(a) -> None:
    db = Db()
    path = PASSWORD_PATH + a.name
    if not db.has(path):
        fail(f"no installer entry '{a.name}' in {db.file}")
    print(db.show(path))


PROFILE_PATH = f"{PROFILE_GROUP}/mobileconfig :: "
EXPOSED = ("WARNING: {} holds account passwords in PLAIN TEXT (signing does "
           "not encrypt). Deploy it now, then delete it and empty the Trash.")


def need_attachments() -> None:
    r = subprocess.run([kpcli(), "--version"], capture_output=True, text=True)
    m = re.match(r"(\d+)\.(\d+)", r.stdout.strip())
    if not m or (int(m[1]), int(m[2])) < (2, 7):
        fail("keepassxc-cli >= 2.7 is required for profile attachments")


def profile_title(name: str) -> str:
    if not NAME_RE.match(name):
        fail("NAME must be a profile file stem (letters, digits, _ . -)")
    return PROFILE_PATH + name


def profile_titles(db: Db) -> list[str]:
    out = db.kp(["ls", "-R", "-f", db.file]).stdout.splitlines()
    return [t for t in out if t.startswith(PROFILE_PATH)]


def profile_ident(db: Db, title: str) -> str:
    return db.kp(["show", "-a", "UserName", db.file, title]).stdout.strip()


def profile_check(name: str, ident: str) -> bool:
    """True if profile NAME is stored; fail if another has PayloadIdentifier."""
    mine = profile_title(name)
    if not dbfile().exists():
        return False
    db = Db()
    titles = profile_titles(db)
    for t in titles:
        if t != mine and profile_ident(db, t) == ident:
            fail(f"'{t}' has the same PayloadIdentifier '{ident}'")
    return mine in titles


def profile_set(name: str, path, ident: str, labels: list[str],
                secret: bool) -> None:
    """Store a profile as the attachment of its own entry."""
    need_attachments()
    title = profile_title(name)
    path = Path(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    notes = "\n".join([
        "Configuration profile, signed unless built with --no-sign.",
        f"SHA-256 {digest}",
        f"Stored {datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}",
        "Secrets prompted: " + (", ".join(labels) or "none"),
        f"Holds secrets: {'yes' if secret else 'no'}",
        f"Extract: bin/pki_keychain.py profile-get --name {name} --out FILE",
    ])
    with lock():
        ensure_db()
        stored = profile_check(name, ident)
        db = Db()
        if stored:
            db.rm(title)
        db.kp(["add", db.file, title, "-u", ident, "--notes", notes])
        try:
            db.kp(["attachment-import", db.file, title,
                   f"{name}.mobileconfig", str(path)])
        except KeychainError:
            db.rm(title)
            raise


def unsign(data: bytes) -> bytes:
    """The content of a CMS-signed profile (made with -nodetach)."""
    with tempfile.TemporaryDirectory(prefix="pki-profile.") as td:
        src, dst = Path(td, "signed"), Path(td, "content")
        src.write_bytes(data)
        r = subprocess.run(
            [openssl(), "smime", "-verify", "-binary", "-inform", "der",
             "-noverify", "-in", str(src), "-out", str(dst)],
            capture_output=True, text=True)
        if r.returncode:
            fail("cannot read the signed profile: " + r.stderr.strip())
        return dst.read_bytes()


def profile_get(name: str, out, unsigned: bool = False) -> None:
    need_attachments()
    title = profile_title(name)
    out = Path(out)
    if out.exists() or out.is_symlink():
        fail(f"{out} exists; not replaced")
    db = Db()
    if not db.has(title):
        fail(f"no stored profile '{name}' (see profile-list)")
    notes = db.kp(["show", "-a", "Notes", db.file, title]).stdout
    m = re.search(r"^SHA-256 ([0-9a-f]{64})$", notes, re.M)
    if not m:
        fail(f"entry '{title}' has no recorded SHA-256")
    with tempfile.TemporaryDirectory(prefix="pki-profile.") as td:
        tmp = Path(td) / f"{name}.mobileconfig"
        db.kp(["attachment-export", db.file, title,
               f"{name}.mobileconfig", str(tmp)])
        data = tmp.read_bytes()
    if hashlib.sha256(data).hexdigest() != m.group(1):
        fail("stored profile does not match its recorded SHA-256")
    if unsigned and data[:1] == b"\x30":   # DER: signed; an unsigned one is a plist
        data = unsign(data)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    if out.resolve().is_relative_to(PKI_ROOT.resolve()):
        print(textwrap.fill(f"Warning: {out} is inside the PKI tree.", 79),
              file=sys.stderr)
    if "Holds secrets: no" not in notes:   # older entries lack the line
        print(textwrap.fill(EXPOSED.format(out), 79), file=sys.stderr)


def cmd_profile_get(a) -> None:
    profile_get(a.name, a.out, a.unsigned)


def cmd_profile_list(a) -> None:
    for t in profile_titles(Db()):
        print(t[len(PROFILE_PATH):])


def cmd_profile_rm(a) -> None:
    title = profile_title(a.name)
    if not dbfile().exists():
        return
    with lock():
        db = Db()
        if db.has(title):
            db.rm(title)


def cmd_kdf_check(a) -> None:
    p = kdbx_params(dbfile())
    print(fmt_params(p))
    if not kdf_ok(p):
        fail(f"database is not KDBX4 with Argon2 >= {KDF_MEM_MIB} MiB and {KDF_LANES} lanes")


def cmd_verify(a) -> None:
    d = kdir()
    db, kf = dbfile(d), keyfile(d)
    if not db.exists():
        print("no database; nothing to verify")
        return
    if not kf.is_file():
        fail(f"key file {kf} is missing")
    verify_open(db, kf)
    print("ok: master item readable, database opens; " + fmt_params(kdbx_params(db)))


def main() -> None:
    ap = argparse.ArgumentParser(description="PKI key passphrases in a KeePassXC database.")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    def sel(p):
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--id")
        g.add_argument("--cert")
        return g

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
    sel(p).add_argument("--all", action="store_true",
                        help="every secret of --field, as id16<TAB>secret")
    p.add_argument("--field", choices=("key", "p12"), default="key")
    p.set_defaults(func=cmd_get)
    p = sub.add_parser("forget")
    sel(p)
    p.set_defaults(func=cmd_forget)
    p = sub.add_parser("prune")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_prune)
    sub.add_parser("list").set_defaults(func=cmd_list)
    sub.add_parser("reap").set_defaults(func=cmd_reap)
    sub.add_parser("verify").set_defaults(func=cmd_verify)
    sub.add_parser("selftest").set_defaults(func=cmd_selftest)
    sub.add_parser("kdf-check").set_defaults(func=cmd_kdf_check)
    for name, fn in (("installer-set", cmd_installer_set), ("installer-get", cmd_installer_get)):
        p = sub.add_parser(name)
        p.add_argument("--name", required=True)
        p.set_defaults(func=fn)
    p = sub.add_parser("profile-get")
    p.add_argument("--name", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--unsigned", "--no-sign", action="store_true",
                   help="write the plist, not the signed profile")
    p.set_defaults(func=cmd_profile_get)
    sub.add_parser("profile-list").set_defaults(func=cmd_profile_list)
    p = sub.add_parser("profile-rm")
    p.add_argument("--name", required=True)
    p.set_defaults(func=cmd_profile_rm)

    ap.epilog = "commands: " + ", ".join(sub.choices)
    a = ap.parse_args()
    try:
        a.func(a)
    except KeychainError as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()

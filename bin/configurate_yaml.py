#!/usr/bin/env python3
"""
configurate_yaml.py -- YAML -> .mobileconfig (unsigned) -> signed .mobileconfig

Usage (from PKI_ROOT):
    bin/configurate_yaml.py mdm-private/yaml/myorganization-trust.yaml [--no-sign]

PKI_ROOT is the directory above this script's directory, and the script
chdir()s into it, exactly as bin/pki_structure.sh does:
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
    cd "${PKI_ROOT}"
All relative paths are therefore relative to PKI_ROOT, wherever you run it from.
SECURITY: YAML files and generated profiles can contain secrets (e.g. a Wi-Fi
password in a settings payload). Signing a profile does NOT encrypt it: any
plaintext secret in the YAML is readable in the signed .mobileconfig by anyone
who has it. Ownership is left alone (the script runs as whoever runs it);
only permissions are managed:
  * Generated profiles (mdm-private/mobfileconfigs-*) end up as 0700 directories and 0600
    files, also on exit when the run failed.
  * Before anything is read, ALL of mdm-private/ is checked. Loose permissions on the output
    directories/files produce a warning and are fixed immediately.
  * Loose permissions on everything else (your YAML, etc.) produce a warning and a prompt
    offering to fix them; nothing there is changed without a "y".
  * The YAML must live under mdm-private/, and the output directories must be inside it.
If the YAML has no 'identifier:', it is generated as  <reverse-DNS of $DOMAIN_VAR>.mdm.<yaml file name>
(e.g. org.myorganization.mdm.myorganization-trust), where DOMAIN_VAR is the identity.env
variable named below. An explicit 'identifier:' in the YAML still wins.
${VAR} / ${VAR|rdns} placeholders in the YAML fields identifier, name, description,
organization, and in payloads[].name / .description / .settings (recursively), are
filled in from ./identity.env (see load_identity below).

A profile needs at least one of 'certificates:' or 'payloads:'.

'certificates:' (with 'cert_dirs:') embeds X.509 certificates as
com.apple.security.root or com.apple.security.pkcs1 payloads; see resolve_cert.

'payloads:' is a list of arbitrary Apple payload dicts:
    payloads:
      - id: passcode              # required, stable, unique in the profile; do not
                                   # rename after deployment (see 'include:' below)
        type: com.apple.mobiledevice.passwordpolicy   # required, verbatim
        name: Passcode             # optional; PayloadDisplayName (default: id)
        description: ...           # optional; PayloadDescription
        settings:                  # Apple's own key names/types, passed through as-is.
          forcePIN: true           # Keys starting with "Payload" are reserved.
  'include:' merges other YAML files' 'payloads:' underneath this file's own, in the
  listed order, keyed by 'id' (this file's own payloads are applied last and win):
    include:
      - ios-restrictions-baseline.yaml
  Each include path is relative to the file that lists it (recursive: an included
  file's own 'include:' resolves relative to itself). An included file may contain
  only 'payloads:' and 'include:'. A later 'settings:' for the same id is deep-merged
  key by key into the earlier one; 'name'/'description'/'type' are replaced outright
  when given. Redefining an existing id with a different 'type' is an error -- use a
  different id instead.

Environment overrides (same names/defaults as create_codesign.sh):
    CERTDIR       default "codesign"    (signing identity directory)
    CERTNAME      default $CERTDIR
    HASH_DIGEST   default "sha256"
    ISSUERCADIR   default "intermediate"  (its certs/<ISSUERCANAME>.chain.pem and index.txt
    ISSUERCANAME  default $ISSUERCADIR     are used to vet signing certs: revoked/expired are skipped;
                                           every CRL in */crl/ is also checked, see collect_crls)
    CERTSHA1      optional: pick a specific signer when several usable ones exist
    UNSIGNED_DIR  default "mdm-private/mobfileconfigs-unsigned"
    SIGNED_DIR    default "mdm-private/mobfileconfigs-signed"
"""
import argparse
import glob
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

# Fixed namespace so UUIDs are deterministic across rebuilds. Change once, keep forever.
NAMESPACE = uuid.UUID("6f1c2f54-3b0e-4a57-9c5e-2d1f8a7b4c10")

# Payload types this script itself constructs as certificate payloads (see build_profile).
CERT_PAYLOAD_TYPES = {"com.apple.security.root", "com.apple.security.pkcs1"}

# Same definition as bin/pki_structure.sh.
ORIG_CWD = Path.cwd()
SCRIPT_DIR = Path(__file__).resolve().parent
PKI_ROOT = SCRIPT_DIR.parent
os.chdir(PKI_ROOT)
os.environ["PKI_ROOT"] = str(PKI_ROOT)  # so $PKI_ROOT works inside the YAML
MDM_PRIVATE = PKI_ROOT / "mdm-private"   # holds secrets: see audit_private() / secure_outputs()
os.umask(0o077)  # anything we (or openssl) create is private from the first byte


def die(msg):
    sys.exit(f"ERROR: {msg}")


def expand(p):
    return Path(os.path.expandvars(str(p))).expanduser()


def under_root(p):
    p = expand(p)
    return p if p.is_absolute() else PKI_ROOT / p


def load_yaml_file(path):
    try:
        cfg = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        die(f"cannot parse YAML {path}: {e}")
    return cfg or {}


# --------------------------------------------------------------------------
# identity.env  (bash variables) -> template placeholders in the YAML
# --------------------------------------------------------------------------
IDENTITY_ENV = PKI_ROOT / "identity.env"
_identity_cache = None

# Prints every exported variable as NAME\0VALUE\0 (portable to macOS bash 3.2, unlike `env -0`).
_EMIT = r"""for v in $(compgen -e); do printf '%s\0%s\0' "$v" "${!v}"; done"""


def _bash_env(script, *args):
    r = subprocess.run(["bash", "-c", script, "_", *args], capture_output=True,
                       env={"PKI_ROOT": str(PKI_ROOT), "HOME": str(Path.home()),
                            "PATH": os.environ.get("PATH", "/usr/bin:/bin")})
    if r.returncode:
        die(f"bash failed while reading {IDENTITY_ENV}:\n{r.stderr.decode(errors='replace')}")
    parts = r.stdout.decode().split("\0")[:-1]
    return dict(zip(parts[0::2], parts[1::2]))


def load_identity():
    """Source identity.env in a clean bash (so quoting, ${X} references etc. behave exactly as
    they do for the other scripts) and return only the variables it defines or changes."""
    global _identity_cache
    if _identity_cache is None:
        if not IDENTITY_ENV.is_file():
            die(f"{IDENTITY_ENV} not found, but the YAML uses ${{...}} placeholders")
        base = _bash_env(_EMIT)
        after = _bash_env('set -a; . "$1" 1>&2; ' + _EMIT, str(IDENTITY_ENV))
        _identity_cache = {k: v for k, v in after.items()
                           if base.get(k) != v and k not in ("_", "PWD", "OLDPWD", "SHLVL")}
    return _identity_cache


_PLACEHOLDER = re.compile(r"\$\{(\w+)(?:\|(\w+))?\}")
_FILTERS = {
    "rdns": lambda v: ".".join(reversed(v.strip(".").lower().split("."))),  # pki.example.org -> org.example.pki
    "lower": str.lower,
    "upper": str.upper,
}

# Name of the identity.env variable holding the bare domain (e.g. myorganization.org).
# Change this default, or override per run:  IDENTITY_DOMAIN_VAR=OTHER_VAR bin/configurate_yaml.py ...
DOMAIN_VAR = os.environ.get("IDENTITY_DOMAIN_VAR", "DOMAIN_NAME")


def default_identifier(yaml_stem):
    ident = load_identity()
    domain = ident.get(DOMAIN_VAR, "").strip()
    if not domain:
        die(f"no 'identifier:' in the YAML and '{DOMAIN_VAR}' is not set in {IDENTITY_ENV.name}. "
            f"Defined there: {sorted(ident)}. Set DOMAIN_VAR in {Path(__file__).name} "
            f"(or IDENTITY_DOMAIN_VAR=...) to the variable holding your domain.")
    stem = re.sub(r"[^A-Za-z0-9-]+", "-", yaml_stem).strip("-")
    return f"{_FILTERS['rdns'](domain)}.mdm.{stem}"


def render(text):
    """Replace ${VAR} and ${VAR|filter} using identity.env (falling back to the environment)."""
    if not isinstance(text, str) or "${" not in text:
        return text
    ident = load_identity()

    def sub(m):
        name, flt = m.groups()
        val = ident.get(name, os.environ.get(name))
        if val is None:
            die(f"'${{{name}}}' is not defined in {IDENTITY_ENV.name}. Defined there: {sorted(ident)}")
        if flt:
            if flt not in _FILTERS:
                die(f"unknown filter '{flt}' in '${{{name}|{flt}}}' (available: {sorted(_FILTERS)})")
            val = _FILTERS[flt](val)
        return val

    return _PLACEHOLDER.sub(sub, text)


def render_deep(obj):
    """Apply render() to every string leaf in a nested dict/list structure."""
    if isinstance(obj, dict):
        return {k: render_deep(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [render_deep(v) for v in obj]
    return render(obj)


# --------------------------------------------------------------------------
# 'payloads:' / 'include:' merging
# --------------------------------------------------------------------------
def deep_merge_settings(base, overlay):
    """Recursively merge overlay into base; overlay wins on scalar conflicts, dicts
    merge key by key, anything else (lists, scalars) is replaced outright."""
    result = dict(base)
    for k, v in overlay.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = deep_merge_settings(result[k], v)
        else:
            result[k] = v
    return result


def merge_payload_entry(base, overlay):
    merged = dict(base)
    for key in ("name", "description", "type"):
        if key in overlay:
            merged[key] = overlay[key]
    merged["settings"] = deep_merge_settings(base.get("settings") or {}, overlay.get("settings") or {})
    return merged


def merge_payloads(base_list, overlay_list, source_desc=""):
    """Merge overlay_list into base_list by 'id'. A later entry with the same id deep-merges
    its 'settings' into the earlier one; 'name'/'description'/'type' are replaced outright
    when given. An id reused with a different 'type' is an error."""
    by_id, order = {}, []
    for p in base_list:
        pid = p.get("id")
        if not pid:
            die(f"payload entry missing required 'id'{source_desc}: {p}")
        if pid in by_id:
            die(f"duplicate payload id '{pid}'{source_desc}")
        by_id[pid] = dict(p)
        order.append(pid)
    for p in overlay_list:
        pid = p.get("id")
        if not pid:
            die(f"payload entry missing required 'id'{source_desc}: {p}")
        if pid in by_id:
            existing = by_id[pid]
            if "type" in p and existing.get("type") and p["type"] != existing["type"]:
                die(f"payload id '{pid}' redefined with a different type "
                    f"('{existing['type']}' -> '{p['type']}'){source_desc}; use a different id")
            by_id[pid] = merge_payload_entry(existing, p)
        else:
            by_id[pid] = dict(p)
            order.append(pid)
    return [by_id[pid] for pid in order]


def resolve_payloads_from_file(path, allow_extra_keys, _seen):
    """Load path, verify it may only contain 'payloads:'/'include:' unless allow_extra_keys,
    and return its fully merged payload list (its own includes resolved first)."""
    path = path.resolve()
    if path in _seen:
        die(f"circular 'include:' detected at {path}")
    _seen = _seen | {path}
    cfg = load_yaml_file(path)
    if not allow_extra_keys:
        extra = set(cfg) - {"payloads", "include"}
        if extra:
            die(f"included file {path} may contain only 'payloads:' (and its own "
                f"'include:'); found: {sorted(extra)}")
    return resolve_included_payloads(cfg, path, _seen)


def resolve_included_payloads(cfg, path, _seen):
    """Resolve cfg's 'include:' list (each entry relative to path's directory, recursively),
    then merge cfg's own 'payloads:' on top (last, so it wins)."""
    merged = []
    for inc in cfg.get("include", []):
        inc_path = (path.parent / expand(inc)).resolve()
        if not inc_path.is_file():
            die(f"include '{inc}' referenced from {path} not found: {inc_path}")
        inc_payloads = resolve_payloads_from_file(inc_path, allow_extra_keys=False, _seen=_seen)
        merged = merge_payloads(merged, inc_payloads, f" (from {inc_path})")
    merged = merge_payloads(merged, cfg.get("payloads", []), f" (from {path})")
    return merged


# --------------------------------------------------------------------------
# Certificates
# --------------------------------------------------------------------------
def load_cert(path):
    raw = Path(path).read_bytes()
    if b"-----BEGIN" in raw:
        return x509.load_pem_x509_certificate(raw)
    return x509.load_der_x509_certificate(raw)


def resolve_cert(name, cert_dirs):
    """Find a certificate file.  Tries an exact filename in each cert_dir; if none,
    falls back to '<stem>.*<suffix>' to match create_*.sh's '<name>.<sha1>.cer'
    renaming.  Errors on no match or on more than one distinct match."""
    p = expand(name)
    bases = [p.parent] if p.is_absolute() else [d / p.parent for d in cert_dirs]
    exact = {(b / p.name).resolve() for b in bases if (b / p.name).is_file()}
    hits = exact or {
        f.resolve()
        for b in bases
        for f in b.glob(f"{glob.escape(p.stem)}.*{glob.escape(p.suffix)}")
        if f.is_file()
    }
    if not hits:
        die(f"certificate '{name}' not found in: {[str(b) for b in bases]}")
    if len(hits) > 1:
        die(f"certificate '{name}' is ambiguous, matches:\n  " + "\n  ".join(map(str, sorted(hits)))
            + "\nUse a more specific filename or path in the YAML.")
    return hits.pop()


def common_name(name, fallback):
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return attrs[0].value
    return fallback


# --------------------------------------------------------------------------
# Profile
# --------------------------------------------------------------------------
def build_profile(cfg, cert_dirs):
    for key in ("identifier", "name", "description"):
        if key not in cfg:
            die(f"YAML is missing required field '{key}'")
    cert_entries = cfg.get("certificates", [])
    payload_entries = cfg.get("payloads", [])
    if not cert_entries and not payload_entries:
        die("YAML needs at least one of 'payloads' or 'certificates'")
    scope = cfg.get("scope", "System")
    if scope not in ("System", "User"):
        die(f"scope must be System or User, got '{scope}'")

    ident = cfg["identifier"]
    payloads, seen = [], set()

    for entry in cert_entries:
        path = resolve_cert(entry, cert_dirs)
        cert = load_cert(path)
        is_root = cert.subject == cert.issuer
        ptype = "com.apple.security.root" if is_root else "com.apple.security.pkcs1"
        fp = cert.fingerprint(hashes.SHA256()).hex()
        u = str(uuid.uuid5(NAMESPACE, f"{ident}:{fp}")).upper()
        if u in seen:
            die(f"certificate listed twice: {path}")
        seen.add(u)
        payloads.append({
            "PayloadCertificateFileName": path.with_suffix(".cer").name,
            "PayloadContent": cert.public_bytes(serialization.Encoding.DER),  # -> <data>
            "PayloadDescription": ("Adds a CA root certificate" if is_root
                                   else "Adds a PKCS#1-formatted certificate"),
            "PayloadDisplayName": common_name(cert.subject, path.stem),
            "PayloadIdentifier": f"{ident}.{ptype.rsplit('.', 1)[1]}.{u}",  # e.g. <profile id>.root.<UUID>
            "PayloadType": ptype,
            "PayloadUUID": u,
            "PayloadVersion": 1,
        })
        print(f"  + {ptype.rsplit('.', 1)[1]:5s} {payloads[-1]['PayloadDisplayName']}  ({path})")

    for entry in payload_entries:
        for key in ("id", "type"):
            if key not in entry:
                die(f"payload entry missing required '{key}': {entry}")
        pid, ptype = entry["id"], entry["type"]
        settings = entry.get("settings") or {}
        bad = [k for k in settings if k.startswith("Payload")]
        if bad:
            die(f"payload '{pid}': settings key(s) {bad} start with 'Payload', which is reserved")
        u = str(uuid.uuid5(NAMESPACE, f"{ident}:{pid}")).upper()
        if u in seen:
            die(f"payload id '{pid}' produces a duplicate UUID/identifier")
        seen.add(u)
        pl = {
            "PayloadType": ptype,
            "PayloadIdentifier": f"{ident}.{pid}",
            "PayloadUUID": u,
            "PayloadVersion": 1,
            "PayloadDisplayName": entry.get("name", pid),
            "PayloadEnabled": True,
        }
        if "description" in entry:
            pl["PayloadDescription"] = entry["description"]
        pl.update(settings)
        payloads.append(pl)
        print(f"  + payload {ptype}  (id: {pid})")

    profile = {
        "PayloadContent": payloads,
        "PayloadDescription": cfg["description"],
        "PayloadDisplayName": cfg["name"],
        "PayloadIdentifier": ident,
        "PayloadScope": scope,
        "PayloadType": "Configuration",
        "PayloadUUID": str(uuid.uuid5(NAMESPACE, ident)).upper(),
        "PayloadVersion": 1,
    }
    if cfg.get("organization"):
        profile["PayloadOrganization"] = cfg["organization"]
    if cfg.get("removal_disallowed") is not None:
        profile["PayloadRemovalDisallowed"] = bool(cfg["removal_disallowed"])
    return profile


def validate_profile(profile):
    """Check the keys/values Apple's Configuration Profile documentation requires."""
    def check(d, where, want_type=None):
        for k, t in (("PayloadType", str), ("PayloadIdentifier", str),
                     ("PayloadUUID", str), ("PayloadVersion", int)):
            if not isinstance(d.get(k), t):
                die(f"{where}: missing or invalid {k}")
        if want_type and d["PayloadType"] != want_type:
            die(f"{where}: PayloadType must be '{want_type}'")
        if d["PayloadVersion"] != 1:
            die(f"{where}: PayloadVersion must be 1")
        try:
            if str(uuid.UUID(d["PayloadUUID"])).upper() != d["PayloadUUID"]:
                raise ValueError
        except ValueError:
            die(f"{where}: PayloadUUID '{d['PayloadUUID']}' is not an uppercase UUID")
        if not re.fullmatch(r"[A-Za-z0-9.-]+", d["PayloadIdentifier"]):
            die(f"{where}: PayloadIdentifier '{d['PayloadIdentifier']}' is not reverse-DNS style")

    check(profile, "profile", "Configuration")
    if not profile.get("PayloadContent"):
        die("profile: PayloadContent must contain at least one payload")
    ids, uuids = {profile["PayloadIdentifier"]}, {profile["PayloadUUID"]}
    for i, pl in enumerate(profile["PayloadContent"], 1):
        check(pl, f"payload {i}")
        if pl["PayloadType"] in CERT_PAYLOAD_TYPES:
            if not isinstance(pl.get("PayloadContent"), bytes):
                die(f"payload {i}: certificate PayloadContent must be <data>")
        if pl["PayloadIdentifier"] in ids or pl["PayloadUUID"] in uuids:
            die(f"payload {i}: PayloadIdentifier/PayloadUUID is not unique within the profile")
        ids.add(pl["PayloadIdentifier"])
        uuids.add(pl["PayloadUUID"])


# --------------------------------------------------------------------------
# Signing (same layout/conventions as create_codesign.sh)
# --------------------------------------------------------------------------
def _validity(c):
    nb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=timezone.utc)
    return nb, na


def load_ca_index(index_file):
    """Parse an OpenSSL CA database (index.txt): {serial_int: (status, revocation_field)}.
    Columns are tab-separated: status, expiry, revocation[,reason], serial(hex), filename, subject."""
    db = {}
    for line in index_file.read_text().splitlines():
        f = line.split("\t")
        if len(f) >= 4:
            try:
                db[int(f[3], 16)] = (f[0], f[2])
            except ValueError:
                pass
    return db


def output_dirs():
    unsigned = under_root(os.environ.get("UNSIGNED_DIR", "mdm-private/mobfileconfigs-unsigned"))
    signed = under_root(os.environ.get("SIGNED_DIR", "mdm-private/mobfileconfigs-signed"))
    return unsigned, signed


def _entries(base, prune=()):
    """Yield (path, wanted_mode) for base and everything below it: directories want 0700, files
    0600, and wanted_mode None marks a symlink (never followed). Directories in `prune` are skipped."""
    prune = {os.path.abspath(p) for p in prune}
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if os.path.abspath(os.path.join(dirpath, d)) not in prune]
        yield dirpath, 0o700
        for n in dirnames + filenames:
            if os.path.islink(os.path.join(dirpath, n)):
                yield os.path.join(dirpath, n), None
        for n in filenames:
            if not os.path.islink(os.path.join(dirpath, n)):
                yield os.path.join(dirpath, n), 0o600


def find_loose(base, prune=()):
    """Return ([(path, wanted_mode, stat)] whose mode is wrong, [symlinks])."""
    loose, links = [], []
    for path, want in _entries(base, prune):
        if want is None:
            links.append(path)
            continue
        st = os.lstat(path)
        if stat.S_IMODE(st.st_mode) != want:
            loose.append((path, want, st))
    return loose, links


def apply_fix(loose):
    for path, want, st in loose:
        try:
            os.chmod(path, want)
        except PermissionError as e:
            die(f"cannot change permissions of {path}: {e}")


def secure_outputs(dirs):
    """Always applied to the generated profiles: 0700 directories, 0600 files."""
    for d in dirs:
        if not d.resolve().is_relative_to(MDM_PRIVATE.resolve()):
            continue  # never touch anything outside mdm-private/
        if d.is_symlink():
            die(f"{d} is a symlink; refusing")
        if not d.is_dir():
            continue
        loose, links = find_loose(d)
        if links:
            die(f"symlink under {d}: {links[0]} (refusing, chmod would follow it)")
        if loose:
            print(f"WARNING: {len(loose)} path(s) under {d} had loose permissions at exit; "
                  f"set to 0700/0600", file=sys.stderr)
        apply_fix(loose)


def _under(path, directory):
    path, directory = os.path.abspath(path), os.path.abspath(directory)
    return path == directory or path.startswith(directory + os.sep)


def _print_loose(items):
    for path, want, st in items[:25]:
        print(f"  {stat.S_IMODE(st.st_mode):04o}  (want {want:04o})  {os.path.relpath(path, PKI_ROOT)}",
              file=sys.stderr)
    if len(items) > 25:
        print(f"  ... and {len(items) - 25} more", file=sys.stderr)


def audit_private(outputs):
    """Check permissions of everything under mdm-private/ before any secret is read.
      * Generated-profile locations (the output directories and their files): warn, then fix
        immediately (these are always 0700/0600).
      * Everything else (your YAML, etc.): warn and offer to fix; nothing changes without a y."""
    if not MDM_PRIVATE.is_dir():
        return
    loose, links = find_loose(MDM_PRIVATE)
    for link in links:
        print(f"WARNING: symlink under {MDM_PRIVATE.name}/ (not followed, not checked): {link}",
              file=sys.stderr)

    out_loose = [x for x in loose if any(_under(x[0], d) for d in outputs)]
    out_paths = {x[0] for x in out_loose}
    in_loose = [x for x in loose if x[0] not in out_paths]

    if out_loose:
        print(f"\nWARNING: output paths under {MDM_PRIVATE.name}/ had loose permissions; "
              f"setting 0700 (dirs) / 0600 (files) now:", file=sys.stderr)
        _print_loose(out_loose)
        apply_fix(out_loose)

    if not in_loose:
        return
    print(f"\nWARNING: these private paths under {MDM_PRIVATE.name}/ may hold secrets but are "
          f"not restricted (want 0700 dirs / 0600 files):", file=sys.stderr)
    _print_loose(in_loose)

    fix_cmd = (f"find {MDM_PRIVATE.name} -type d -exec chmod 0700 {{}} + && "
               f"find {MDM_PRIVATE.name} -type f -exec chmod 0600 {{}} +")
    if not sys.stdin.isatty():
        print(f"Not changed (no terminal to prompt on). To fix, from {PKI_ROOT}:\n  {fix_cmd}\n",
              file=sys.stderr)
        return
    try:
        answer = input("Change them now? [y/N] ").strip().lower()
    except EOFError:
        answer = ""
    if answer in ("y", "yes"):
        apply_fix(in_loose)
        print(f"  permissions fixed on {len(in_loose)} path(s)")
    else:
        print(f"WARNING: continuing with loose permissions. To fix later, from {PKI_ROOT}:\n"
              f"  {fix_cmd}\n", file=sys.stderr)


def collect_crls():
    """Load every CRL under PKI_ROOT/*/crl/.  In each directory prefer '*.crl.pem'; if there is
    none, use '*.crl' (DER or PEM).  Returns [(path, crl_object)]."""
    found = []
    for d in sorted(PKI_ROOT.glob("*/crl")):
        files = sorted(d.glob("*.crl.pem")) or sorted(d.glob("*.crl"))
        for f in files:
            raw = f.read_bytes()
            try:
                crl = (x509.load_pem_x509_crl(raw) if b"-----BEGIN" in raw
                       else x509.load_der_x509_crl(raw))
            except ValueError as e:
                die(f"cannot parse CRL {f}: {e}")
            found.append((f, crl))
    return found


def signer_problems(cert, cert_file, ca_db, ca_bundle, crl_bundle, now):
    """Return a list of reasons this certificate must not be used to sign (empty = usable)."""
    nb, na = _validity(cert)
    if now < nb:
        return [f"not valid until {nb:%Y-%m-%d %H:%M}Z"]
    if now > na:
        return [f"expired {na:%Y-%m-%d %H:%M}Z"]

    entry = ca_db.get(cert.serial_number)
    if entry is None:
        return [f"serial {cert.serial_number:X} not in the issuer's index.txt (cannot confirm it is not revoked)"]
    status, rev = entry
    if status == "R":
        return [f"revoked ({rev})"]
    if status != "V":
        return [f"index.txt status '{status}' (expected V)"]

    try:  # if an EKU is present it must allow code signing
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if x509.oid.ExtendedKeyUsageOID.CODE_SIGNING not in eku:
            return ["ExtendedKeyUsage does not include codeSigning"]
    except x509.ExtensionNotFound:
        pass

    # Chain + CRL check: -crl_check_all needs a current, correctly signed CRL for the signer
    # (from the intermediate) and for every CA below the root (from the root).
    r = subprocess.run(["openssl", "verify", "-CAfile", str(ca_bundle),
                        "-crl_check_all", "-CRLfile", str(crl_bundle), str(cert_file)],
                       capture_output=True, text=True)
    if r.returncode:
        lines = (r.stdout + r.stderr).strip().splitlines()
        err = next((l for l in lines if "error" in l.lower()), lines[-1] if lines else "")
        hint = " (missing or expired CRL?)" if "CRL" in err else ""
        return [f"failed chain/CRL verification against {ca_bundle.name}: {err}{hint}"]
    return []


def find_signer():
    """Pick the newest signing cert that is in date, not revoked (per the issuer's index.txt),
    and chains to the issuer CA bundle.  Layout follows create_codesign.sh."""
    certdir_name = os.environ.get("CERTDIR", "codesign")
    certname = os.environ.get("CERTNAME", certdir_name)
    certdir = under_root(certdir_name)
    issuer_dir = under_root(os.environ.get("ISSUERCADIR", "intermediate"))
    issuer_name = os.environ.get("ISSUERCANAME", os.environ.get("ISSUERCADIR", "intermediate"))
    want = os.environ.get("CERTSHA1", "").lower()

    ca_bundle = issuer_dir / "certs" / f"{issuer_name}.chain.pem"
    if not ca_bundle.is_file():  # same fallback as create_codesign.sh
        ca_bundle = issuer_dir / "certs" / f"{issuer_name}.cert.pem"
    if not ca_bundle.is_file():
        die(f"issuer CA chain not found: {issuer_dir / 'certs' / (issuer_name + '.chain.pem')}")
    index_file = issuer_dir / "index.txt"
    if not index_file.is_file():
        die(f"{index_file} not found; cannot check revocation status of signing certs")
    ca_db = load_ca_index(index_file)

    crls = collect_crls()
    if not crls:
        die(f"no CRLs found in {PKI_ROOT}/*/crl/ (looked for *.crl.pem, then *.crl); "
            f"cannot check revocation")
    print("  CRLs: " + ", ".join(f"{f.parent.parent.name}/crl/{f.name}" for f, _ in crls), file=sys.stderr)

    now = datetime.now(timezone.utc)
    pat = re.compile(rf"^{re.escape(certname)}\.([0-9a-f]{{40}})\.cert\.pem$")
    usable, rejected = [], []
    with tempfile.TemporaryDirectory() as td:
        crl_bundle = Path(td) / "crls.pem"
        crl_bundle.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for _, c in crls))
        for f in sorted((certdir / "certs").glob(f"{glob.escape(certname)}.*.cert.pem")):
            m = pat.match(f.name)
            if not m or (want and m.group(1) != want):
                continue
            c = load_cert(f)
            problems = signer_problems(c, f, ca_db, ca_bundle, crl_bundle, now)
            if problems:
                rejected.append((f, problems[0]))
            else:
                usable.append((_validity(c)[0], m.group(1), f, c))

    for f, why in rejected:
        print(f"  skipping signer {f.name}: {why}", file=sys.stderr)
    if not usable:
        die(f"no usable signing certificate '{certname}.<sha1>.cert.pem' in {certdir / 'certs'}"
            + (f" with sha1 {want}" if want else "")
            + (" (all candidates rejected, see above)" if rejected else " (none found)"))

    usable.sort(key=lambda t: t[0])
    _, sha, cert_file, cert = usable[-1]  # newest usable
    if len(usable) > 1:
        print(f"  note: {len(usable)} usable signer certs found, using newest ({sha}); "
              f"set CERTSHA1 to override", file=sys.stderr)

    key = certdir / "private" / f"{certname}.{sha}.key.pem"
    chain = certdir / "certs" / f"{certname}.{sha}.chain.pem"
    pw = certdir / "private" / "passphrase.txt"
    for f in (key, pw):
        if not f.is_file():
            die(f"missing {f}")
    return cert_file, cert, key, chain, pw


def sign(unsigned, signed):
    signed.unlink(missing_ok=True)  # never leave a stale signed profile behind if signing fails
    digest = os.environ.get("HASH_DIGEST", "sha256")
    cert_file, cert, key, chain, pw = find_signer()

    with tempfile.TemporaryDirectory() as td:
        cmd = ["openssl", "smime", "-sign", "-binary", "-nodetach", "-md", digest,
               "-in", str(unsigned),
               "-signer", str(cert_file), "-inkey", str(key),
               "-passin", f"file:{pw}",        # line 1 of passphrase.txt, as in create_codesign.sh
               "-outform", "der", "-out", str(signed)]

        # Extra certs = issuer chain, minus the signer itself (avoids embedding it twice).
        if chain.is_file():
            der = cert.public_bytes(serialization.Encoding.DER)
            extras = [c for c in x509.load_pem_x509_certificates(chain.read_bytes())
                      if c.public_bytes(serialization.Encoding.DER) != der]
            if extras:
                extra_file = Path(td) / "extra.pem"
                extra_file.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in extras))
                cmd += ["-certfile", str(extra_file)]
        else:
            print(f"  warning: {chain} not found; signing without chain", file=sys.stderr)

        signed.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            die(f"openssl sign failed:\n{r.stderr}")

        # Integrity check: signature verifies and payload round-trips byte-for-byte.
        out = Path(td) / "verified.out"
        v = subprocess.run(["openssl", "smime", "-verify", "-binary", "-inform", "der", "-in", str(signed),
                            "-noverify", "-out", str(out)], capture_output=True, text=True)
        if v.returncode or out.read_bytes() != unsigned.read_bytes():
            die(f"verification of signed profile failed:\n{v.stderr}")
    print(f"  signed with {cert_file.name}")


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Convert a YAML description into a signed .mobileconfig")
    ap.add_argument("yaml_file", help="path to YAML (relative to PKI_ROOT)")
    ap.add_argument("--no-sign", action="store_true", help="only write the unsigned profile")
    args = ap.parse_args()

    outputs = output_dirs()
    audit_private(outputs)         # warn (+ prompt for the YAML) before any secret is read
    try:
        build(args)
    finally:
        secure_outputs(outputs)    # generated profiles: 0700/0600, even after a failure


def build(args):
    ypath = under_root(args.yaml_file)
    if not ypath.is_file() and (ORIG_CWD / args.yaml_file).is_file():
        ypath = (ORIG_CWD / args.yaml_file).resolve()  # convenience: path relative to where you ran it
    if not ypath.is_file():
        die(f"YAML file not found: {args.yaml_file}")
    if not ypath.resolve().is_relative_to(MDM_PRIVATE.resolve()):
        die(f"{ypath} is outside {MDM_PRIVATE}. YAML files can contain secrets and must live "
            f"under {MDM_PRIVATE.name}/")

    cfg = load_yaml_file(ypath)
    for key in ("identifier", "name", "description", "organization"):
        if key in cfg:
            cfg[key] = render(cfg[key])
    if "identifier" not in cfg:
        cfg["identifier"] = default_identifier(ypath.stem)
        print(f"  identifier (from {DOMAIN_VAR} in {IDENTITY_ENV.name}): {cfg['identifier']}")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", str(cfg.get("identifier", ""))):
        die(f"identifier '{cfg.get('identifier')}' must be reverse-DNS (letters, digits, '.' and '-')")

    cfg["payloads"] = render_deep(resolve_included_payloads(cfg, ypath, {ypath.resolve()}))

    cert_dirs = [under_root(d) for d in cfg.get("cert_dirs", [])]
    if cfg.get("certificates") and not cert_dirs:
        die("YAML has 'certificates' but no 'cert_dirs'")

    print(f"PKI_ROOT = {PKI_ROOT}\nBuilding {ypath.name}:")
    profile = build_profile(cfg, cert_dirs)
    validate_profile(profile)

    unsigned_dir, signed_dir = output_dirs()
    for d in (unsigned_dir, signed_dir):
        if not d.resolve().is_relative_to(MDM_PRIVATE.resolve()):
            die(f"output directory {d} must be inside {MDM_PRIVATE} (profiles can contain secrets)")
    unsigned_dir.mkdir(parents=True, exist_ok=True)
    unsigned = unsigned_dir / (ypath.stem + ".mobileconfig")

    # Two profiles with the same PayloadIdentifier replace each other on the device: refuse.
    for other in unsigned_dir.glob("*.mobileconfig"):
        if other.resolve() == unsigned.resolve():
            continue
        try:
            other_id = plistlib.loads(other.read_bytes()).get("PayloadIdentifier")
        except Exception:
            continue
        if other_id == profile["PayloadIdentifier"]:
            die(f"PayloadIdentifier '{other_id}' is already used by {other.name}. "
                f"Profiles with the same identifier replace each other on a device; "
                f"set a different 'identifier:' in {ypath.name}.")
    unsigned.write_bytes(plistlib.dumps(profile, fmt=plistlib.FMT_XML))
    plistlib.loads(unsigned.read_bytes())  # round-trip sanity check
    if shutil.which("plutil"):
        subprocess.run(["plutil", "-lint", str(unsigned)], check=True)
    print(f"  wrote {unsigned}")

    if not args.no_sign:
        signed = signed_dir / unsigned.name
        sign(unsigned, signed)
        print(f"  wrote {signed}")


if __name__ == "__main__":
    main()

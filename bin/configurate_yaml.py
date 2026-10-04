#!/usr/bin/env python3
"""
configurate_yaml.py -- YAML -> .mobileconfig (unsigned) -> signed
.mobileconfig

Usage (from PKI_ROOT):
    bin/configurate_yaml.py \
        mdm-private/yaml/myorganization-trust.yaml [--no-sign]

PKI_ROOT is the directory above this script's directory, and the
script chdir()s into it, exactly as bin/pki_structure.sh does:
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
    cd "${PKI_ROOT}"
All relative paths are therefore relative to PKI_ROOT, wherever you
run it from.

SECURITY: YAML files and generated profiles can contain secrets (e.g.
a Wi-Fi password in a settings payload). Signing a profile does NOT
encrypt it: any plaintext secret in the YAML is readable in the
signed .mobileconfig by anyone who has it. Ownership is left alone
(the script runs as whoever runs it); only permissions are managed:
  * Generated profiles (mdm-private/mobfileconfigs-*) end up as 0700
    directories and 0600 files, also on exit when the run failed.
  * Before anything is read, ALL of mdm-private/ is checked. Loose
    permissions on the output directories/files produce a warning
    and are fixed immediately.
  * Loose permissions on everything else (your YAML, etc.) produce a
    warning and a prompt offering to fix them; nothing there is
    changed without a "y".
  * The YAML must live under mdm-private/, and the output
    directories must be inside it.

If the YAML has no 'identifier:', it is generated as
<reverse-DNS of $DOMAIN_VAR>.mdm.<yaml file name>
(e.g. org.myorganization.mdm.myorganization-trust), where DOMAIN_VAR
is the pki_identity.env variable named below. An explicit
'identifier:' in the YAML still wins.

${VAR} / ${VAR|rdns} placeholders in the YAML fields identifier,
name, description, organization, short_name, and in payloads[].name
/ .description / .settings and accounts[]'s string fields (all
recursively), are filled in from ./pki_identity.env (see
load_identity below).

A profile needs at least one of 'certificates:', 'payloads:',
'identities:' or 'accounts:'.

'certificates:' (with 'cert_dirs:') embeds X.509 certificates as
com.apple.security.root or com.apple.security.pkcs1 payloads; see
resolve_file.

'payloads:' is a list of arbitrary Apple payload dicts:
    payloads:
      - id: passcode          # required, stable, unique in the
                               # profile; do not rename after
                               # deployment (see 'include:' below)
        type: com.apple.mobiledevice.passwordpolicy   # required
        name: Passcode         # optional; PayloadDisplayName
                               # (default: id)
        description: ...       # optional; PayloadDescription
        settings:               # Apple's own key names/types,
          forcePIN: true         # passed through as-is. Keys
                                  # starting with "Payload" are
                                  # reserved.
  'include:' merges other YAML files' 'payloads:' underneath this
  file's own, in the listed order, keyed by 'id' (this file's own
  payloads are applied last and win):
    include:
      - ios-restrictions-baseline.yaml
  Each include path is relative to the file that lists it (recursive:
  an included file's own 'include:' resolves relative to itself). An
  included file may contain only 'payloads:' and 'include:'. A later
  'settings:' for the same id is deep-merged key by key into the
  earlier one; 'name'/'description'/'type' are replaced outright when
  given. Redefining an existing id with a different 'type' is an
  error -- use a different id instead. 'accounts:' (below) are
  converted into 'payloads:' entries before 'include:' is resolved,
  so a hand-written payload with the same id overrides the
  account-generated one, field by field.

'identities:' embeds S/MIME identities as pairs of
com.apple.security.pkcs12 payloads (one signing cert, one encryption
cert):
    identity_dirs:                # optional; default shown
      - $PKI_ROOT/smime/private
      - $PKI_ROOT/archive-2023/smime/private
        # any number of PKI_ROOT-shaped smime/private/ trees, e.g.
        # an archived one alongside the current one
    identity_passphrase_file: smime/private/passphrase.txt
        # optional; default shown; line 2; shared by every entry
        # below unless an entry sets its own
    identities:
      - persona_myorganization_2026
        # plain name: looks for <name>-signature.p12 and
        # <name>-encryption.p12 via identity_dirs, default passphrase
      - name: persona_oldwork_2022
        identity_passphrase_file: archive-2023/smime/private/passphrase.txt
            # optional; this entry's own passphrase file, e.g. an
            # archived tree with a different passphrase
        allow_expired_encryption: true
            # optional, default false; lets this identity's
            # ENCRYPTION certificate be expired, for decrypting old
            # mail only -- never applies to the signing certificate,
            # which must never be expired
  Lookup follows resolve_file (same '<stem>.*<suffix>' fallback as
  'certificates:'). Each identity's UUIDs are available to
  'accounts:' mail entries as identity_uuids[name]
  {"signing": UUID, "encryption": UUID}; see AccountType.settings.
  Every identity certificate -- the one actually embedded in the
  .p12, opened with the configured passphrase, not a same-named file
  elsewhere -- is checked exactly like the code-signing signer below:
  'V' in the issuer's index.txt, and verifies against every CRL in
  PKI_ROOT/*/crl/, even when allow_expired_encryption lets an
  expired encryption certificate through. See build_identities /
  SMIME_ISSUERCADIR below. The "-signature"/"-encryption" suffix
  only says where to look; each certificate's own KeyUsage extension
  is checked against the role implied by that suffix, so a
  mislabeled or swapped file is rejected rather than silently
  embedded under the wrong role. See keyusage_roles.

A 'type:' in 'payloads:' or 'accounts:' may be a short name from
TYPE_ALIASES (e.g. 'airprint') instead of the full Apple PayloadType
string; either always works, and this table is the only place to add
another one. This covers every Configurator payload with no
special-cased Apple-key knowledge -- see TYPE_ALIASES and the example
fragment file mdm-private/yaml/ios-configurator-extras.yaml.sample
for the keys reference/support-level believed to be right for
AirPrint, Notifications, Web Clips and Fonts, and Content Filter's
simplest (BuiltIn) form; that file also flags AirPlay and Subscribed
Calendars as unverified against a real device -- their Apple key
names are not confidently known here, so check Apple's Device
Management documentation or an Apple Configurator export before using
either.

Any 'settings:' value of the exact shape {"file": path} or
{"base64": text} is replaced with the raw bytes of that file
(relative to PKI_ROOT, $VAR expanded) or that base64 text, letting
any payload embed binary data (a font under 'Font', an icon under
'Icon', etc.) with no dedicated YAML section or Python needed; see
embed_data_deep.

YAML footguns this script guards against, so a plain admin-facing
value stays what it looks like: plain 'true'/'false' (only) parse as
booleans -- 'yes'/'no'/'on'/'off' do not, since Apple payload values
are frequently exactly these words as enum strings (see
_StrictBoolLoader); an un-quoted bare date (2026-01-01) is rejected
with a clear message rather than silently becoming a wrong type (see
check_plistable), which also flags any other value plistlib could not
otherwise write.

'accounts:' is a list of network account entries, translated into the
matching Apple payload by an AccountType class (see ACCOUNT_TYPES):
mail (com.apple.mail.managed), caldav (com.apple.caldav.account),
carddav (com.apple.carddav.account).
    short_name: Jane Short Name
        # optional; default sender name for mail accounts
    accounts:
      - type: mail
        description: MyOrganization
            # required; also the default PayloadDisplayName
        email: jane@example.org       # required
        username: jane                # required
        password: "CHANGE-ME"         # required, secret
        host: example.org
            # required; used for both incoming/outgoing
        imap_port: 993                # optional, default shown
        smtp_port: 587                # optional, default shown
        account_name: Jane Doe
            # optional; else short_name, else description
        smime:                        # optional
          identity: persona_myorganization_2026
              # must appear in 'identities:'
          encrypt_by_default: false   # optional, default false
        settings:
              # optional escape hatch, applied last, Apple's
              # own keys
          PreventMove: true
      - type: caldav   # or carddav
        description: MyOrganization
        host: example.org
        username: jane
        password: "CHANGE-ME"
        port: 8443
            # optional; default 8443 (caldav) / 8843 (carddav)
        principal_url: ""             # optional, default ""
  Each account needs an 'id:' only to be referenced by an include or
  overridden by a hand-written payload; otherwise one is derived from
  type + description and must be unique among accounts. See
  AccountType subclasses for the full field list and defaults.

Environment overrides (same names/defaults as create_codesign.sh):
    CERTDIR       default "codesign"
                  (signing identity directory)
    CERTNAME      default $CERTDIR
    HASH_DIGEST   default "sha256"
    ISSUERCADIR   default "intermediate"
                  (its certs/<ISSUERCANAME>.chain.pem and index.txt
    ISSUERCANAME  default $ISSUERCADIR
                  are used to vet signing certs: revoked/expired are
                  skipped; every CRL in */crl/ is also checked, see
                  collect_crls)
    CERTSHA1      optional: pick a specific signer when several
                  usable ones exist
    SMIME_ISSUERCADIR   default $ISSUERCADIR
                  (same role as ISSUERCADIR/ISSUERCANAME, but for
    SMIME_ISSUERCANAME  default $SMIME_ISSUERCADIR
                  vetting 'identities:' certificates; override only
                  if S/MIME certs come from a different intermediate)
    UNSIGNED_DIR  default "mdm-private/mobfileconfigs-unsigned"
    SIGNED_DIR    default "mdm-private/mobfileconfigs-signed"
    IDENTITY_DOMAIN_VAR  see DOMAIN_VAR below
"""
from __future__ import annotations

import argparse
import base64
import glob
import hashlib
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Fixed namespace so UUIDs are deterministic across rebuilds. Change
# once, keep forever.
NAMESPACE = uuid.UUID("6f1c2f54-3b0e-4a57-9c5e-2d1f8a7b4c10")

# Payload types this script itself constructs with raw <data>
# PayloadContent (certificates and S/MIME identities): see
# build_profile / build_identities.
EMBEDDED_DATA_TYPES = {
    "com.apple.security.root",
    "com.apple.security.pkcs1",
    "com.apple.security.pkcs12",
}

# Short names for 'payloads:'/'accounts:' 'type:' -- purely a
# convenience so common payloads don't need Apple's full PayloadType
# string memorized; the literal string always still works too (this
# dict is consulted, and if 'type:' isn't a key here it is used
# as-is). Add to this table freely -- it is the only change needed
# to give a payload type a short name.
TYPE_ALIASES: dict[str, str] = {
    "passcode": "com.apple.mobiledevice.passwordpolicy",
    "restrictions": "com.apple.applicationaccess",
    "wifi": "com.apple.wifi.managed",
    # Note: 'mail', 'caldav', 'carddav' are deliberately not aliased
    # here -- those words are reserved for 'accounts:' 'type:' (see
    # ACCOUNT_TYPES), which does friendly-field translation, not a
    # plain alias to the Apple string. A hand-written 'payloads:'
    # entry for one of these still works, just spell out the full
    # type, e.g. com.apple.mail.managed.
    "airprint": "com.apple.airprint",
    "airplay": "com.apple.airplay",
    "content-filter": "com.apple.webcontent-filter",
    "fonts": "com.apple.font",
    "notifications": "com.apple.notificationsettings",
    "subscribed-calendar": "com.apple.subscribedcalendar",
    "webclip": "com.apple.webClip.managed",
}

# Same definition as bin/pki_structure.sh.
ORIG_CWD = Path.cwd()
SCRIPT_DIR = Path(__file__).resolve().parent
PKI_ROOT = SCRIPT_DIR.parent
os.chdir(PKI_ROOT)
os.environ["PKI_ROOT"] = str(PKI_ROOT)  # so $PKI_ROOT works in YAML
MDM_PRIVATE = PKI_ROOT / "mdm-private"
# ^ holds secrets: see audit_private() / secure_outputs()
os.umask(0o077)  # anything created here is private from the 1st byte


def die(msg: str) -> None:
    sys.exit(f"ERROR: {msg}")


def expand(p: str | Path) -> Path:
    return Path(os.path.expandvars(str(p))).expanduser()


def under_root(p: str | Path) -> Path:
    p = expand(p)
    return p if p.is_absolute() else PKI_ROOT / p


class _StrictBoolLoader(yaml.SafeLoader):
    """SafeLoader, but only true/True/TRUE/false/False/FALSE parse
    as booleans. Plain YAML (1.1) also treats
    yes/Yes/YES/no/No/NO/on/On/ON/off/Off/OFF as booleans, which is
    a landmine here: Apple payload values are frequently exactly
    these words as literal enum strings (e.g. EncryptionType: WPA,
    or a hypothetical AlertStyle: Off), and an unquoted 'off' would
    silently become Python False instead of the string 'off'. This
    does not relax the type system -- true/false quoted or not still
    parse as bool; it only removes the extra YAML 1.1 spellings, so
    anyone who does want a boolean still writes true/false."""


_STRICT_BOOL_RE = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")
_StrictBoolLoader.yaml_implicit_resolvers = {
    first: [
        (tag, regexp) if tag != "tag:yaml.org,2002:bool"
        else (tag, _STRICT_BOOL_RE)
        for tag, regexp in resolvers
    ]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


_PLIST_SCALAR_TYPES = (str, bytes, bytearray, bool, int, float, datetime)


def check_plistable(obj: Any, where: str = "profile") -> None:
    """Walk a nested structure and give a clear error for any value
    plistlib can't write, instead of an opaque failure from
    plistlib.dumps() much later. Catches the two most common
    accidental-YAML-type mistakes: a bare date (2026-01-01) parsed as
    datetime.date, and a key or value that YAML turned into
    something other than a plain string/scalar."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                die(f"{where}: key {k!r} is not a string "
                    f"({type(k).__name__}) -- check "
                    f"quoting/indentation around it")
            check_plistable(v, f"{where}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            check_plistable(v, f"{where}[{i}]")
    elif obj is None:
        die(f"{where}: value is empty/null -- plist has no such "
            f"value; remove the key or give it a value")
    elif isinstance(obj, date) and not isinstance(obj, datetime):
        die(f"{where}: bare date {obj} -- YAML read this as a date, "
            f"but plist needs either a full timestamp or a plain "
            f"string; write \"{obj}\" (quoted) if a string was meant")
    elif not isinstance(obj, _PLIST_SCALAR_TYPES):
        die(f"{where}: unsupported value type {type(obj).__name__} "
            f"({obj!r}) -- plist supports strings, numbers, "
            f"booleans, dates and binary data")


def load_yaml_file(path: Path) -> dict[str, Any]:
    try:
        cfg = yaml.load(path.read_text(), Loader=_StrictBoolLoader)
    except yaml.YAMLError as e:
        die(f"cannot parse YAML {path}: {e}")
    return cfg or {}


# ---------------------------------------------------------------------
# pki_identity.env  (bash variables) -> template placeholders in YAML
# ---------------------------------------------------------------------
IDENTITY_ENV = PKI_ROOT / "pki_identity.env"
_identity_cache: dict[str, str] | None = None

# Prints every exported variable as NAME\0VALUE\0 (portable to macOS
# bash 3.2, unlike `env -0`).
_EMIT = r"""for v in $(compgen -e); do printf '%s\0%s\0' "$v" "${!v}"; done"""


def _bash_env(script: str, *args: str) -> dict[str, str]:
    r = subprocess.run(
        ["bash", "-c", script, "_", *args],
        capture_output=True,
        env={
            "PKI_ROOT": str(PKI_ROOT),
            "HOME": str(Path.home()),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        },
    )
    if r.returncode:
        die(f"bash failed while reading {IDENTITY_ENV}:\n"
            f"{r.stderr.decode(errors='replace')}")
    parts = r.stdout.decode().split("\0")[:-1]
    return dict(zip(parts[0::2], parts[1::2]))


def load_identity() -> dict[str, str]:
    """Source pki_identity.env in a clean bash (so quoting, ${X}
    references etc. behave exactly as they do for the other scripts)
    and return only the variables it defines or changes."""
    global _identity_cache
    if _identity_cache is None:
        if not IDENTITY_ENV.is_file():
            die(f"{IDENTITY_ENV} not found, but the YAML uses "
                f"${{...}} placeholders")
        base = _bash_env(_EMIT)
        after = _bash_env('set -a; . "$1" 1>&2; ' + _EMIT,
                          str(IDENTITY_ENV))
        _identity_cache = {
            k: v for k, v in after.items()
            if base.get(k) != v
            and k not in ("_", "PWD", "OLDPWD", "SHLVL")
        }
    return _identity_cache


_PLACEHOLDER = re.compile(r"\$\{(\w+)(?:\|(\w+))?\}")
_FILTERS: dict[str, Callable[[str], str]] = {
    # pki.example.org -> org.example.pki
    "rdns": lambda v: ".".join(reversed(v.strip(".").lower().split("."))),
    "lower": str.lower,
    "upper": str.upper,
}

# Name of the pki_identity.env variable holding the bare domain
# (e.g. myorganization.org). Change this default, or override per
# run: IDENTITY_DOMAIN_VAR=OTHER_VAR bin/configurate_yaml.py ...
DOMAIN_VAR = os.environ.get("IDENTITY_DOMAIN_VAR", "DOMAIN_NAME")


def default_identifier(yaml_stem: str) -> str:
    ident = load_identity()
    domain = ident.get(DOMAIN_VAR, "").strip()
    if not domain:
        die(f"no 'identifier:' in the YAML and '{DOMAIN_VAR}' is "
            f"not set in {IDENTITY_ENV.name}. "
            f"Defined there: {sorted(ident)}. Set DOMAIN_VAR in "
            f"{Path(__file__).name} (or IDENTITY_DOMAIN_VAR=...) "
            f"to the variable holding your domain.")
    stem = re.sub(r"[^A-Za-z0-9-]+", "-", yaml_stem).strip("-")
    return f"{_FILTERS['rdns'](domain)}.mdm.{stem}"


def render(text: Any) -> Any:
    """Replace ${VAR} and ${VAR|filter} using pki_identity.env
    (falling back to the environment)."""
    if not isinstance(text, str) or "${" not in text:
        return text
    ident = load_identity()

    def sub(m: re.Match[str]) -> str:
        name, flt = m.groups()
        val = ident.get(name, os.environ.get(name))
        if val is None:
            die(f"'${{{name}}}' is not defined in "
                f"{IDENTITY_ENV.name}. Defined there: "
                f"{sorted(ident)}")
        if flt:
            if flt not in _FILTERS:
                die(f"unknown filter '{flt}' in '${{{name}|{flt}}}' "
                    f"(available: {sorted(_FILTERS)})")
            val = _FILTERS[flt](val)
        return val

    return _PLACEHOLDER.sub(sub, text)


def render_deep(obj: Any) -> Any:
    """Apply render() to every string leaf in a nested dict/list
    structure."""
    if isinstance(obj, dict):
        return {k: render_deep(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [render_deep(v) for v in obj]
    return render(obj)


# ---------------------------------------------------------------------
# Generic binary embedding for any 'settings:' value --
# {"file": path} / {"base64": text}
#
# Several Apple payloads need raw binary data under an arbitrary
# key: a font file under 'Font' (com.apple.font), an icon under
# 'Icon' (com.apple.webClip.managed), and so on. Rather than one
# bespoke top-level YAML section and Python loop per such payload
# (as 'certificates:' and 'identities:' already are, because those
# also need certificate parsing/validation), any payload's
# 'settings:' can embed a file directly:
#     settings:
#       Font: {file: fonts/MyFont.ttf}
#           # path relative to PKI_ROOT, $VAR expanded
#       Icon: {base64: iVBORw0KGgoAAAANSU...}
#           # already-encoded data, e.g. pasted from an existing
#           # exported .mobileconfig
# This one mechanism covers every current and future payload type
# that embeds a file, with no new Python needed to add another one.
# ---------------------------------------------------------------------
def embed_data_deep(obj: Any) -> Any:
    if isinstance(obj, dict):
        keys = set(obj)
        if keys == {"file"}:
            path = under_root(obj["file"])
            if not path.is_file():
                die(f"embedded file not found: {path} "
                    f"(from 'file: {obj['file']}')")
            return path.read_bytes()
        if keys == {"base64"}:
            try:
                return base64.b64decode(obj["base64"], validate=True)
            except (ValueError, TypeError) as e:
                die(f"invalid base64 value: {e}")
        return {k: embed_data_deep(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [embed_data_deep(v) for v in obj]
    return obj


# ---------------------------------------------------------------------
# 'payloads:' / 'include:' merging
# ---------------------------------------------------------------------
def deep_merge_settings(
    base: dict[str, Any], overlay: dict[str, Any]
) -> dict[str, Any]:
    """Recursively merge overlay into base; overlay wins on scalar
    conflicts, dicts merge key by key, anything else (lists,
    scalars) is replaced outright."""
    result = dict(base)
    for k, v in overlay.items():
        if (k in result and isinstance(result[k], dict)
                and isinstance(v, dict)):
            result[k] = deep_merge_settings(result[k], v)
        else:
            result[k] = v
    return result


def merge_payload_entry(
    base: dict[str, Any], overlay: dict[str, Any]
) -> dict[str, Any]:
    merged = dict(base)
    for key in ("name", "description", "type"):
        if key in overlay:
            merged[key] = overlay[key]
    merged["settings"] = deep_merge_settings(
        base.get("settings") or {}, overlay.get("settings") or {}
    )
    return merged


def merge_payloads(
    base_list: list[dict[str, Any]],
    overlay_list: list[dict[str, Any]],
    source_desc: str = "",
) -> list[dict[str, Any]]:
    """Merge overlay_list into base_list by 'id'. A later entry with
    the same id deep-merges its 'settings' into the earlier one;
    'name'/'description'/'type' are replaced outright when given.
    An id reused with a different 'type' is an error."""
    by_id: dict[str, dict[str, Any]] = {}
    order: list[str] = []
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
            if ("type" in p and existing.get("type")
                    and p["type"] != existing["type"]):
                die(f"payload id '{pid}' redefined with a different "
                    f"type ('{existing['type']}' -> '{p['type']}')"
                    f"{source_desc}; use a different id")
            by_id[pid] = merge_payload_entry(existing, p)
        else:
            by_id[pid] = dict(p)
            order.append(pid)
    return [by_id[pid] for pid in order]


def resolve_payloads_from_file(
    path: Path, allow_extra_keys: bool, _seen: frozenset[Path]
) -> list[dict[str, Any]]:
    """Load path, verify it may only contain 'payloads:'/'include:'
    unless allow_extra_keys, and return its fully merged payload
    list (its own includes resolved first)."""
    path = path.resolve()
    if path in _seen:
        die(f"circular 'include:' detected at {path}")
    _seen = _seen | {path}
    cfg = load_yaml_file(path)
    if not allow_extra_keys:
        extra = set(cfg) - {"payloads", "include"}
        if extra:
            die(f"included file {path} may contain only "
                f"'payloads:' (and its own 'include:'); "
                f"found: {sorted(extra)}")
    return resolve_included_payloads(cfg, path, _seen)


def resolve_included_payloads(
    cfg: dict[str, Any], path: Path, _seen: frozenset[Path]
) -> list[dict[str, Any]]:
    """Resolve cfg's 'include:' list (each entry relative to path's
    directory, recursively), then merge cfg's own 'payloads:' on top
    (last, so it wins)."""
    merged: list[dict[str, Any]] = []
    for inc in cfg.get("include", []):
        inc_path = (path.parent / expand(inc)).resolve()
        if not inc_path.is_file():
            die(f"include '{inc}' referenced from {path} not "
                f"found: {inc_path}")
        inc_payloads = resolve_payloads_from_file(
            inc_path, allow_extra_keys=False, _seen=_seen
        )
        merged = merge_payloads(merged, inc_payloads, f" (from {inc_path})")
    merged = merge_payloads(merged, cfg.get("payloads", []), f" (from {path})")
    return merged


# ---------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------
def load_cert(path: Path) -> x509.Certificate:
    raw = Path(path).read_bytes()
    if b"-----BEGIN" in raw:
        return x509.load_pem_x509_certificate(raw)
    return x509.load_der_x509_certificate(raw)


def resolve_file(name: str, dirs: list[Path]) -> Path:
    """Find a file (certificate or PKCS#12) by name. Tries an exact
    filename in each of `dirs`; if none, falls back to
    '<stem>.*<suffix>' to match create_*.sh's '<name>.<sha1>.cer'
    renaming. Errors on no match or on more than one distinct
    match."""
    p = expand(name)
    bases = [p.parent] if p.is_absolute() else [d / p.parent for d in dirs]
    exact = {(b / p.name).resolve() for b in bases if (b / p.name).is_file()}
    hits = exact or {
        f.resolve()
        for b in bases
        for f in b.glob(f"{glob.escape(p.stem)}.*{glob.escape(p.suffix)}")
        if f.is_file()
    }
    if not hits:
        die(f"file '{name}' not found in: {[str(b) for b in bases]}")
    if len(hits) > 1:
        die(f"file '{name}' is ambiguous, matches:\n  "
            + "\n  ".join(map(str, sorted(hits)))
            + "\nUse a more specific filename or path in the YAML.")
    return hits.pop()


def common_name(name: x509.Name, fallback: str) -> str:
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return attrs[0].value
    return fallback


# ---------------------------------------------------------------------
# S/MIME identities ('identities:') -> com.apple.security.pkcs12
# payloads
# ---------------------------------------------------------------------
def load_passphrase_line(path: Path, line_no: int) -> str:
    lines = Path(path).read_text().splitlines()
    if len(lines) < line_no:
        die(f"{path} has fewer than {line_no} lines "
            f"(need line {line_no})")
    return lines[line_no - 1]


def load_pkcs12(path: Path, password: str) -> x509.Certificate:
    """Open a .p12 and return its certificate. The private key and
    any extra certs in the bundle aren't needed here -- only the
    certificate is checked, and only its bytes are embedded in the
    profile."""
    try:
        _, cert, _ = pkcs12.load_key_and_certificates(
            path.read_bytes(), password.encode()
        )
    except ValueError as e:
        die(f"{path}: cannot open PKCS#12 (wrong passphrase, or "
            f"not a PKCS#12 file?): {e}")
    if cert is None:
        die(f"{path}: PKCS#12 contains no certificate")
    return cert


def keyusage_roles(cert: x509.Certificate) -> set[str] | None:
    """Return the S/MIME role(s) this certificate's KeyUsage
    extension actually supports: a subset of {"signing",
    "encryption"}, or None if the certificate carries no KeyUsage
    extension at all (nothing to check against). "signing" requires
    digitalSignature or nonRepudiation; "encryption" requires
    keyEncipherment (RSA) or keyAgreement (ECDH)."""
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return None
    roles: set[str] = set()
    if ku.digital_signature or ku.content_commitment:
        roles.add("signing")
    if ku.key_encipherment or ku.key_agreement:
        roles.add("encryption")
    return roles


def normalize_identity_entry(raw: Any) -> dict[str, Any]:
    """A 'identities:' entry is either a plain name, or a mapping
    with 'name:' plus optional 'identity_passphrase_file:' (its own
    passphrase file, e.g. for an archived PKI_ROOT-shaped tree with
    a different passphrase than the current one) and
    'allow_expired_encryption:' (see build_identities)."""
    if isinstance(raw, str):
        return {"name": raw}
    if isinstance(raw, dict) and isinstance(raw.get("name"), str):
        return raw
    die(f"invalid 'identities:' entry: {raw!r} -- expected a name, "
        f"or a mapping with 'name:'")


def build_identities(
    cfg: dict[str, Any], ident: str, identity_dirs: list[Path]
) -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    """Build a signing + encryption com.apple.security.pkcs12
    payload for each entry in 'identities:' (<name>-signature.p12
    and <name>-encryption.p12, found via resolve_file -- so
    identity_dirs may list any number of PKI_ROOT-shaped
    smime/private/ trees, e.g. an archived one alongside the
    current one).

    Each certificate is checked exactly like the code-signing signer
    in find_signer(): not revoked per the issuer's index.txt, and
    verifies against every CRL in PKI_ROOT/*/crl/. This checks the
    certificate actually embedded in the .p12 (opened with the
    configured passphrase) -- not a same-named file elsewhere such
    as smime/certs/, so a stray or stale file there can't make a bad
    identity look fine, or a fine one look bad.

    An identity's signing certificate must never be expired: it is
    never legitimate to sign new mail with an expired certificate.
    Its encryption certificate may be expired -- kept only to
    decrypt old archived mail -- if the entry sets
    'allow_expired_encryption: true'; revocation is still checked
    (against today's CRL/index.txt) even then.

    A plain passphrase file is shared by every entry by default
    (identity_passphrase_file:, or its own default); a mapping entry
    may set its own 'identity_passphrase_file:' to use a different
    one, e.g. an archived tree's own passphrase.txt.

    Returns (payloads, identity_uuids), where identity_uuids maps
    each name to {"signing": UUID, "encryption": UUID}.
    """
    entries = [normalize_identity_entry(e) for e in cfg.get("identities", [])]
    if not entries:
        return [], {}

    default_pw_file = cfg.get(
        "identity_passphrase_file", "smime/private/passphrase.txt"
    )

    def load_password(pw_rel: str) -> str:
        pw_file = under_root(pw_rel)
        if not pw_file.is_file():
            die(f"'identities:' given but passphrase file not "
                f"found: {pw_file} (set 'identity_passphrase_file:' "
                f"to override)")
        # line 1 = key passphrase, line 2 = p12 export password
        return load_passphrase_line(pw_file, 2)

    # Defaults to the same issuer as code signing; override with
    # SMIME_ISSUERCADIR/NAME if S/MIME certs come from a different
    # intermediate.
    ca_bundle, ca_db, crls = load_issuer_context(
        "SMIME_ISSUERCADIR",
        "SMIME_ISSUERCANAME",
        os.environ.get("ISSUERCADIR", "intermediate"),
    )
    now = datetime.now(timezone.utc)

    payloads: list[dict[str, Any]] = []
    identity_uuids: dict[str, dict[str, str]] = {}
    seen: set[str] = set()
    with tempfile.TemporaryDirectory() as td:
        crl_bundle = Path(td) / "crls.pem"
        crl_bundle.write_bytes(
            b"".join(c.public_bytes(serialization.Encoding.PEM)
                    for _, c in crls)
        )

        for spec in entries:
            name = spec["name"]
            password = load_password(
                spec.get("identity_passphrase_file", default_pw_file)
            )
            allow_expired_encryption = bool(
                spec.get("allow_expired_encryption", False)
            )

            roles: dict[str, str] = {}
            for role, suffix in (("signing", "signature"),
                                 ("encryption", "encryption")):
                path = resolve_file(f"{name}-{suffix}.p12", identity_dirs)
                data = path.read_bytes()
                cert = load_pkcs12(path, password)

                # The file name only says where to look; the
                # certificate's own KeyUsage extension says what
                # it's actually for. Catch a role/content mismatch
                # (wrong file renamed, swapped at issuance, etc.)
                # rather than silently embedding it under the wrong
                # label.
                supported_roles = keyusage_roles(cert)
                if supported_roles is not None and role not in supported_roles:
                    die(f"identity '{name}' ({role}) {path.name}: "
                        f"certificate's KeyUsage does not support "
                        f"{role} (supports: "
                        f"{sorted(supported_roles) or 'nothing'}) -- "
                        f"wrong certificate for this role?")

                pem_path = Path(td) / f"{path.stem}.pem"
                pem_path.write_bytes(
                    cert.public_bytes(serialization.Encoding.PEM)
                )
                allow_expired = (
                    role == "encryption" and allow_expired_encryption
                )
                problems = cert_problems(
                    cert, pem_path, ca_db, ca_bundle, crl_bundle, now,
                    required_eku=ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    eku_name="emailProtection",
                    allow_expired=allow_expired,
                )
                if problems:
                    die(f"identity '{name}' ({role}) {path.name}: "
                        f"{problems[0]}")
                if allow_expired and now > _validity(cert)[1]:
                    print(f"  WARNING: identity '{name}' encryption "
                          f"certificate is expired; included only "
                          f"to decrypt old mail (allow_expired_"
                          f"encryption: true) -- do not use it to "
                          f"encrypt anything new", file=sys.stderr)

                digest = hashlib.sha256(data).hexdigest()
                u = str(uuid.uuid5(
                    NAMESPACE, f"{ident}:identity:{name}:{role}:{digest}"
                )).upper()
                if u in seen:
                    die(f"identity '{name}' ({role}): duplicate UUID "
                        f"(identical file listed twice?)")
                seen.add(u)
                roles[role] = u
                payloads.append({
                    "Password": password,
                    "PayloadCertificateFileName": path.name,
                    "PayloadContent": data,  # -> <data>
                    "PayloadDescription":
                        "Adds a PKCS#12-formatted certificate",
                    "PayloadDisplayName": path.name,
                    "PayloadIdentifier": f"{ident}.pkcs12.{u}",
                    "PayloadType": "com.apple.security.pkcs12",
                    "PayloadUUID": u,
                    "PayloadVersion": 1,
                })
            identity_uuids[name] = roles
            print(f"  + pkcs12 {name}  "
                  f"(signing + encryption, from {identity_dirs})")
    return payloads, identity_uuids


# ---------------------------------------------------------------------
# Network accounts ('accounts:') -> 'payloads:' entries
#
# Each AccountType subclass captures one Apple payload's field
# mapping: its Apple PayloadType, the friendly fields it requires, a
# default PayloadDisplayName, and a settings() method building
# Apple's own keys from the friendly entry. accounts_to_
# payload_entries() turns 'accounts:' into ordinary payload entries
# (id/type/name/settings), so they flow through the same
# merge_payloads/render_deep/build_profile pipeline as hand-written
# 'payloads:' -- accounts are just a friendlier way to write a
# handful of well-known payload types.
# ---------------------------------------------------------------------

# One entry in an AccountType.fields table: (friendly_key, apple_key,
# default), where default is a literal value or a
# default_factory(entry, context) callable.
FieldMap = tuple[str, str, Any]


def _same_as(
    friendly_key: str,
) -> Callable[[dict[str, Any], dict[str, Any]], Any]:
    """A fields= default_factory: falls back to another friendly
    field on the same entry (e.g. Mail's outgoing host defaults to
    its incoming host)."""
    return lambda entry, context: entry[friendly_key]


class AccountType:
    """Base class translating one 'accounts:' entry into an Apple
    payload's own keys.

    Subclasses declare:
      apple_type -- the Apple PayloadType string.
      required   -- friendly field names that must be present
                    (checked by accounts_to_payload_entries before
                    settings() is ever called).
      fields     -- the plain 1:1 mappings: a tuple of
                    (friendly_key, apple_key, default), where
                    default is either a literal value or a
                    default_factory(entry, context) callable (see
                    _same_as above). The base settings() applies
                    these; a friendly_key may appear more than once
                    to fan out to several Apple keys (e.g. one
                    'use_ssl' -> two *UseSSL keys).
    A subclass overrides settings() only for what isn't a plain 1:1
    mapping -- a computed key, a conditional block -- calling
    super().settings(...) first and layering its own keys on top;
    see MailAccountType for the one case here that needs this
    (SMIME).
    """
    apple_type: str = ""
    required: tuple[str, ...] = ()
    fields: tuple[FieldMap, ...] = ()

    def display_name(self, entry: dict[str, Any]) -> str:
        return entry.get("description", "")

    def settings(
        self,
        entry: dict[str, Any],
        identity_uuids: dict[str, dict[str, str]],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for friendly_key, apple_key, default in self.fields:
            if friendly_key in entry:
                out[apple_key] = entry[friendly_key]
            elif callable(default):
                out[apple_key] = default(entry, context)
            else:
                out[apple_key] = default
        return out


class MailAccountType(AccountType):
    apple_type = "com.apple.mail.managed"
    required = ("description", "email", "username", "password", "host")
    fields: tuple[FieldMap, ...] = (
        ("description", "EmailAccountDescription", None),
        ("account_name", "EmailAccountName",
         lambda e, c: c.get("short_name") or e["description"]),
        ("account_type", "EmailAccountType", "EmailTypeIMAP"),
        ("email", "EmailAddress", None),
        ("incoming_host", "IncomingMailServerHostName", _same_as("host")),
        ("imap_port", "IncomingMailServerPortNumber", 993),
        ("use_ssl", "IncomingMailServerUseSSL", True),
        ("username", "IncomingMailServerUsername", None),
        ("password", "IncomingPassword", None),
        ("outgoing_host", "OutgoingMailServerHostName", _same_as("host")),
        ("smtp_port", "OutgoingMailServerPortNumber", 587),
        ("use_ssl", "OutgoingMailServerUseSSL", True),
        ("outgoing_username", "OutgoingMailServerUsername",
         _same_as("username")),
        ("prevent_app_sheet", "PreventAppSheet", False),
        ("prevent_move", "PreventMove", False),
        ("allow_mail_drop", "allowMailDrop", False),
        ("disable_recents_syncing", "disableMailRecentsSyncing", False),
    )

    def display_name(self, entry: dict[str, Any]) -> str:
        return entry["description"]

    def settings(
        self,
        entry: dict[str, Any],
        identity_uuids: dict[str, dict[str, str]],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        s = super().settings(entry, identity_uuids, context)
        s["IncomingMailServerAuthentication"] = "EmailAuthPassword"
        s["OutgoingMailServerAuthentication"] = "EmailAuthPassword"
        s["OutgoingPasswordSameAsIncomingPassword"] = (
            "outgoing_password" not in entry
        )
        if "outgoing_password" in entry:
            s["OutgoingPassword"] = entry["outgoing_password"]
        if "smime" in entry:
            smime = entry["smime"] or {}
            name = smime.get("identity")
            if name not in identity_uuids:
                die(f"account '{entry['description']}': "
                    f"smime.identity '{name}' is not listed in "
                    f"'identities:' ({sorted(identity_uuids)})")
            per_message = smime.get("allow_per_message_toggle", True)
            sign_overrideable = smime.get("signing_overrideable", True)
            encrypt_overrideable = smime.get("encrypt_overrideable", True)
            encrypt = bool(smime.get("encrypt_by_default", False))
            s.update({
                "SMIMEEnabled": True,
                "SMIMEEnablePerMessageSwitch": per_message,
                "SMIMEEnableEncryptionPerMessageSwitch": per_message,
                "SMIMESigningEnabled": smime.get("sign", True),
                "SMIMESigningUserOverrideable": sign_overrideable,
                "SMIMESigningCertificateUUID":
                    identity_uuids[name]["signing"],
                "SMIMESigningCertificateUUIDUserOverrideable":
                    sign_overrideable,
                "SMIMEEncryptByDefault": encrypt,
                "SMIMEEncryptByDefaultUserOverrideable":
                    encrypt_overrideable,
                "SMIMEEncryptionEnabled": encrypt,
                "SMIMEEncryptionCertificateUUID":
                    identity_uuids[name]["encryption"],
                "SMIMEEncryptionCertificateUUIDUserOverrideable":
                    encrypt_overrideable,
            })
        return s


class CalDAVAccountType(AccountType):
    apple_type = "com.apple.caldav.account"
    required = ("description", "host", "username", "password")
    fields: tuple[FieldMap, ...] = (
        ("description", "CalDAVAccountDescription", None),
        ("host", "CalDAVHostName", None),
        ("password", "CalDAVPassword", None),
        ("port", "CalDAVPort", 8443),
        ("principal_url", "CalDAVPrincipalURL", ""),
        ("use_ssl", "CalDAVUseSSL", True),
        ("username", "CalDAVUsername", None),
    )

    def display_name(self, entry: dict[str, Any]) -> str:
        return f"Calendar ({entry['description']})"


class CardDAVAccountType(AccountType):
    apple_type = "com.apple.carddav.account"
    required = ("description", "host", "username", "password")
    fields: tuple[FieldMap, ...] = (
        ("description", "CardDAVAccountDescription", None),
        ("host", "CardDAVHostName", None),
        ("password", "CardDAVPassword", None),
        ("port", "CardDAVPort", 8843),
        ("principal_url", "CardDAVPrincipalURL", ""),
        ("use_ssl", "CardDAVUseSSL", True),
        ("username", "CardDAVUsername", None),
    )

    def display_name(self, entry: dict[str, Any]) -> str:
        return "Contacts"


ACCOUNT_TYPES: dict[str, AccountType] = {
    "mail": MailAccountType(),
    "caldav": CalDAVAccountType(),
    "carddav": CardDAVAccountType(),
}


def slugify(text: Any) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", str(text)).strip("-").lower()
    return s or "account"


def accounts_to_payload_entries(
    cfg: dict[str, Any], identity_uuids: dict[str, dict[str, str]]
) -> list[dict[str, Any]]:
    """Turn 'accounts:' into a list of payload entries
    (id/type/name/settings), ready to merge_payloads() against
    'payloads:'/'include:'."""
    context = {"short_name": cfg.get("short_name")}
    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for i, entry in enumerate(cfg.get("accounts", []), 1):
        t = entry.get("type")
        account = ACCOUNT_TYPES.get(t)
        if account is None:
            die(f"account #{i}: unknown type '{t}' "
                f"(expected one of {sorted(ACCOUNT_TYPES)})")
        missing = [f for f in account.required if f not in entry]
        if missing:
            die(f"account #{i} (type {t}): missing required "
                f"field(s) {missing}")
        settings = account.settings(entry, identity_uuids, context)
        if entry.get("settings"):  # escape hatch: Apple's own keys
            settings = deep_merge_settings(settings, entry["settings"])
        pid = entry.get("id") or f"{t}-{slugify(entry.get('description', i))}"
        if pid in seen_ids:
            die(f"account #{i}: id '{pid}' is not unique among "
                f"accounts; set 'id:' explicitly")
        seen_ids.add(pid)
        entries.append({
            "id": pid,
            "type": account.apple_type,
            "name": entry.get("name", account.display_name(entry)),
            "settings": settings,
        })
    return entries


# ---------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------
def build_profile(
    cfg: dict[str, Any],
    cert_dirs: list[Path],
    identity_payloads: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    identity_payloads = list(identity_payloads)
    for key in ("identifier", "name", "description"):
        if key not in cfg:
            die(f"YAML is missing required field '{key}'")
    cert_entries = cfg.get("certificates", [])
    payload_entries = cfg.get("payloads", [])
    if not cert_entries and not payload_entries and not identity_payloads:
        die("YAML needs at least one of 'payloads', 'certificates', "
            "'identities' or 'accounts'")
    scope = cfg.get("scope", "System")
    if scope not in ("System", "User"):
        die(f"scope must be System or User, got '{scope}'")

    ident = cfg["identifier"]
    payloads: list[dict[str, Any]] = list(identity_payloads)
    seen: set[str] = {p["PayloadUUID"] for p in identity_payloads}

    for entry in cert_entries:
        path = resolve_file(entry, cert_dirs)
        cert = load_cert(path)
        is_root = cert.subject == cert.issuer
        ptype = ("com.apple.security.root" if is_root
                 else "com.apple.security.pkcs1")
        fp = cert.fingerprint(hashes.SHA256()).hex()
        u = str(uuid.uuid5(NAMESPACE, f"{ident}:{fp}")).upper()
        if u in seen:
            die(f"certificate listed twice: {path}")
        seen.add(u)
        payloads.append({
            "PayloadCertificateFileName": path.with_suffix(".cer").name,
            "PayloadContent": cert.public_bytes(serialization.Encoding.DER),
            "PayloadDescription": (
                "Adds a CA root certificate" if is_root
                else "Adds a PKCS#1-formatted certificate"
            ),
            "PayloadDisplayName": common_name(cert.subject, path.stem),
            # e.g. <profile id>.root.<UUID>
            "PayloadIdentifier": f"{ident}.{ptype.rsplit('.', 1)[1]}.{u}",
            "PayloadType": ptype,
            "PayloadUUID": u,
            "PayloadVersion": 1,
        })
        print(f"  + {ptype.rsplit('.', 1)[1]:5s} "
              f"{payloads[-1]['PayloadDisplayName']}  ({path})")

    for entry in payload_entries:
        for key in ("id", "type"):
            if key not in entry:
                die(f"payload entry missing required '{key}': {entry}")
        pid = entry["id"]
        ptype = TYPE_ALIASES.get(entry["type"], entry["type"])
        settings = entry.get("settings") or {}
        bad = [k for k in settings if k.startswith("Payload")]
        if bad:
            die(f"payload '{pid}': settings key(s) {bad} start "
                f"with 'Payload', which is reserved")
        u = str(uuid.uuid5(NAMESPACE, f"{ident}:{pid}")).upper()
        if u in seen:
            die(f"payload id '{pid}' produces a duplicate UUID/identifier")
        seen.add(u)
        pl: dict[str, Any] = {
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

    profile: dict[str, Any] = {
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


def validate_profile(profile: dict[str, Any]) -> None:
    """Check the keys/values Apple's Configuration Profile
    documentation requires."""
    def check(
        d: dict[str, Any], where: str, want_type: str | None = None
    ) -> None:
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
            die(f"{where}: PayloadUUID '{d['PayloadUUID']}' is not "
                f"an uppercase UUID")
        if not re.fullmatch(r"[A-Za-z0-9.-]+", d["PayloadIdentifier"]):
            die(f"{where}: PayloadIdentifier '{d['PayloadIdentifier']}' "
                f"is not reverse-DNS style")

    check(profile, "profile", "Configuration")
    if not profile.get("PayloadContent"):
        die("profile: PayloadContent must contain at least one payload")
    ids = {profile["PayloadIdentifier"]}
    uuids = {profile["PayloadUUID"]}
    for i, pl in enumerate(profile["PayloadContent"], 1):
        check(pl, f"payload {i}")
        if pl["PayloadType"] in EMBEDDED_DATA_TYPES:
            if not isinstance(pl.get("PayloadContent"), bytes):
                die(f"payload {i}: certificate PayloadContent must be <data>")
        if pl["PayloadIdentifier"] in ids or pl["PayloadUUID"] in uuids:
            die(f"payload {i}: PayloadIdentifier/PayloadUUID is "
                f"not unique within the profile")
        ids.add(pl["PayloadIdentifier"])
        uuids.add(pl["PayloadUUID"])


# ---------------------------------------------------------------------
# Signing (same layout/conventions as create_codesign.sh)
# ---------------------------------------------------------------------
def _validity(c: x509.Certificate) -> tuple[datetime, datetime]:
    nb = (getattr(c, "not_valid_before_utc", None)
          or c.not_valid_before.replace(tzinfo=timezone.utc))
    na = (getattr(c, "not_valid_after_utc", None)
          or c.not_valid_after.replace(tzinfo=timezone.utc))
    return nb, na


def load_ca_index(index_file: Path) -> dict[int, tuple[str, str]]:
    """Parse an OpenSSL CA database (index.txt):
    {serial_int: (status, revocation_field)}. Columns are
    tab-separated: status, expiry, revocation[,reason],
    serial(hex), filename, subject."""
    db: dict[int, tuple[str, str]] = {}
    for line in index_file.read_text().splitlines():
        f = line.split("\t")
        if len(f) >= 4:
            try:
                db[int(f[3], 16)] = (f[0], f[2])
            except ValueError:
                pass
    return db


def output_dirs() -> tuple[Path, Path]:
    unsigned = under_root(
        os.environ.get("UNSIGNED_DIR", "mdm-private/mobfileconfigs-unsigned")
    )
    signed = under_root(
        os.environ.get("SIGNED_DIR", "mdm-private/mobfileconfigs-signed")
    )
    return unsigned, signed


def _entries(
    base: Path, prune: Iterable[Path] = ()
) -> Iterator[tuple[str, int | None]]:
    """Yield (path, wanted_mode) for base and everything below it:
    directories want 0700, files 0600, and wanted_mode None marks a
    symlink (never followed). Directories in `prune` are skipped."""
    prune_set = {os.path.abspath(p) for p in prune}
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [
            d for d in dirnames
            if os.path.abspath(os.path.join(dirpath, d)) not in prune_set
        ]
        yield dirpath, 0o700
        for n in dirnames + filenames:
            if os.path.islink(os.path.join(dirpath, n)):
                yield os.path.join(dirpath, n), None
        for n in filenames:
            if not os.path.islink(os.path.join(dirpath, n)):
                yield os.path.join(dirpath, n), 0o600


LooseEntry = tuple[str, int, os.stat_result]


def find_loose(
    base: Path, prune: Iterable[Path] = ()
) -> tuple[list[LooseEntry], list[str]]:
    """Return ([(path, wanted_mode, stat)] whose mode is wrong,
    [symlinks])."""
    loose: list[LooseEntry] = []
    links: list[str] = []
    for path, want in _entries(base, prune):
        if want is None:
            links.append(path)
            continue
        st = os.lstat(path)
        if stat.S_IMODE(st.st_mode) != want:
            loose.append((path, want, st))
    return loose, links


def apply_fix(loose: list[LooseEntry]) -> None:
    for path, want, st in loose:
        try:
            os.chmod(path, want)
        except PermissionError as e:
            die(f"cannot change permissions of {path}: {e}")


def secure_outputs(dirs: Iterable[Path]) -> None:
    """Always applied to the generated profiles: 0700 directories,
    0600 files."""
    for d in dirs:
        if not d.resolve().is_relative_to(MDM_PRIVATE.resolve()):
            continue  # never touch anything outside mdm-private/
        if d.is_symlink():
            die(f"{d} is a symlink; refusing")
        if not d.is_dir():
            continue
        loose, links = find_loose(d)
        if links:
            die(f"symlink under {d}: {links[0]} "
                f"(refusing, chmod would follow it)")
        if loose:
            print(f"WARNING: {len(loose)} path(s) under {d} had "
                  f"loose permissions at exit; set to 0700/0600",
                  file=sys.stderr)
        apply_fix(loose)


def _under(path: str, directory: Path) -> bool:
    path = os.path.abspath(path)
    directory_s = os.path.abspath(directory)
    return path == directory_s or path.startswith(directory_s + os.sep)


def _print_loose(items: list[LooseEntry]) -> None:
    for path, want, st in items[:25]:
        print(f"  {stat.S_IMODE(st.st_mode):04o}  (want {want:04o})  "
              f"{os.path.relpath(path, PKI_ROOT)}", file=sys.stderr)
    if len(items) > 25:
        print(f"  ... and {len(items) - 25} more", file=sys.stderr)


def audit_private(outputs: Iterable[Path]) -> None:
    """Check permissions of everything under mdm-private/ before
    any secret is read.
      * Generated-profile locations (the output directories and
        their files): warn, then fix immediately (these are always
        0700/0600).
      * Everything else (your YAML, etc.): warn and offer to fix;
        nothing changes without a y."""
    if not MDM_PRIVATE.is_dir():
        return
    loose, links = find_loose(MDM_PRIVATE)
    for link in links:
        print(f"WARNING: symlink under {MDM_PRIVATE.name}/ "
              f"(not followed, not checked): {link}", file=sys.stderr)

    out_loose = [x for x in loose if any(_under(x[0], d) for d in outputs)]
    out_paths = {x[0] for x in out_loose}
    in_loose = [x for x in loose if x[0] not in out_paths]

    if out_loose:
        print(f"\nWARNING: output paths under {MDM_PRIVATE.name}/ had "
              f"loose permissions; setting 0700 (dirs) / 0600 (files) "
              f"now:", file=sys.stderr)
        _print_loose(out_loose)
        apply_fix(out_loose)

    if not in_loose:
        return
    print(f"\nWARNING: these private paths under {MDM_PRIVATE.name}/ "
          f"may hold secrets but are not restricted (want 0700 dirs "
          f"/ 0600 files):", file=sys.stderr)
    _print_loose(in_loose)

    fix_cmd = (
        f"find {MDM_PRIVATE.name} -type d -exec chmod 0700 {{}} + && "
        f"find {MDM_PRIVATE.name} -type f -exec chmod 0600 {{}} +"
    )
    if not sys.stdin.isatty():
        print(f"Not changed (no terminal to prompt on). To fix, "
              f"from {PKI_ROOT}:\n  {fix_cmd}\n", file=sys.stderr)
        return
    try:
        answer = input("Change them now? [y/N] ").strip().lower()
    except EOFError:
        answer = ""
    if answer in ("y", "yes"):
        apply_fix(in_loose)
        print(f"  permissions fixed on {len(in_loose)} path(s)")
    else:
        print(f"WARNING: continuing with loose permissions. "
              f"To fix later, from {PKI_ROOT}:\n  {fix_cmd}\n",
              file=sys.stderr)


def collect_crls() -> list[tuple[Path, x509.CertificateRevocationList]]:
    """Load every CRL under PKI_ROOT/*/crl/. In each directory
    prefer '*.crl.pem'; if there is none, use '*.crl' (DER or PEM).
    Returns [(path, crl_object)]."""
    found: list[tuple[Path, x509.CertificateRevocationList]] = []
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


def cert_problems(
    cert: x509.Certificate,
    cert_file: Path,
    ca_db: dict[int, tuple[str, str]],
    ca_bundle: Path,
    crl_bundle: Path,
    now: datetime,
    required_eku: x509.ObjectIdentifier | None = None,
    eku_name: str = "",
    allow_expired: bool = False,
) -> list[str]:
    """Return a list of reasons this certificate must not be
    trusted (empty = OK). Shared by the code-signing signer check
    and the S/MIME identity check below; required_eku is only
    enforced when the certificate actually carries an
    ExtendedKeyUsage extension.

    allow_expired lets an expired certificate through (still
    subject to every other check, including today's CRL/index.txt
    revocation status) -- for an S/MIME encryption certificate kept
    only to decrypt old mail. A certificate that isn't valid yet is
    never allowed, and this must never be set for a code-signing
    signer or an S/MIME signing certificate: signing with an expired
    certificate is never legitimate."""
    nb, na = _validity(cert)
    if now < nb:
        return [f"not valid until {nb:%Y-%m-%d %H:%M}Z"]
    expired = now > na
    if expired and not allow_expired:
        return [f"expired {na:%Y-%m-%d %H:%M}Z"]

    entry = ca_db.get(cert.serial_number)
    if entry is None:
        return [f"serial {cert.serial_number:X} not in the issuer's "
                f"index.txt (cannot confirm it is not revoked)"]
    status, rev = entry
    if status == "R":
        return [f"revoked ({rev})"]
    if status != "V":
        return [f"index.txt status '{status}' (expected V)"]

    if required_eku is not None:
        try:  # if an EKU is present it must allow the required use
            eku = cert.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
            if required_eku not in eku:
                return [f"ExtendedKeyUsage does not include "
                        f"{eku_name or required_eku}"]
        except x509.ExtensionNotFound:
            pass

    # Chain + CRL check: -crl_check_all needs a current, correctly
    # signed CRL for this certificate (from the intermediate) and
    # for every CA below the root (from the root). -no_check_time
    # only skips openssl's own expiry check (already decided above);
    # it does not relax the CRL/revocation check, which still runs
    # against today's CRL.
    cmd = ["openssl", "verify", "-CAfile", str(ca_bundle),
          "-crl_check_all", "-CRLfile", str(crl_bundle)]
    if expired:
        cmd.append("-no_check_time")
    cmd.append(str(cert_file))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        lines = (r.stdout + r.stderr).strip().splitlines()
        err = next((l for l in lines if "error" in l.lower()),
                    lines[-1] if lines else "")
        hint = " (missing or expired CRL?)" if "CRL" in err else ""
        return [f"failed chain/CRL verification against "
                f"{ca_bundle.name}: {err}{hint}"]
    return []


IssuerContext = tuple[Path, dict[int, tuple[str, str]],
                     list[tuple[Path, x509.CertificateRevocationList]]]

_issuer_context_cache: dict[str, IssuerContext] = {}


def load_issuer_context(
    dir_var: str, name_var: str, default_dir: str
) -> IssuerContext:
    """Resolve an issuer's CA bundle, its OpenSSL index.txt
    (parsed) and every CRL in PKI_ROOT/*/crl/. Shared by the
    code-signing signer check (ISSUERCADIR/ISSUERCANAME) and the
    S/MIME identity check (SMIME_ISSUERCADIR/SMIME_ISSUERCANAME,
    defaulting to the same issuer as code signing unless
    overridden). Cached per dir_var: CRLs are read once per run."""
    if dir_var in _issuer_context_cache:
        return _issuer_context_cache[dir_var]
    issuer_dir = under_root(os.environ.get(dir_var, default_dir))
    issuer_name = os.environ.get(
        name_var, os.environ.get(dir_var, default_dir)
    )

    ca_bundle = issuer_dir / "certs" / f"{issuer_name}.chain.pem"
    if not ca_bundle.is_file():  # same fallback as create_codesign.sh
        ca_bundle = issuer_dir / "certs" / f"{issuer_name}.cert.pem"
    if not ca_bundle.is_file():
        die(f"issuer CA chain not found: "
            f"{issuer_dir / 'certs' / (issuer_name + '.chain.pem')}")
    index_file = issuer_dir / "index.txt"
    if not index_file.is_file():
        die(f"{index_file} not found; cannot check revocation "
            f"status of certificates")
    ca_db = load_ca_index(index_file)

    crls = collect_crls()
    if not crls:
        die(f"no CRLs found in {PKI_ROOT}/*/crl/ (looked for "
            f"*.crl.pem, then *.crl); cannot check revocation")
    print("  CRLs: " + ", ".join(
        f"{f.parent.parent.name}/crl/{f.name}" for f, _ in crls
    ), file=sys.stderr)

    _issuer_context_cache[dir_var] = (ca_bundle, ca_db, crls)
    return ca_bundle, ca_db, crls


SignerInfo = tuple[Path, x509.Certificate, Path, Path, Path]


def find_signer() -> SignerInfo:
    """Pick the newest signing cert that is in date, not revoked
    (per the issuer's index.txt), and chains to the issuer CA
    bundle. Layout follows create_codesign.sh."""
    certdir_name = os.environ.get("CERTDIR", "codesign")
    certname = os.environ.get("CERTNAME", certdir_name)
    certdir = under_root(certdir_name)
    want = os.environ.get("CERTSHA1", "").lower()

    ca_bundle, ca_db, crls = load_issuer_context(
        "ISSUERCADIR", "ISSUERCANAME", "intermediate"
    )

    now = datetime.now(timezone.utc)
    pat = re.compile(rf"^{re.escape(certname)}\.([0-9a-f]{{40}})\.cert\.pem$")
    usable: list[tuple[datetime, str, Path, x509.Certificate]] = []
    rejected: list[tuple[Path, str]] = []
    with tempfile.TemporaryDirectory() as td:
        crl_bundle = Path(td) / "crls.pem"
        crl_bundle.write_bytes(
            b"".join(c.public_bytes(serialization.Encoding.PEM)
                    for _, c in crls)
        )
        for f in sorted((certdir / "certs").glob(
            f"{glob.escape(certname)}.*.cert.pem"
        )):
            m = pat.match(f.name)
            if not m or (want and m.group(1) != want):
                continue
            c = load_cert(f)
            problems = cert_problems(
                c, f, ca_db, ca_bundle, crl_bundle, now,
                required_eku=ExtendedKeyUsageOID.CODE_SIGNING,
                eku_name="codeSigning",
            )
            if problems:
                rejected.append((f, problems[0]))
            else:
                usable.append((_validity(c)[0], m.group(1), f, c))

    for f, why in rejected:
        print(f"  skipping signer {f.name}: {why}", file=sys.stderr)
    if not usable:
        die(f"no usable signing certificate "
            f"'{certname}.<sha1>.cert.pem' in {certdir / 'certs'}"
            + (f" with sha1 {want}" if want else "")
            + (" (all candidates rejected, see above)" if rejected
               else " (none found)"))

    usable.sort(key=lambda t: t[0])
    _, sha, cert_file, cert = usable[-1]  # newest usable
    if len(usable) > 1:
        print(f"  note: {len(usable)} usable signer certs found, "
              f"using newest ({sha}); set CERTSHA1 to override",
              file=sys.stderr)

    key = certdir / "private" / f"{certname}.{sha}.key.pem"
    chain = certdir / "certs" / f"{certname}.{sha}.chain.pem"
    pw = certdir / "private" / "passphrase.txt"
    for f in (key, pw):
        if not f.is_file():
            die(f"missing {f}")
    return cert_file, cert, key, chain, pw


def sign(unsigned: Path, signed: Path) -> None:
    # never leave a stale signed profile behind if signing fails
    signed.unlink(missing_ok=True)
    digest = os.environ.get("HASH_DIGEST", "sha256")
    cert_file, cert, key, chain, pw = find_signer()

    with tempfile.TemporaryDirectory() as td:
        cmd = [
            "openssl", "smime", "-sign", "-binary", "-nodetach",
            "-md", digest,
            "-in", str(unsigned),
            "-signer", str(cert_file), "-inkey", str(key),
            # line 1 of passphrase.txt, as in create_codesign.sh
            "-passin", f"file:{pw}",
            "-outform", "der", "-out", str(signed),
        ]

        # Extra certs = issuer chain, minus the signer itself
        # (avoids embedding it twice).
        if chain.is_file():
            der = cert.public_bytes(serialization.Encoding.DER)
            extras = [
                c for c in x509.load_pem_x509_certificates(chain.read_bytes())
                if c.public_bytes(serialization.Encoding.DER) != der
            ]
            if extras:
                extra_file = Path(td) / "extra.pem"
                extra_file.write_bytes(b"".join(
                    c.public_bytes(serialization.Encoding.PEM) for c in extras
                ))
                cmd += ["-certfile", str(extra_file)]
        else:
            print(f"  warning: {chain} not found; signing without chain",
                  file=sys.stderr)

        signed.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            die(f"openssl sign failed:\n{r.stderr}")

        # Integrity check: signature verifies and payload
        # round-trips byte-for-byte.
        out = Path(td) / "verified.out"
        v = subprocess.run(
            ["openssl", "smime", "-verify", "-binary", "-inform", "der",
             "-in", str(signed), "-noverify", "-out", str(out)],
            capture_output=True, text=True,
        )
        if v.returncode or out.read_bytes() != unsigned.read_bytes():
            die(f"verification of signed profile failed:\n{v.stderr}")
    print(f"  signed with {cert_file.name}")


# ---------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(
        description="Convert a YAML description into a signed .mobileconfig"
    )
    ap.add_argument("yaml_file", help="path to YAML (relative to PKI_ROOT)")
    ap.add_argument("--no-sign", action="store_true",
                    help="only write the unsigned profile")
    args = ap.parse_args()

    outputs = output_dirs()
    # warn (+ prompt for the YAML) before any secret is read
    audit_private(outputs)
    try:
        build(args)
    finally:
        # generated profiles: 0700/0600, even after a failure
        secure_outputs(outputs)


def build(args: argparse.Namespace) -> None:
    ypath = under_root(args.yaml_file)
    if not ypath.is_file() and (ORIG_CWD / args.yaml_file).is_file():
        # convenience: path relative to where you ran it
        ypath = (ORIG_CWD / args.yaml_file).resolve()
    if not ypath.is_file():
        die(f"YAML file not found: {args.yaml_file}")
    if not ypath.resolve().is_relative_to(MDM_PRIVATE.resolve()):
        die(f"{ypath} is outside {MDM_PRIVATE}. YAML files can "
            f"contain secrets and must live under {MDM_PRIVATE.name}/")

    cfg = load_yaml_file(ypath)
    for key in ("identifier", "name", "description", "organization",
                "short_name"):
        if key in cfg:
            cfg[key] = render(cfg[key])
    if "identifier" not in cfg:
        cfg["identifier"] = default_identifier(ypath.stem)
        print(f"  identifier (from {DOMAIN_VAR} in {IDENTITY_ENV.name}): "
              f"{cfg['identifier']}")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", str(cfg.get("identifier", ""))):
        die(f"identifier '{cfg.get('identifier')}' must be reverse-DNS "
            f"(letters, digits, '.' and '-')")
    ident = cfg["identifier"]

    identity_dirs = [
        under_root(d) for d in cfg.get("identity_dirs", ["smime/private"])
    ]
    identity_payloads, identity_uuids = build_identities(
        cfg, ident, identity_dirs
    )

    # 'accounts:' become payload entries, merged UNDER any
    # hand-written 'payloads:' (which therefore override an account
    # field for field, the same way 'include:' works below).
    account_entries = accounts_to_payload_entries(cfg, identity_uuids)
    if account_entries:
        cfg["payloads"] = merge_payloads(
            account_entries, cfg.get("payloads", [])
        )

    cfg["payloads"] = render_deep(
        resolve_included_payloads(cfg, ypath, frozenset({ypath.resolve()}))
    )
    # {"file": ...} / {"base64": ...} -> bytes
    cfg["payloads"] = embed_data_deep(cfg["payloads"])

    cert_dirs = [under_root(d) for d in cfg.get("cert_dirs", [])]
    if cfg.get("certificates") and not cert_dirs:
        die("YAML has 'certificates' but no 'cert_dirs'")

    print(f"PKI_ROOT = {PKI_ROOT}\nBuilding {ypath.name}:")
    profile = build_profile(cfg, cert_dirs, identity_payloads)
    check_plistable(profile)
    validate_profile(profile)

    unsigned_dir, signed_dir = output_dirs()
    for d in (unsigned_dir, signed_dir):
        if not d.resolve().is_relative_to(MDM_PRIVATE.resolve()):
            die(f"output directory {d} must be inside {MDM_PRIVATE} "
                f"(profiles can contain secrets)")
    unsigned_dir.mkdir(parents=True, exist_ok=True)
    unsigned = unsigned_dir / (ypath.stem + ".mobileconfig")

    # Two profiles with the same PayloadIdentifier replace each
    # other on the device: refuse.
    for other in unsigned_dir.glob("*.mobileconfig"):
        if other.resolve() == unsigned.resolve():
            continue
        try:
            other_id = plistlib.loads(other.read_bytes()).get(
                "PayloadIdentifier"
            )
        except Exception:
            continue
        if other_id == profile["PayloadIdentifier"]:
            die(f"PayloadIdentifier '{other_id}' is already used by "
                f"{other.name}. Profiles with the same identifier "
                f"replace each other on a device; set a different "
                f"'identifier:' in {ypath.name}.")
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

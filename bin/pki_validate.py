#!/usr/bin/env python3
"""pki_validate.py -- the one certificate validator (S/MIME, code signing).

Library for configurate_yaml.py; CLI for create_credentials.sh:
  pki_validate.py ROLE CERT --ca-bundle PEM --crl-bundle PEM --index FILE...
                  [--allow-expired] [--allow-superseded]
                  [--allow-signature-with-encryption]
  pki_validate.py signer DIR [--name PREFIX] [--sha1 HEX]   (same bundles)
Accepted: prints the state, exit 0 (signer: the sha1 of the newest valid code
signing certificate DIR/certs/PREFIX.<sha1>.cert.pem). Rejected: reasons on
stderr, exit 1.
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SIGN = ("digital_signature", "content_commitment")
ENCR = ("key_encipherment", "data_encipherment", "key_agreement")


@dataclass(frozen=True)
class Role:
    eku: x509.ObjectIdentifier
    eku_name: str
    ku_any: tuple[str, ...]    # at least one must be set (empty: no demand)
    ku_none: tuple[str, ...]   # none may be set
    may_expire: bool           # expiry can be waived on request
    may_supersede: bool        # "superseded" revocation can be waived on request
    purpose: str = "any"       # `openssl verify -purpose` for the leaf; checks
                               # the EKU of every CA in the chain, which
                               # scopes the intermediates. "any" for codesign
                               # (no verify purpose exists for it)


# Policy table.
#
# state                  signature, codesign   encryption
# valid                  accept                accept
# expired                reject                accept with allow_expired
# revoked: superseded    reject                accept with allow_superseded
# expired + superseded   reject                accept with both
# other revocation, not yet valid, bad usage or chain: reject
POLICY: dict[str, Role] = {
    "signature": Role(ExtendedKeyUsageOID.EMAIL_PROTECTION, "emailProtection",
                      SIGN, (), False, False, "smimesign"),
    "encryption": Role(ExtendedKeyUsageOID.EMAIL_PROTECTION, "emailProtection",
                       ENCR, SIGN, True, True, "smimeencrypt"),
    "codesign": Role(ExtendedKeyUsageOID.CODE_SIGNING, "codeSigning",
                     ("digital_signature",), (), False, False, "any"),
}


@dataclass(frozen=True)
class Trust:
    ca_bundle: Path                       # roots + intermediates, PEM
    crl_bundle: Path                      # current CRLs, PEM
    index: dict[int, tuple[str, str]]     # serial -> (status, revocation field)


def load_cert(path: Path) -> x509.Certificate:
    raw = Path(path).read_bytes()
    if b"-----BEGIN" in raw:
        return x509.load_pem_x509_certificate(raw)
    return x509.load_der_x509_certificate(raw)


def common_name(name: x509.Name, fallback: str) -> str:
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return attrs[0].value
    return fallback


def validity(c: x509.Certificate) -> tuple[datetime, datetime]:
    nb = (getattr(c, "not_valid_before_utc", None)
          or c.not_valid_before.replace(tzinfo=timezone.utc))
    na = (getattr(c, "not_valid_after_utc", None)
          or c.not_valid_after.replace(tzinfo=timezone.utc))
    return nb, na


def index_entries(index_file: Path) -> list[tuple[str, str, str, str]]:
    """Rows of an OpenSSL index.txt: (status, revocation field, serial, subject)."""
    rows = []
    for line in Path(index_file).read_text().splitlines():
        f = line.split("\t")
        if len(f) >= 6:
            rows.append((f[0], f[2], f[3], f[5]))
    return rows


def load_ca_index(index_file: Path) -> dict[int, tuple[str, str]]:
    """OpenSSL index.txt -> {serial: (status, revocation field)}."""
    return {int(s, 16): (st, rev) for st, rev, s, _ in index_entries(index_file)}


def strict_verify() -> bool:
    """-x509_strict always; PKI_VERIFY_STRICT=0 only inside a test tree."""
    if os.environ.get("PKI_VERIFY_STRICT", "1") != "0":
        return True
    if (Path(__file__).resolve().parent.parent / ".pki_test_tree").exists():
        return False
    raise SystemExit("PKI_VERIFY_STRICT=0 is allowed only in a test tree.")


def _openssl_verify(cert_file: Path, trust: Trust, *, crl: str | None = None,
                    no_time: bool = False, purpose: str | None = None) -> str | None:
    """None if `openssl verify` passes, else its error line.
    crl: None, "leaf" (-crl_check) or "all" (-crl_check_all)."""
    cmd = [os.environ.get("OPENSSL", "openssl"), "verify", "-CAfile", str(trust.ca_bundle)]
    if strict_verify():
        cmd.append("-x509_strict")
    if purpose:
        cmd += ["-purpose", purpose]
    if crl:
        cmd += ["-crl_check_all" if crl == "all" else "-crl_check",
                "-CRLfile", str(trust.crl_bundle)]
    if no_time:
        cmd.append("-no_check_time")
    cmd.append(str(cert_file))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode == 0:
        return None
    lines = (r.stdout + r.stderr).strip().splitlines()
    err = next((l for l in lines if "error" in l.lower()),
               lines[-1] if lines else "")
    return f"{err}{' (missing or expired CRL?)' if 'CRL' in err else ''}"


def crl_revocation_reason(cert: x509.Certificate, crl_bundle: Path) -> str | None:
    """Reason a CRL from the cert's issuer lists it under; None if unlisted."""
    pem = Path(crl_bundle).read_text()
    for block in re.findall(
            r"-----BEGIN X509 CRL-----.*?-----END X509 CRL-----", pem, re.S):
        crl = x509.load_pem_x509_crl(block.encode())
        if crl.issuer != cert.issuer:
            continue
        entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if entry is None:
            continue
        try:
            return entry.extensions.get_extension_for_class(
                x509.CRLReason).value.reason.name
        except x509.ExtensionNotFound:
            return "unspecified"
    return None


_CHAIN_PROBLEMS: dict[tuple[Path, Path], list[str]] = {}


def ca_chain_problems(trust: Trust) -> list[str]:
    """Every non-root CA in the bundle must be valid and not revoked."""
    key = (trust.ca_bundle, trust.crl_bundle)
    if key in _CHAIN_PROBLEMS:
        return _CHAIN_PROBLEMS[key]
    problems: list[str] = []
    pem = trust.ca_bundle.read_text()
    with tempfile.TemporaryDirectory() as td:
        for i, block in enumerate(re.findall(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                pem, re.S)):
            ca = x509.load_pem_x509_certificate(block.encode())
            if ca.subject == ca.issuer:
                continue
            f = Path(td) / f"ca{i}.pem"
            f.write_text(block + "\n")
            err = _openssl_verify(f, trust, crl="leaf")
            if err:
                problems.append(
                    f"CA {common_name(ca.subject, 'certificate')}: {err}")
    _CHAIN_PROBLEMS[key] = problems
    return problems


def _usage_problem(cert: x509.Certificate, name: str, role: Role,
                   relax: bool = False) -> str | None:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return f"no ExtendedKeyUsage; cannot be limited to {role.eku_name}"
    if role.eku not in eku:
        return f"ExtendedKeyUsage lacks {role.eku_name}"
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        # No keyUsage is unrestricted: fine for signing, not for encryption.
        return (f"no keyUsage; cannot be limited to {name}"
                if role.ku_none else None)
    if role.ku_any and not any(getattr(ku, a) for a in role.ku_any):
        return f"keyUsage does not allow {name}"
    if not relax and any(getattr(ku, a) for a in role.ku_none):
        return f"keyUsage also allows signing; not a {name} certificate"
    return None


def issuer_eku_problem(cert: x509.Certificate, trust: Trust,
                       eku: x509.ObjectIdentifier, name: str) -> str | None:
    """`-purpose any` ignores CA EKUs: the issuing CA must allow `name`."""
    pem = trust.ca_bundle.read_text()
    for block in re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            pem, re.S):
        ca = x509.load_pem_x509_certificate(block.encode())
        try:
            cert.verify_directly_issued_by(ca)
        except (ValueError, TypeError, InvalidSignature):
            continue
        try:
            ekus = ca.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            return None   # unrestricted CA
        if eku in ekus:
            return None
    return f"no issuing CA allows {name}"


def validate(cert: x509.Certificate, cert_file: Path, role_name: str,
             trust: Trust, now: datetime, allow_expired: bool = False,
             allow_superseded: bool = False,
             allow_sig_enc: bool = False) -> tuple[list[str], str]:
    """Return (problems, state); problems is empty if accepted."""
    role = POLICY[role_name]
    nb, na = validity(cert)
    if now < nb:
        return [f"not valid until {nb:%Y-%m-%d %H:%M}Z"], ""
    allow_sig_enc = allow_sig_enc and role_name == "encryption"
    problem = _usage_problem(cert, role_name, role, allow_sig_enc)
    if problem:
        return [problem], ""
    problem = issuer_eku_problem(cert, trust, role.eku, role.eku_name)
    if problem:
        return [problem], ""

    entry = trust.index.get(cert.serial_number)
    if entry is None:
        return [f"serial {cert.serial_number:X} not in the issuer's index.txt "
                f"(cannot confirm it is not revoked)"], ""
    status, rev = entry
    expired = now > na
    superseded = status == "R" and rev.lower().endswith(",superseded")
    if status == "R" and not superseded:
        return [f"revoked ({rev})"], ""
    if status not in ("V", "R", "E") or (status == "E" and not expired):
        return [f"index.txt status '{status}' (expected V)"], ""

    for what, hit, may, allowed in (
            ("expired", expired, role.may_expire, allow_expired),
            ("superseded", superseded, role.may_supersede, allow_superseded)):
        if hit and not may:
            return [f"{what}: never accepted for a {role_name} certificate"], ""
        if hit and not allowed:
            return [f"{what}; opt-in: allow_{what}_{role_name}"], ""
    state = ", ".join(s for s, hit in (("expired", expired),
                                       ("revoked: superseded", superseded))
                      if hit) or "valid"

    if superseded:
        # openssl stops at the cert's own revocation: check chain, CAs, CRL apart.
        err = _openssl_verify(cert_file, trust, no_time=True,
                              purpose=role.purpose)
        if err:
            return [f"failed chain verification: {err}"], ""
        problems = ca_chain_problems(trust)
        if problems:
            return problems, ""
        reason = crl_revocation_reason(cert, trust.crl_bundle)
        if reason != "superseded":
            return [f"index.txt says superseded but the CRLs say "
                    f"{reason or 'not revoked'} (stale CRL?)"], ""
        return [], state

    # -no_check_time skips only the expiry already decided above, not the CRLs.
    err = _openssl_verify(cert_file, trust, crl="all", no_time=expired,
                          purpose=role.purpose)
    if err:
        return [f"failed chain/CRL verification: {err}"], ""
    return [], state


def pick_signer(certdir: Path, certname: str, trust: Trust, now: datetime,
                want: str = "") -> tuple[Path, str, list[str]]:
    """Newest in-date code signing certificate certdir/certs/NAME.<sha1>.cert.pem
    that validates. Returns (file, sha1, notes); notes list the rejected
    candidates and any ambiguity. LookupError if none qualifies."""
    pat = re.compile(rf"^{re.escape(certname)}\.([0-9a-f]{{40}})\.cert\.pem$")
    usable: list[tuple[datetime, str, Path]] = []
    notes: list[str] = []
    for f in sorted((certdir / "certs").glob(f"{glob.escape(certname)}.*.cert.pem")):
        m = pat.match(f.name)
        if not m or (want and m.group(1) != want):
            continue
        c = load_cert(f)
        problems, _ = validate(c, f, "codesign", trust, now)
        if problems:
            notes.append(f"skipping signer {f.name}: {problems[0]}")
        else:
            usable.append((validity(c)[0], m.group(1), f))
    if not usable:
        raise LookupError(
            f"no usable signing certificate '{certname}.<sha1>.cert.pem' in "
            f"{certdir / 'certs'}" + (f" with sha1 {want}" if want else "")
            + "".join(f"\n  {n}" for n in notes))
    usable.sort(key=lambda t: t[0])
    _, sha, f = usable[-1]
    if len(usable) > 1:
        notes.append(f"{len(usable)} usable signer certificates; using the "
                     f"newest ({sha}); pin one with its sha1")
    return f, sha, notes


def main() -> None:
    ap = argparse.ArgumentParser(description="Validate one certificate.")
    ap.add_argument("role", choices=[*sorted(POLICY), "signer"])
    ap.add_argument("cert", help="certificate; for signer: the directory")
    ap.add_argument("--name", default="codesign", help="signer: file name prefix")
    ap.add_argument("--sha1", default="", help="signer: pin one certificate")
    ap.add_argument("--ca-bundle", required=True)
    ap.add_argument("--crl-bundle", required=True)
    ap.add_argument("--index", action="append", required=True)
    ap.add_argument("--allow-expired", action="store_true")
    ap.add_argument("--allow-superseded", action="store_true")
    ap.add_argument("--allow-signature-with-encryption", action="store_true",
                    help="encryption certs with signing keyUsage")
    a = ap.parse_args()

    index: dict[int, tuple[str, str]] = {}
    for f in a.index:
        index.update(load_ca_index(Path(f)))
    trust = Trust(Path(a.ca_bundle), Path(a.crl_bundle), index)
    if a.role == "signer":
        try:
            _, sha, notes = pick_signer(Path(a.cert), a.name, trust,
                                        datetime.now(timezone.utc), a.sha1.lower())
        except LookupError as e:
            sys.exit(str(e))
        for n in notes:
            print(n, file=sys.stderr)
        print(sha)
        return
    cert = load_cert(Path(a.cert))
    problems, state = validate(cert, Path(a.cert), a.role, trust,
                               datetime.now(timezone.utc),
                               a.allow_expired, a.allow_superseded,
                               a.allow_signature_with_encryption)
    if problems:
        print("; ".join(problems), file=sys.stderr)
        sys.exit(1)
    print(state)


if __name__ == "__main__":
    main()

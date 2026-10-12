#!/usr/bin/env python3
"""pki_validate.py -- the one certificate validator (S/MIME, code signing).

Library for configurate_yaml.py; CLI for create_credentials.sh:
  pki_validate.py ROLE CERT --ca-bundle PEM --crl-bundle PEM --index FILE...
                  [--allow-expired] [--allow-superseded]
Accepted: prints the state, exit 0. Rejected: reasons on stderr, exit 1.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
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
                      SIGN, (), False, False),
    "encryption": Role(ExtendedKeyUsageOID.EMAIL_PROTECTION, "emailProtection",
                       ENCR, SIGN, True, True),
    "codesign": Role(ExtendedKeyUsageOID.CODE_SIGNING, "codeSigning",
                     ("digital_signature",), (), False, False),
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


def load_ca_index(index_file: Path) -> dict[int, tuple[str, str]]:
    """OpenSSL index.txt -> {serial: (status, revocation field)}."""
    db: dict[int, tuple[str, str]] = {}
    for line in Path(index_file).read_text().splitlines():
        f = line.split("\t")
        if len(f) >= 4:
            try:
                db[int(f[3], 16)] = (f[0], f[2])
            except ValueError:
                pass
    return db


def _openssl_verify(cert_file: Path, trust: Trust, *, crl: str | None = None,
                    no_time: bool = False) -> str | None:
    """None if `openssl verify` passes, else its error line.
    crl: None, "leaf" (-crl_check) or "all" (-crl_check_all)."""
    cmd = [os.environ.get("OPENSSL", "openssl"), "verify", "-CAfile", str(trust.ca_bundle)]
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


def ca_chain_problems(trust: Trust) -> list[str]:
    """Every non-root CA in the bundle must be valid and not revoked."""
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
    return problems


def _usage_problem(cert: x509.Certificate, name: str, role: Role) -> str | None:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if role.eku not in eku:
            return f"ExtendedKeyUsage lacks {role.eku_name}"
    except x509.ExtensionNotFound:
        pass
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        # No keyUsage is unrestricted: fine for signing, not for encryption.
        return f"no keyUsage; cannot be limited to {name}" if role.ku_none else None
    if role.ku_any and not any(getattr(ku, a) for a in role.ku_any):
        return f"keyUsage does not allow {name}"
    if any(getattr(ku, a) for a in role.ku_none):
        return f"keyUsage also allows signing; not a {name} certificate"
    return None


def validate(cert: x509.Certificate, cert_file: Path, role_name: str,
             trust: Trust, now: datetime, allow_expired: bool = False,
             allow_superseded: bool = False) -> tuple[list[str], str]:
    """Return (problems, state); problems is empty if accepted."""
    role = POLICY[role_name]
    nb, na = validity(cert)
    if now < nb:
        return [f"not valid until {nb:%Y-%m-%d %H:%M}Z"], ""
    problem = _usage_problem(cert, role_name, role)
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
        err = _openssl_verify(cert_file, trust, no_time=True)
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
    err = _openssl_verify(cert_file, trust, crl="all", no_time=expired)
    if err:
        return [f"failed chain/CRL verification: {err}"], ""
    return [], state


def main() -> None:
    ap = argparse.ArgumentParser(description="Validate one certificate.")
    ap.add_argument("role", choices=sorted(POLICY))
    ap.add_argument("cert")
    ap.add_argument("--ca-bundle", required=True)
    ap.add_argument("--crl-bundle", required=True)
    ap.add_argument("--index", action="append", required=True)
    ap.add_argument("--allow-expired", action="store_true")
    ap.add_argument("--allow-superseded", action="store_true")
    a = ap.parse_args()

    index: dict[int, tuple[str, str]] = {}
    for f in a.index:
        index.update(load_ca_index(Path(f)))
    trust = Trust(Path(a.ca_bundle), Path(a.crl_bundle), index)
    cert = load_cert(Path(a.cert))
    problems, state = validate(cert, Path(a.cert), a.role, trust,
                               datetime.now(timezone.utc),
                               a.allow_expired, a.allow_superseded)
    if problems:
        print("; ".join(problems), file=sys.stderr)
        sys.exit(1)
    print(state)


if __name__ == "__main__":
    main()

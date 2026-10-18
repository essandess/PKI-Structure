#!/usr/bin/env bash

# verify_installer.sh -- check an installer's signature without running it.
#
# Usage: verify_installer.sh INSTALLER (--root FILE | --root-sha256 HEX)
#
#   --root FILE        trust anchor: this PKI's root certificate (PEM or DER)
#   --root-sha256 HEX  use the root in the signature block if its SHA-256
#                      matches (fingerprint received separately)
#
# Run it from a trusted tree, never from the installer: the installer's own
# check sits in the file an attacker may have edited. Checks: unchanged since
# signing; the signer is a non-CA code signing certificate that chains to the
# anchor through CAs that allow code signing. Nothing is decrypted or run.

set -Eeuo pipefail
umask 077

die() { echo "Error: $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
. "${PKI_ROOT}/bin/define_openssl.sh"

INST="" ROOT="" PIN=""
while [ $# -gt 0 ]; do
    case $1 in
        --root)
            [ $# -ge 2 ] || die "--root needs a FILE"
            ROOT=$2; shift 2 ;;
        --root-sha256)
            [ $# -ge 2 ] || die "--root-sha256 needs a value"
            PIN=$(printf '%s' "$2" | sed 's/^.*=//' | tr -d ': ' | tr '[:upper:]' '[:lower:]')
            shift 2 ;;
        -h|--help)
            awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "$0"
            exit 0 ;;
        -*) die "unknown option '$1'" ;;
        *)  [ -z "${INST}" ] || die "give one INSTALLER"
            INST=$1; shift ;;
    esac
done
[ -f "${INST}" ] || die "usage: $(basename "$0") INSTALLER (--root FILE | --root-sha256 HEX)"
[ -n "${ROOT}" ] || [ -n "${PIN}" ] || die "give --root FILE or --root-sha256 HEX"

T=$(mktemp -d "${TMPDIR:-/tmp}/verify-installer.XXXXXX")
trap 'rm -rf "${T}"' EXIT

grep -q '^__SIGNATURE_BELOW__$' "${INST}" && grep -q '^__PAYLOAD_BELOW__$' "${INST}" \
    || die "${INST} has no signature block"
# signed content: the file without the signature lines
awk '/^__SIGNATURE_BELOW__$/ { print; skip = 1; next }
     /^__PAYLOAD_BELOW__$/ { skip = 0 }
     !skip { print }' "${INST}" > "${T}/signed"
awk '/^__SIGNATURE_BELOW__$/ { skip = 1; next }
     /^__PAYLOAD_BELOW__$/ { skip = 0 }
     skip' "${INST}" | "${OPENSSL}" base64 -d > "${T}/sig" 2>/dev/null || true
[ -s "${T}/sig" ] || die "no readable signature in ${INST}"

# certificates carried in the signature block, one file each
"${OPENSSL}" pkcs7 -inform DER -in "${T}/sig" -print_certs -out "${T}/block.pem" 2>/dev/null \
    || die "unreadable signature block"
awk -v p="${T}/blk" '
    /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s.%d.pem", p, n) }
    f { print > f }
    /-----END CERTIFICATE-----/ { close(f); f = "" }' "${T}/block.pem"

fp() {
    "${OPENSSL}" x509 -noout -fingerprint -sha256 -in "$1" \
        | sed -e 's/^.*=//' -e 's/://g' | tr '[:upper:]' '[:lower:]'
}

ANCHOR="${T}/anchor.pem"
if [ -n "${ROOT}" ]; then
    "${OPENSSL}" x509 -in "${ROOT}" -out "${ANCHOR}" 2>/dev/null \
        || "${OPENSSL}" x509 -inform DER -in "${ROOT}" -out "${ANCHOR}" 2>/dev/null \
        || die "cannot read ${ROOT}"
    if [ -n "${PIN}" ] && [ "$(fp "${ANCHOR}")" != "${PIN}" ]; then
        die "--root does not match --root-sha256"
    fi
else
    for f in "${T}"/blk.*.pem; do
        { [ -f "${f}" ] && [ "$(fp "${f}")" = "${PIN}" ]; } || continue
        cp "${f}" "${ANCHOR}"
    done
    [ -s "${ANCHOR}" ] || die "no certificate in the signature block has SHA-256 ${PIN}"
fi
"${OPENSSL}" verify -CAfile "${ANCHOR}" "${ANCHOR}" >/dev/null 2>&1 \
    || die "the root is not self-signed, or has expired"

out=$("${OPENSSL}" smime -verify -binary -inform DER -in "${T}/sig" \
          -content "${T}/signed" -CAfile "${ANCHOR}" -purpose any \
          -signer "${T}/signer.pem" -out /dev/null 2>&1) \
    || die "SIGNATURE CHECK FAILED: changed after signing, or not chained to the root. ${out}"

ext() { "${OPENSSL}" x509 -noout -ext "$1" -in "$2" 2>/dev/null || true; }
case "$(ext extendedKeyUsage "${T}/signer.pem")" in
    *"Code Signing"*) ;;
    *) die "the signer lacks the codeSigning extendedKeyUsage" ;;
esac
case "$(ext basicConstraints "${T}/signer.pem")" in
    *"CA:TRUE"*) die "the signer is a CA certificate" ;;
esac

# `-purpose any` ignores CA EKUs: the issuing CA must allow codeSigning
ok=0
if "${OPENSSL}" verify -CAfile "${ANCHOR}" "${T}/signer.pem" >/dev/null 2>&1; then
    ok=1
fi
for f in "${T}"/blk.*.pem; do
    [ -f "${f}" ] || continue
    "${OPENSSL}" verify -CAfile "${ANCHOR}" -untrusted "${f}" "${T}/signer.pem" \
        >/dev/null 2>&1 || continue
    case "$(ext extendedKeyUsage "${f}")" in
        *"Code Signing"*) ok=1 ;;
    esac
done
[ "${ok}" = 1 ] || die "the issuing CA of the signer does not allow codeSigning"

echo "Signature OK: $(basename "${INST}") signed by" \
     "$("${OPENSSL}" x509 -noout -subject -in "${T}/signer.pem" | sed 's/^subject= *//')"
echo "  root SHA-256 $(fp "${ANCHOR}")"

#!/usr/bin/env bash

# create_crl.sh
#
# Usage: create_crl.sh [--min-days-left DAYS] [--force] root|intermediate|intermediate_smime|privoxy
#
# Generates (or refreshes) the CRL for the named CA, at a stable
# filename suitable for publishing at the CRL Distribution Point
# endpoint. Reads the CA's existing index.txt and key, overwrites the CRL
# file in place. Safe to re-run at any time; intended to be invoked
# periodically (e.g. by a daemon/cron job).
#
# An existing CRL is left alone unless one of these holds:
#   - it is missing or unreadable,
#   - it expires in fewer than DAYS days (--min-days-left, else the
#     environment variable CRL_MIN_DAYS_LEFT, else 15),
#   - it is not signed by the CA's current certificate (new CA key),
#   - the set of revoked serials in index.txt differs from the CRL's.
# --force regenerates it regardless.

set -e
set -E
set -o pipefail
trap 'rc=$?; echo "Error: $(basename "$0") failed (exit ${rc}) at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

SHOW_CRL_TEXT=${SHOW_CRL_TEXT:-1}
MIN_DAYS_LEFT=${CRL_MIN_DAYS_LEFT:-15}
FORCE=0

POSITIONAL_ARGS_USAGE=${POSITIONAL_ARGS_USAGE:-root|intermediate|intermediate_smime|privoxy}
POSITIONAL_ARGS=()
HELP=0

while [[ $# -gt 0 ]]; do
    case $1 in
	-h|--help)
	    HELP=1
	    shift
	    ;;
	--min-days-left)
	    if [ $# -lt 2 ]; then
		echo "Option '$1' needs an argument: a number of days." >&2
		exit 1
	    fi
	    MIN_DAYS_LEFT=$2
	    shift; shift
	    ;;
	--min-days-left=*)
	    MIN_DAYS_LEFT=${1#*=}
	    shift
	    ;;
	--force)
	    FORCE=1
	    shift
	    ;;
	*)
	    POSITIONAL_ARGS+=("$1")
	    shift
	    ;;
    esac
done
set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

if [ "${HELP}" != "0" ]; then
    cat <<USAGE
Usage:

$(basename "$0") [-h|--help] [--min-days-left DAYS] [--force] ${POSITIONAL_ARGS_USAGE}

Regenerates the CRL only if it is missing, expires in fewer than DAYS days
(default 15; environment variable CRL_MIN_DAYS_LEFT), is not signed by the
CA's current certificate, or no longer matches the revocations in index.txt.
--force regenerates it regardless.
USAGE
    exit 0
fi

if ! [[ "${MIN_DAYS_LEFT}" =~ ^[0-9]+$ ]]; then
    echo "Error: --min-days-left / CRL_MIN_DAYS_LEFT must be a whole number of days, not '${MIN_DAYS_LEFT}'." >&2
    exit 1
fi

if [ "${#POSITIONAL_ARGS[@]}" -ne 1 ]; then
    echo "Usage: $(basename "$0") [--min-days-left DAYS] [--force] ${POSITIONAL_ARGS_USAGE}" >&2
    exit 1
fi
CANAME="${POSITIONAL_ARGS[0]}"

CERTDIR="${CANAME}"
case "${CANAME}" in
    root)
	CONFIG="${PKI_ROOT}/openssl.cnf"
	;;
    intermediate|intermediate_smime|privoxy)
	CONFIG="${PKI_ROOT}/${CERTDIR}/openssl_${CERTDIR}.cnf"
	;;
    *)
	echo "Unknown CA name '${CANAME}'; expected root, intermediate, intermediate_smime, or privoxy." >&2
	exit 1
	;;
esac

. "${PKI_ROOT}/bin/define_openssl.sh"
. "${PKI_ROOT}/bin/pki_common.sh"
. "${PKI_ROOT}/pki_identity.env"

: "${OPENSSL:?OPENSSL is not set by bin/define_openssl.sh}"

CACERT="${CERTDIR}/certs/${CERTDIR}.cert.pem"
CAKEY="${CERTDIR}/private/${CERTDIR}.key.pem"
if [ ! -f "${CAKEY}" ]; then
    echo "CA key '${CAKEY}' doesn't exist." >&2
    exit 1
fi
if [ ! -f "${CERTDIR}/index.txt" ]; then
    echo "Index file '${CERTDIR}/index.txt' doesn't exist; is '${CERTDIR}' an initialized CA?" >&2
    exit 1
fi

# crlnumber isn't created by pki_structure.sh, so seed it on first run
# the same way pki_structure.sh seeds serial.
if [ ! -f "${CERTDIR}/crlnumber" ]; then
    echo '01' > "${CERTDIR}/crlnumber"
fi
mkdir -p "${CERTDIR}/crl"

CRLOUT="${CERTDIR}/crl/${CERTDIR}.crl.pem"
# CRL DP fields reference this bare name (no .pem) - openssl ca -gencrl
# has no -outform, so PEM->DER conversion is a separate step.
CRLDER="${CERTDIR}/crl/${CERTDIR}.crl"

# crl_refresh_reason: print why the CRL must be regenerated, or nothing if
# the existing one is still good. Always succeeds.
crl_refresh_reason() {
    local next end now cacert in_index in_crl

    if [ ! -f "${CRLOUT}" ] || [ ! -f "${CRLDER}" ]; then
	echo "no CRL yet"
	return 0
    fi

    next=$("${OPENSSL}" crl -noout -nextupdate -in "${CRLOUT}" 2>/dev/null) || next=""
    end=$(pki_date_epoch "${next#nextUpdate=}" 2>/dev/null) || end=""
    if [ -z "${end}" ]; then
	echo "cannot read nextUpdate of ${CRLOUT}"
	return 0
    fi
    now=$(date +%s)
    if [ "${end}" -le "${now}" ]; then
	echo "CRL has expired"
	return 0
    fi
    if [ $((end - now)) -lt $((MIN_DAYS_LEFT * 86400)) ]; then
	echo "CRL expires in $(((end - now) / 86400)) day(s), fewer than ${MIN_DAYS_LEFT}"
	return 0
    fi

    # crl -verify exits 0 even on failure, so read what it says
    cacert="${CERTDIR}/certs/${CERTDIR}.cert.pem"
    if [ -f "${cacert}" ] \
	   && ! "${OPENSSL}" crl -verify -noout -CAfile "${cacert}" -in "${CRLOUT}" 2>&1 | grep -q '^verify OK'; then
	echo "CRL is not signed by the current ${CANAME} certificate"
	return 0
    fi

    # Revoked serials, leading zeros dropped, one per line, sorted
    in_index=$(awk -F'\t' '$1 == "R" { s = toupper($4); sub(/^0+/, "", s); print s }' "${CERTDIR}/index.txt" | sort)
    in_crl=$("${OPENSSL}" crl -noout -text -in "${CRLOUT}" \
		 | awk '/^ *Serial Number:/ { s = toupper($NF); sub(/^0+/, "", s); print s }' | sort)
    if [ "${in_index}" != "${in_crl}" ]; then
	echo "revocations in ${CERTDIR}/index.txt differ from the CRL"
	return 0
    fi

    return 0
}

if [ "${FORCE}" = "0" ]; then
    reason=$(crl_refresh_reason)
    if [ -z "${reason}" ]; then
	echo "${CRLOUT}: CRL is current (minimum ${MIN_DAYS_LEFT} day(s) left); not regenerating. Use --force to override." >&2
	exit 0
    fi
    echo "Regenerating the ${CANAME} CRL: ${reason}" >&2
fi

trap 'rm -f "${CRLOUT}.tmp" "${CRLDER}.tmp"' EXIT
"${OPENSSL}" ca -config "${CONFIG}" \
	-gencrl \
	-passin fd:3 3< <(pki_kc get --cert "${CACERT}") \
	-out "${CRLOUT}.tmp"

"${OPENSSL}" crl -in "${CRLOUT}.tmp" -outform DER -out "${CRLDER}.tmp"
# crl -verify exits 0 even on failure: read its verdict. Publish only a CRL the
# CA's current certificate verifies; the old files stay in place otherwise.
crl_check=$("${OPENSSL}" crl -verify -noout -CAfile "${CERTDIR}/certs/${CERTDIR}.cert.pem" -in "${CRLOUT}.tmp" 2>&1) || true
if ! grep -q '^verify OK' <<<"${crl_check}"; then
    echo "Error: the new ${CANAME} CRL does not verify against ${CERTDIR}/certs/${CERTDIR}.cert.pem; the previous CRL is kept." >&2
    exit 1
fi
mv -f "${CRLOUT}.tmp" "${CRLOUT}" && mv -f "${CRLDER}.tmp" "${CRLDER}"
if [ "${SHOW_CRL_TEXT}" != "0" ]; then
    "${OPENSSL}" crl -noout -text -in "${CRLOUT}"
fi

echo "Wrote ${CRLOUT} and ${CRLDER}"

#!/usr/bin/env bash

# create_crl.sh
#
# Usage: create_crl.sh root|intermediate|privoxy
#
# Generates (or refreshes) the CRL for the named CA, at a stable
# filename suitable for publishing at the CRL Distribution Point
# endpoint. Safe to re-run at any time - reads the CA's existing
# index.txt and key, overwrites the CRL file in place. Intended to
# be invoked periodically (e.g. by a daemon/cron job).

set -e
set -E
set -o pipefail
trap 'rc=$?; echo "Error: $(basename "$0") failed (exit ${rc}) at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SHOW_CRL_TEXT=${SHOW_CRL_TEXT:-1}

POSITIONAL_ARGS_USAGE=${POSITIONAL_ARGS_USAGE:-root|intermediate|privoxy}
POSITIONAL_ARGS=()
HELP=0

while [[ $# -gt 0 ]]; do
    case $1 in
	-h|--help)
	    HELP=1
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
    cat <<USEAGE
Useage:

$(basename "$0") [-h|--help] ${POSITIONAL_ARGS_USAGE}
USEAGE
    exit 0
fi

if [ "${#POSITIONAL_ARGS[@]}" -ne 1 ]; then
    echo "Usage: $(basename "$0") ${POSITIONAL_ARGS_USAGE}" >&2
    exit 1
fi
CANAME="${POSITIONAL_ARGS[0]}"

CERTDIR="${CANAME}"
case "${CANAME}" in
    root)
	CONFIG="${PKI_ROOT}/openssl.cnf"
	;;
    intermediate)
	CONFIG="${PKI_ROOT}/${CERTDIR}/openssl_${CERTDIR}.cnf"
	;;
    privoxy)
	CONFIG="${PKI_ROOT}/${CERTDIR}/openssl_${CERTDIR}.cnf"
	;;
    *)
	echo "Unknown CA name '${CANAME}'; expected root, intermediate, or privoxy." >&2
	exit 1
	;;
esac

cd "${PKI_ROOT}"

. ./identity.env

PASSPHRASE="${CERTDIR}/private/passphrase.txt"
if [ ! -f "${PASSPHRASE}" ]; then
    echo "Passphrase file '${PASSPHRASE}' doesn't exist." >&2
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

openssl ca -config "${CONFIG}" \
	-gencrl \
	-passin file:"${PASSPHRASE}" \
	-out "${CRLOUT}"

# CRL DP fields reference this bare name (no .pem) - openssl ca -gencrl
# has no -outform, so PEM->DER conversion is a separate step.
CRLDER="${CERTDIR}/crl/${CERTDIR}.crl"
openssl crl -in "${CRLOUT}" -outform DER -out "${CRLDER}.tmp" && mv -f "${CRLDER}.tmp" "${CRLDER}"
if [ "${SHOW_CRL_TEXT}" != "0" ]; then
    openssl crl -noout -text -in "${CRLOUT}"
fi

echo "Wrote ${CRLOUT} and ${CRLDER}"

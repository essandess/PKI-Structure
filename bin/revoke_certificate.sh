#!/usr/bin/env bash

# Usage: revoke_certificate.sh certfile root|intermediate|privoxy [crlReason]
#
# Revokes a certificate for the named CA and stated reason,
# and overwrites the CRL file.

set -e
set -E
set -o pipefail
trap 'rc=$?; echo "Error: $(basename "$0") failed (exit ${rc}) at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

POSITIONAL_ARGS_USAGE=${POSITIONAL_ARGS_USAGE:-certfile root|intermediate|privoxy [crlReason]}
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

if [ "${#POSITIONAL_ARGS[@]}" -lt 2 ]; then
    echo "Usage: $(basename "$0") ${POSITIONAL_ARGS_USAGE}" >&2
    exit 1
fi

CERTFILE="${POSITIONAL_ARGS[0]}"
CANAME="${POSITIONAL_ARGS[1]}"
CRLREASON="${POSITIONAL_ARGS[2]:-keyCompromise}"

ISSUERCADIR="${CANAME}"
ISSUERCANAME="${CANAME}"
case "${CANAME}" in
    root)
	CONFIG="${PKI_ROOT}/openssl.cnf"
	;;
    intermediate)
	CONFIG="${PKI_ROOT}/${ISSUERCADIR}/openssl_${ISSUERCADIR}.cnf"
	;;
    privoxy)
	CONFIG="${PKI_ROOT}/${ISSUERCADIR}/openssl_${ISSUERCADIR}.cnf"
	;;
    *)
	echo "Unknown CA name '${CANAME}'; expected root, intermediate, or privoxy." >&2
	exit 1
	;;
esac

cd "${PKI_ROOT}"

. ./identity.env

PASSPHRASE="${ISSUERCADIR}/private/passphrase.txt"
if [ ! -f "${PASSPHRASE}" ]; then
    echo "Passphrase file '${PASSPHRASE}' doesn't exist." >&2
    exit 1
fi
if [ ! -f "${ISSUERCADIR}/index.txt" ]; then
    echo "Index file '${ISSUERCADIR}/index.txt' doesn't exist; is '${ISSUERCADIR}' an initialized CA?" >&2
    exit 1
fi

# crlnumber isn't created by pki_structure.sh, so seed it on first run
# the same way pki_structure.sh seeds serial.
if [ ! -f "${ISSUERCADIR}/crlnumber" ]; then
    echo '01' > "${ISSUERCADIR}/crlnumber"
fi
mkdir -p "${ISSUERCADIR}/crl"

CRLOUT="${ISSUERCADIR}/crl/${ISSUERCANAME}.crl.pem"

openssl ca \
        -config "${CONFIG}" \
        -revoke "${CERTFILE}" \
        -crl_reason "${CRLREASON}" \
	-passin file:"${PASSPHRASE}"

bin/create_crl.sh "${CANAME}"

echo "Revoked ${CERTFILE} for CA ${CANAME}"

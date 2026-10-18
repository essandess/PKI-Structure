#!/usr/bin/env bash

# Usage: revoke_certificate.sh certfile root|intermediate|intermediate_smime|privoxy [crlReason]
#
# Revokes a certificate for the named CA and stated reason,
# overwrites the CRL file, and (every CA but privoxy) publishes the new CRL
# with bin/publish_crls.sh when a web directory is configured there.

set -e
set -E
set -o pipefail
trap 'rc=$?; echo "Error: $(basename "$0") failed (exit ${rc}) at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

POSITIONAL_ARGS_USAGE=${POSITIONAL_ARGS_USAGE:-certfile root|intermediate|intermediate_smime|privoxy [crlReason]}
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
    cat <<USAGE
Usage:

$(basename "$0") [-h|--help] ${POSITIONAL_ARGS_USAGE}
USAGE
    exit 0
fi

if [ "${#POSITIONAL_ARGS[@]}" -lt 2 ]; then
    echo "Usage: $(basename "$0") ${POSITIONAL_ARGS_USAGE}" >&2
    exit 1
fi

CERTFILE="${POSITIONAL_ARGS[0]}"
CANAME="${POSITIONAL_ARGS[1]}"
CRLREASON="${POSITIONAL_ARGS[2]:-unspecified}"

if [ ! -f "${CERTFILE}" ]; then
    echo "Certificate file '${CERTFILE}' doesn't exist." >&2
    exit 1
fi

VALID_CRL_REASONS="unspecified keyCompromise CACompromise affiliationChanged superseded cessationOfOperation certificateHold"

case " ${VALID_CRL_REASONS} " in
    *" ${CRLREASON} "*)
	;;
    *)
	echo "Unknown crlReason '${CRLREASON}'." >&2
	echo "Valid values: ${VALID_CRL_REASONS}" >&2
	echo "See man openssl-ca, -crl_reason." >&2
	exit 1
	;;
esac

echo "About to revoke:"
echo "  Certificate: ${CERTFILE}"
echo "  CA:          ${CANAME}"
echo "  Reason:      ${CRLREASON}"
read -p "Proceed? Type 'yes' to confirm: " -r
echo
if [ "${REPLY}" != "yes" ]; then
    echo "Aborted." >&2
    exit 1
fi

ISSUERCANAME="${CANAME}"
case "${CANAME}" in
    root)
	CONFIG="${PKI_ROOT}/openssl.cnf"
	;;
    intermediate|intermediate_smime|privoxy)
	CONFIG="${PKI_ROOT}/${ISSUERCANAME}/openssl_${ISSUERCANAME}.cnf"
	;;
    *)
	echo "Unknown CA name '${CANAME}'; expected root, intermediate, intermediate_smime, or privoxy." >&2
	exit 1
	;;
esac

. "${PKI_ROOT}/pki_identity.env"
. "${PKI_ROOT}/bin/define_openssl.sh"
. "${PKI_ROOT}/bin/pki_common.sh"

: "${OPENSSL:?OPENSSL is not set by bin/define_openssl.sh}"

CACERT="${ISSUERCANAME}/certs/${ISSUERCANAME}.cert.pem"
CAKEY="${ISSUERCANAME}/private/${ISSUERCANAME}.key.pem"
if [ ! -f "${CAKEY}" ]; then
    echo "CA key '${CAKEY}' doesn't exist." >&2
    exit 1
fi
if [ ! -f "${ISSUERCANAME}/index.txt" ]; then
    echo "Index file '${ISSUERCANAME}/index.txt' doesn't exist; is '${ISSUERCANAME}' an initialized CA?" >&2
    exit 1
fi


"${OPENSSL}" ca \
        -config "${CONFIG}" \
        -revoke "${CERTFILE}" \
        -crl_reason "${CRLREASON}" \
	-passin fd:3 3< <(pki_kc get --cert "${CACERT}")

bin/create_crl.sh "${CANAME}"

# Publish the new CRL now: clients only learn of the revocation from the
# published copy. (The privoxy CRL is not published anywhere.)
if [ "${CANAME}" != "privoxy" ]; then
    bin/publish_crls.sh --if-configured --no-regenerate "${CANAME}"
fi

echo "Revoked ${CERTFILE} for CA ${CANAME}"

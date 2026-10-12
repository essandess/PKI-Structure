#!/usr/bin/env bash

# create_server.sh

# https://support.apple.com/en-us/HT210176
DAYS=825

# Usage: create_server.sh [--server-fqdn SERVER_FQDN] [-a EC|RSA] [-c|--clean|-vc|--veryclean] [-h|--help]
#
# SERVER_FQDN comes from ./pki_identity.env; --server-fqdn overrides it for this
# run. It must equal DOMAIN_NAME or be under it: the intermediate's
# nameConstraints permit nothing else.

# get SERVER_FQDN from ./pki_identity.env
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

. "${PKI_ROOT}/pki_identity.env"
. "${SCRIPT_DIR}/pki_common.sh"

# --server-fqdn is ours; everything else is for pki_structure.sh
SERVER_FQDN_FLAG=""
ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
	--server-fqdn)
	    if [ $# -lt 2 ] || [ -z "$2" ]; then
		echo "Option '$1' needs an argument: a host name." >&2
		exit 1
	    fi
	    SERVER_FQDN_FLAG=$2
	    shift 2
	    ;;
	--server-fqdn=*)
	    SERVER_FQDN_FLAG=${1#*=}
	    if [ -z "${SERVER_FQDN_FLAG}" ]; then
		echo "Option '--server-fqdn' needs an argument: a host name." >&2
		exit 1
	    fi
	    shift
	    ;;
	*)
	    ARGS+=("$1")
	    shift
	    ;;
    esac
done
set -- "${ARGS[@]}"

POSITIONAL_ARGS_USAGE="${POSITIONAL_ARGS_USAGE:-[--server-fqdn SERVER_FQDN]}"

if [ -n "${SERVER_FQDN_FLAG}" ]; then
    SERVER_FQDN=$(printf '%s' "${SERVER_FQDN_FLAG}" | tr '[:upper:]' '[:lower:]')
fi

# The intermediate's nameConstraints permit DNS names equal to or under
# DOMAIN_NAME only; refuse anything else before a key or file is created.
# (Not for -h or the clean options, which create nothing.)
CHECK_FQDN=1
for arg in "$@"; do
    case "${arg}" in
	-h|--help|-c|--clean|-vc|--veryclean) CHECK_FQDN=0 ;;
    esac
done
if [ "${CHECK_FQDN}" = "1" ]; then
    FQDN_LC=$(printf '%s' "${SERVER_FQDN:-}" | tr '[:upper:]' '[:lower:]')
    DOMAIN_LC=$(printf '%s' "${DOMAIN_NAME:-}" | tr '[:upper:]' '[:lower:]')
    if [ -z "${DOMAIN_LC}" ]; then
	echo "Error: DOMAIN_NAME is not set in pki_identity.env; it defines the names the intermediate CA may issue for." >&2
	exit 1
    fi
    if [ -z "${FQDN_LC}" ]; then
	echo "Error: no server name: set SERVER_FQDN in pki_identity.env or pass --server-fqdn." >&2
	exit 1
    fi
    if [ "${#FQDN_LC}" -gt 253 ] \
	   || ! [[ "${FQDN_LC}" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$ ]]; then
	echo "Error: '${SERVER_FQDN}' is not a plain host name (letters, digits, '-' and '.'; no wildcards)." >&2
	exit 1
    fi
    if [ "${FQDN_LC}" != "${DOMAIN_LC}" ] && [[ "${FQDN_LC}" != *".${DOMAIN_LC}" ]]; then
	echo "Error: '${SERVER_FQDN}' is not within DOMAIN_NAME '${DOMAIN_NAME}'." >&2
	echo "The intermediate CA's nameConstraints only permit DNS names equal to or under" >&2
	echo "'${DOMAIN_NAME}', so clients would reject a certificate for '${SERVER_FQDN}'." >&2
	echo "Use a name such as 'host.${DOMAIN_NAME}', or change DOMAIN_NAME in pki_identity.env" >&2
	echo "and reissue the intermediate (bin/create_intermediate.sh --new-key)." >&2
	exit 1
    fi
fi
SERVER_FQDN_CHOSEN="${SERVER_FQDN:-}"
export SERVER_FQDN

CATRUE=${CATRUE:-0}
CERTDIR=${CERTDIR:-server}
CERTNAME=${CERTNAME:-${SERVER_FQDN}}
ISSUERCADIR=${ISSUERCADIR:-intermediate}
ISSUERCANAME=${ISSUERCANAME:-intermediate}
EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-256}
RSA_KEYGEN_BITS=${RSA_KEYGEN_BITS:-2048}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/pki_structure.sh"
# pki_structure.sh sources pki_identity.env again; keep the name chosen above
SERVER_FQDN="${SERVER_FQDN_CHOSEN}"
export SERVER_FQDN

# Never longer than the issuer's remaining life
DAYS=$(pki_cap_days "${ISSUERCADIR}/certs/${ISSUERCANAME}.cert.pem" "${DAYS}")

# Certificate encrypted key
case ${ALGORITHM} in
    EC)
	"${OPENSSL}" genpkey -out "${CERTDIR}"/private/"${CERTNAME}".key.pem \
		-algorithm EC -pkeyopt ec_paramgen_curve:"${EC_PARAMGEN_CURVE}" -aes256 \
		-pass file:"${CERTDIR}"/private/passphrase.txt
	;;
    RSA)
	"${OPENSSL}" genpkey -out "${CERTDIR}"/private/"${CERTNAME}".key.pem \
		-algorithm RSA -pkeyopt rsa_keygen_bits:"${RSA_KEYGEN_BITS}" -aes256 \
		-pass file:"${CERTDIR}"/private/passphrase.txt
	;;
    *)
	echo "Unknown algorithm '${ALGORITHM}'"
	exit 1
esac

# Server CSR
"${OPENSSL}" req -config "${CERTDIR}"/openssl_"${CERTDIR}".cnf \
	-new -"${HASH_DIGEST}" \
	-key "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-passin file:"${CERTDIR}"/private/passphrase.txt \
	-out "${CERTDIR}"/certs/"${CERTNAME}".csr.pem -batch

# Server certificate
if "${OPENSSL}" ca -config "${CERTDIR}"/openssl_"${CERTDIR}".cnf \
	-extensions "${CERTDIR}" \
	-days ${DAYS} -notext -md "${HASH_DIGEST}" \
	-in "${CERTDIR}"/certs/"${CERTNAME}".csr.pem \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-passin file:"${ISSUERCADIR}"/private/passphrase.txt \
	-batch
then
    NEW_SERIAL=$("${OPENSSL}" x509 -in "${CERTDIR}/certs/${CERTNAME}.cert.pem" -noout -serial | sed 's|^serial=||')
    pki_revoke_matching_cn "${ISSUERCADIR}" "${ISSUERCADIR}/openssl_${ISSUERCADIR}.cnf" "${CERTNAME}" "${NEW_SERIAL}" intermediate
    rm "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
else
    rm "${CERTDIR}"/private/"${CERTNAME}".key.pem
    rm "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
    exit 1
fi

pki_finish_cert "${CERTDIR}" "${CERTNAME}" "${ISSUERCADIR}" "${ISSUERCANAME}"

# decrypt private key
case ${ALGORITHM} in
    EC)
        "${OPENSSL}" ec -in "${CERTDIR}"/private/"${CERTNAME}".key.pem -out "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted -passin "file:${CERTDIR}"/private/passphrase.txt
        chmod 0600 "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted        ;;
    RSA)
        "${OPENSSL}" rsa -in "${CERTDIR}"/private/"${CERTNAME}".key.pem -out "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted -passin "file:${CERTDIR}"/private/passphrase.txt
        chmod 0600 "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted        ;;
    *)
	echo "Unknown algorithm '${ALGORITHM}'"
	exit 1
esac

# rename certificate
pki_sha1_files mv "${CERTDIR}" "${CERTNAME}" "${SERVER_FQDN}" \
    "private/key.pem private/key.pem.decrypted private/p12 certs/cer certs/cert.pem certs/chain.pem"

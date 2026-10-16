#!/usr/bin/env bash

# create_adblock2privoxy.sh
#
# Usage: create_adblock2privoxy.sh [--decrypt-key] [-a EC|RSA] [-c|--clean] [-h|--help]
#
# --decrypt-key also writes private/<name>.<sha1>.key.pem.decrypted (0600): the UNENCRYPTED
# key, for nginx, which cannot ask for a passphrase. Off by default.

SERVERFQDN=${SERVERFQDN:-adblock2privoxy-nginx}

# https://support.apple.com/en-us/HT210176
DAYS=825

CATRUE=${CATRUE:-0}
CERTDIR=${CERTDIR:-privoxy/adblock2privoxy}
CERTNAME=${CERTNAME:-${SERVERFQDN}}
ISSUERCADIR=${ISSUERCADIR:-privoxy}
ISSUERCANAME=${ISSUERCANAME:-privoxy}

ALGORITHM=${ALGORITHM:-EC}
EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-256}
HASH_DIGEST=${HASH_DIGEST:-sha256}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

. "${SCRIPT_DIR}/pki_common.sh"

# --decrypt-key is ours too: it also writes the UNENCRYPTED key (private/*.key.pem.decrypted)
DECRYPT_KEY=0
_args=()
for _a in "$@"; do
    if [ "${_a}" = "--decrypt-key" ]; then DECRYPT_KEY=1; else _args+=("${_a}"); fi
done
set -- ${_args[@]+"${_args[@]}"}
DECRYPT_FILES=""
if [ "${DECRYPT_KEY}" = "1" ]; then DECRYPT_FILES=" private/key.pem.decrypted"; fi
POSITIONAL_ARGS_USAGE="[--decrypt-key]"
. "${SCRIPT_DIR}/pki_structure.sh"

# Never longer than the issuer's remaining life
DAYS=$(pki_cap_days "${ISSUERCADIR}/certs/${ISSUERCANAME}.cert.pem" "${DAYS}")

# Certificate encrypted key
KEY_ID=$(pki_kc genkey --alg "${ALGORITHM}" --curve "${EC_PARAMGEN_CURVE}" --bits "${RSA_KEYGEN_BITS}" \
	--out "${CERTDIR}/private/${CERTNAME}.key.pem" --label "${CERTNAME}")
if [ "${DECRYPT_KEY}" = "1" ]; then
case ${ALGORITHM} in
    EC)
	"${OPENSSL}" ec -in "${CERTDIR}"/private/"${CERTNAME}".key.pem \
		-passin fd:3 -out "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted \
		3< <(pki_kc get --id "${KEY_ID}")
	;;
    RSA)
	"${OPENSSL}" rsa -in "${CERTDIR}"/private/"${CERTNAME}".key.pem \
		-passin fd:3 -out "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted \
		3< <(pki_kc get --id "${KEY_ID}")
	;;
esac
chmod 0600 "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted
fi

# Server CSR
"${OPENSSL}" req -config "${CERTDIR}"/openssl_"${CERTDIR##*/}".cnf \
	-new -"${HASH_DIGEST}" \
	-key "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-passin fd:3 3< <(pki_kc get --id "${KEY_ID}") \
	-out "${CERTDIR}"/certs/"${CERTNAME}".csr.pem -batch

# Server certificate
if "${OPENSSL}" ca -config "${CERTDIR}"/openssl_"${CERTDIR##*/}".cnf \
	-extensions "${CERTDIR##*/}" \
	-keyfile "${ISSUERCADIR}"/private/"${ISSUERCANAME}".key.pem \
	-cert "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".cert.pem \
	-days ${DAYS} -notext -md "${HASH_DIGEST}" \
	-in "${CERTDIR}"/certs/"${CERTNAME}".csr.pem \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-passin fd:3 3< <(pki_kc get --cert "${ISSUERCADIR}/certs/${ISSUERCANAME}.cert.pem") \
	-batch
then
    if ! pki_assert_leaf_scope "${CERTDIR}/certs/${CERTNAME}.cert.pem" adblock2privoxy; then
        pki_revoke_unscoped "${CERTDIR}/openssl_${CERTDIR##*/}.cnf" "${ISSUERCADIR}" "${CERTDIR}/certs/${CERTNAME}.cert.pem" privoxy
        rm -f "${CERTDIR}"/private/"${CERTNAME}".key.pem "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted "${CERTDIR}"/certs/"${CERTNAME}".csr.pem "${CERTDIR}"/certs/"${CERTNAME}".cert.pem
        exit 1
    fi
    NEW_SERIAL=$("${OPENSSL}" x509 -in "${CERTDIR}/certs/${CERTNAME}.cert.pem" -noout -serial | sed 's|^serial=||')
    pki_revoke_matching_cn "${ISSUERCADIR}" "${CERTDIR}/openssl_${CERTDIR##*/}.cnf" "${CERTNAME}" "${NEW_SERIAL}" privoxy
    rm "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
else
    rm "${CERTDIR}"/private/"${CERTNAME}".key.pem
    rm -f "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted
    rm "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
    exit 1
fi

pki_finish_cert "${CERTDIR}" "${CERTNAME}" "${ISSUERCADIR}" "${ISSUERCANAME}"

# rename certificate
pki_sha1_files mv "${CERTDIR}" "${CERTNAME}" "${SERVERFQDN}" \
    "private/key.pem private/p12 certs/cer certs/cert.pem certs/chain.pem${DECRYPT_FILES}"

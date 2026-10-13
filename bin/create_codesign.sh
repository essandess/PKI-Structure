#!/usr/bin/env bash

# create_codesign.sh

# https://support.apple.com/en-us/HT210176
# Technically longer acceptable for noncommercial S/MIME,
# but not not recommended or guaranteed to be accepted
DAYS=825

CATRUE=${CATRUE:-0}
CERTDIR=${CERTDIR:-codesign}
CERTNAME=${CERTNAME:-${CERTDIR}}
ISSUERCADIR=${ISSUERCADIR:-intermediate}
ISSUERCANAME=${ISSUERCANAME:-intermediate}

ALGORITHM=${ALGORITHM:-EC}
EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-256}
RSA_KEYGEN_BITS=${RSA_KEYGEN_BITS:-2048}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

. "${SCRIPT_DIR}/pki_common.sh"
. "${SCRIPT_DIR}/pki_structure.sh"

# Never longer than the issuer's remaining life
DAYS=$(pki_cap_days "${ISSUERCADIR}/certs/${ISSUERCANAME}.cert.pem" "${DAYS}")

# Certificate encrypted key
KEY_ID=$(pki_kc genkey --alg "${ALGORITHM}" --curve "${EC_PARAMGEN_CURVE}" --bits "${RSA_KEYGEN_BITS}" \
	--out "${CERTDIR}/private/${CERTNAME}.key.pem" --label "${CERTNAME}")

# Server CSR
"${OPENSSL}" req -config "${CERTDIR}"/openssl_"${CERTDIR}".cnf \
	-new -"${HASH_DIGEST}" \
	-key "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-passin fd:3 3< <(pki_kc get --id "${KEY_ID}") \
	-out "${CERTDIR}"/certs/"${CERTNAME}".csr.pem -batch

# Server certificate
if "${OPENSSL}" ca -config "${CERTDIR}"/openssl_"${CERTDIR}".cnf \
	-extensions "${CERTDIR}" \
	-days ${DAYS} -notext -md "${HASH_DIGEST}" \
	-in "${CERTDIR}"/certs/"${CERTNAME}".csr.pem \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-passin fd:3 3< <(pki_kc get --cert "${ISSUERCADIR}/certs/${ISSUERCANAME}.cert.pem") \
	-batch
then
    if ! pki_assert_leaf_scope "${CERTDIR}/certs/${CERTNAME}.cert.pem" codesign; then
        pki_revoke_unscoped "${ISSUERCADIR}/openssl_${ISSUERCADIR}.cnf" "${ISSUERCADIR}" "${CERTDIR}/certs/${CERTNAME}.cert.pem" intermediate
        rm -f "${CERTDIR}"/private/"${CERTNAME}".key.pem "${CERTDIR}"/certs/"${CERTNAME}".csr.pem "${CERTDIR}"/certs/"${CERTNAME}".cert.pem
        exit 1
    fi
    NEW_SERIAL=$("${OPENSSL}" x509 -in "${CERTDIR}/certs/${CERTNAME}.cert.pem" -noout -serial | sed 's|^serial=||')
    pki_revoke_matching_cn "${ISSUERCADIR}" "${ISSUERCADIR}/openssl_${ISSUERCADIR}.cnf" "${ORG_NAME}" "${NEW_SERIAL}" intermediate
    rm "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
else
    rm "${CERTDIR}"/private/"${CERTNAME}".key.pem
    rm "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
    exit 1
fi

pki_finish_cert "${CERTDIR}" "${CERTNAME}" "${ISSUERCADIR}" "${ISSUERCANAME}"

# rename certificate
pki_sha1_files mv "${CERTDIR}" "${CERTNAME}" "${CERTNAME}" \
    "private/key.pem private/p12 certs/cer certs/cert.pem certs/chain.pem"

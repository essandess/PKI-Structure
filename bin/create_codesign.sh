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

# Certificate: key, CSR, issuance and scope check
pki_issue_leaf "${CERTNAME}" "${CERTDIR}/openssl_${CERTDIR}.cnf" "${CERTDIR}" codesign "${CERTNAME}"
pki_revoke_matching_cn "${ISSUERCADIR}" "${ORG_NAME}" "${NEW_SERIAL}"

pki_finish_cert "${CERTDIR}" "${CERTNAME}" "${ISSUERCADIR}" "${ISSUERCANAME}"

# rename certificate
pki_sha1_files mv "${CERTDIR}" "${CERTNAME}" "${CERTNAME}" \
    "private/key.pem private/p12 certs/cer certs/cert.pem certs/chain.pem"

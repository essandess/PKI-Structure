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

# Certificate: key, CSR, issuance and scope check
pki_issue_leaf "${CERTNAME}" "${CERTDIR}/openssl_${CERTDIR##*/}.cnf" "${CERTDIR##*/}" \
    adblock2privoxy "${CERTNAME}" \
    -keyfile "${ISSUERCADIR}/private/${ISSUERCANAME}.key.pem" \
    -cert "${ISSUERCADIR}/certs/${ISSUERCANAME}.cert.pem"
pki_revoke_matching_cn "${ISSUERCADIR}" "${CERTNAME}" "${NEW_SERIAL}"
if [ "${DECRYPT_KEY}" = "1" ]; then
    pki_decrypt_key "${CERTNAME}"
fi

pki_finish_cert "${CERTDIR}" "${CERTNAME}" "${ISSUERCADIR}" "${ISSUERCANAME}"

# rename certificate
pki_sha1_files mv "${CERTDIR}" "${CERTNAME}" "${SERVERFQDN}" \
    "private/key.pem private/p12 certs/cer certs/cert.pem certs/chain.pem${DECRYPT_FILES}"

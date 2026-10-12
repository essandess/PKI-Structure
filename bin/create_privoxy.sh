#!/usr/bin/env bash

# create_privoxy.sh
#
# Usage: create_privoxy.sh [-a EC|RSA] [--new-key] [-c|--clean|-vc|--veryclean] [-h|--help]
#
# Creates the privoxy CA (self-signed). If one already exists, a new
# certificate is issued only when the existing one expires within
# PKI_RENEW_WINDOW_DAYS (default 30) or has expired; earlier than that is an
# error. The old files are archived as privoxy.${CERTSHA1}.* and the new
# certificate is self-signed with the SAME key and subject, so certificates
# it issued (adblock2privoxy-nginx, ...) still chain to it. --new-key
# generates a new key instead; then those must be reissued.
#
# After a renewal, redeploy the certificate where privoxy uses it (see
# privoxy/README.md) and trust the new certificate on the devices that use
# the proxy.

# simply replicate the relative short expiration of a private server cert
# because the server cert must be reissued anyway and longer Root CA lifetime
# doesn't offer any real advantage
# https://support.apple.com/en-us/HT210176
DAYS=825

CATRUE=${CATRUE:-1}
CERTDIR=${CERTDIR:-privoxy}
CERTNAME=${CERTNAME:-privoxy}
ISSUERCADIR=${ISSUERCADIR:-privoxy}
ISSUERCANAME=${ISSUERCANAME:-privoxy}
EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-256}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

. "${SCRIPT_DIR}/pki_common.sh"
. "${PKI_ROOT}/bin/define_openssl.sh"
PRIVOXY_FILES="private/key.pem private/p12 certs/cert.pem certs/chain.pem certs/cer"

# --new-key is ours; everything else is for pki_structure.sh
NEW_KEY=0
ARGS=()
for arg in "$@"; do
    case "${arg}" in
	--new-key) NEW_KEY=1 ;;
	*) ARGS+=("${arg}") ;;
    esac
done
set -- "${ARGS[@]}"
POSITIONAL_ARGS_USAGE="[--new-key]"

# Archive only for a real create run (see create_root.sh).
ARCHIVE=1
for arg in "$@"; do
    case "${arg}" in
	-h|--help|-c|--clean|-vc|--veryclean) ARCHIVE=0 ;;
    esac
done

if [ "${ARCHIVE}" = "1" ] \
       && [ -n "${CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY}" ] \
       && [ "${CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY}" != "0" ]; then
    pki_ca_prepare "${CERTDIR}" "${CERTNAME}" "${PRIVOXY_FILES}" "${NEW_KEY}" 1
fi

. "${SCRIPT_DIR}/pki_structure.sh"

# CA encrypted key
if [ "${PKI_RENEW:-0}" = "1" ]; then
    # the archive step moved the key aside; put the same key back
    pki_ca_restore_key "${CERTDIR}" "${CERTNAME}"
    echo "Renewing ${CERTNAME} with its existing key." >&2
else
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
fi

# CA certificate
"${OPENSSL}" req -config "${CERTDIR}"/openssl_"${CERTDIR}".cnf \
	-extensions "${CERTDIR}_ca" \
	-new -x509 -days "${DAYS}" -"${HASH_DIGEST}" \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-key "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-passin file:"${CERTDIR}"/private/passphrase.txt \
        -batch
REISSUED=1

# verify, .cer and .p12 (self-signed: no chain file)
pki_finish_cert "${CERTDIR}" "${CERTNAME}" "${CERTDIR}" "${CERTNAME}"

# cert text
show_cert_text "${CERTDIR}"/certs/"${CERTNAME}".cert.pem

if [ -n "${PKI_ARCHIVED_SHA1}" ]; then
    echo "The previous ${CERTNAME} CA is archived as ${CERTNAME}.${PKI_ARCHIVED_SHA1}.*; it was not revoked." >&2
    echo "Redeploy the new certificate where privoxy uses it (privoxy/README.md) and trust it on the devices that use the proxy." >&2
    if [ "${PKI_RENEW}" != "1" ]; then
	echo "This CA has a NEW KEY: reissue the certificates it signed (bin/create_adblock2privoxy.sh)." >&2
    fi
fi

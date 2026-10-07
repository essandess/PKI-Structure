#!/usr/bin/env bash

# create_root.sh
#
# Usage: create_root.sh [-a EC|RSA] [--new-key] [-c|--clean|-vc|--veryclean] [-h|--help]
#
# Creates the root CA. If a root certificate already exists, a new one is
# issued only when the existing one expires within PKI_RENEW_WINDOW_DAYS
# (default 30) or has expired; earlier than that is an error. The old files
# are archived as root.${CERTSHA1}.*, and the new certificate is self-signed
# with the SAME key and subject, so everything already issued under the
# root still chains to it. --new-key generates a new key instead; then
# everything the old key signed (the intermediate, ...) must be reissued.
# The CA database (index.txt, serial, crlnumber) is kept.
#
# A renewed root has a new fingerprint: install and trust the new
# certificate on every device before the old one expires.

CATRUE=${CATRUE:-1}
CERTDIR=${CERTDIR:-root}
CERTNAME=${CERTNAME:-root}

# 20 years (plus leap days)
DAYS=7305

ALGORITHM=${ALGORITHM:-EC}
EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-384}
RSA_KEYGEN_BITS=${RSA_KEYGEN_BITS:-3072}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

. "${SCRIPT_DIR}/pki_common.sh"
. "${PKI_ROOT}/bin/define_openssl.sh"
ROOT_FILES="private/key.pem private/p12 certs/cert.pem certs/chain.pem certs/cer"

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

# Archive only for a real create run: not for --help or --clean, and not
# without the CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY precaution. This must run
# BEFORE pki_structure.sh is sourced: its own "CA file already exists" check
# would otherwise abort first.
ARCHIVE=1
for arg in "$@"; do
    case "${arg}" in
	-h|--help|-c|--clean|-vc|--veryclean) ARCHIVE=0 ;;
    esac
done

if [ "${ARCHIVE}" = "1" ] \
       && [ -n "${CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY}" ] \
       && [ "${CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY}" != "0" ]; then
    pki_ca_prepare "${CERTDIR}" "${CERTNAME}" "${ROOT_FILES}" "${NEW_KEY}" 1
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
"${OPENSSL}" req -config openssl.cnf \
	-new -x509 -days "${DAYS}" -"${HASH_DIGEST}" \
	-extensions v3_ca \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-key "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-passin file:"${CERTDIR}"/private/passphrase.txt -batch
REISSUED=1

# CA certificate openssl self-verification
"${OPENSSL}" verify -CAfile "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	"${CERTDIR}"/certs/"${CERTNAME}".cert.pem

# cert text
show_cert_text "${CERTDIR}"/certs/"${CERTNAME}".cert.pem

# Convert to .cer and .p12 for storage
"${OPENSSL}" x509 -outform der -in "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cer

# N.b. passphrase.txt holds two independent secrets: line 1 (-passin)
# unlocks the private key, line 2 (-passout) is the .p12 export password.
# man openssl-passphrase-options
"${OPENSSL}" pkcs12 -legacy -export -out "${CERTDIR}"/private/"${CERTNAME}".p12 \
	-inkey "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-in "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-passin file:"${CERTDIR}"/private/passphrase.txt \
	-passout file:"${CERTDIR}"/private/passphrase.txt
# verify .p12 passphrase
"${OPENSSL}" pkcs12 -legacy -noout -in "${CERTDIR}"/private/"${CERTNAME}".p12 \
	-passin "pass:$(sed -n 2p "${CERTDIR}"/private/passphrase.txt)"

# Generate the CA's CRL as soon as the CA exists, so the
# crlDistributionPoints URL in every cert it signs resolves immediately.
"${PKI_ROOT}"/bin/create_crl.sh root

if [ -n "${PKI_ARCHIVED_SHA1}" ]; then
    echo "The previous root is archived as ${CERTNAME}.${PKI_ARCHIVED_SHA1}.*; it was not revoked." >&2
    echo "The new root certificate has a new fingerprint: install and trust it on every device" >&2
    echo "(bin/create_credentials.sh --ca-only, the MDM trust profile) before the old one expires." >&2
    if [ "${PKI_RENEW}" != "1" ]; then
	echo "This root has a NEW KEY: reissue the intermediate and everything below it." >&2
    fi
fi

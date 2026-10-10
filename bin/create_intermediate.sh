#!/usr/bin/env bash

# create_intermediate.sh
#
# Usage: create_intermediate.sh [-a EC|RSA] [--new-key] [-c|--clean|-vc|--veryclean] [-h|--help]
#
# Creates the intermediate CA, or renews it. If an intermediate already
# exists, the user is asked to confirm, the old files are archived as
# intermediate.${CERTSHA1}.{key,cert,chain}.pem, .cer and .p12, and a new
# certificate is issued in its place:
#
#   default      with the SAME key and subject (renewal). Everything already
#                issued under the intermediate stays valid: it verifies
#                against the old or the new certificate.
#   --new-key    with a NEW key. Nothing issued by the old key chains to
#                the new certificate; reissue the server, code signing and
#                S/MIME certificates (and the old certificate stays valid
#                for what it signed until it expires).
#
# The previous intermediate is NOT revoked: revoking it would invalidate
# everything it signed. If its key is compromised, revoke it yourself:
#   bin/revoke_certificate.sh intermediate/certs/intermediate.<sha1>.cert.pem root CACompromise

CATRUE=${CATRUE:-1}
CERTDIR=${CERTDIR:-intermediate}
CERTNAME=${CERTNAME:-intermediate}
ISSUERCADIR=${ISSUERCADIR:-root}
ISSUERCANAME=${ISSUERCANAME:-root}

# 10 years (plus leap days, half of root); shortened if the root ends sooner
DAYS=3653

ALGORITHM=${ALGORITHM:-EC}
EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-384}
RSA_KEYGEN_BITS=${RSA_KEYGEN_BITS:-3072}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

. "${SCRIPT_DIR}/pki_common.sh"
# The archive step below needs OPENSSL (cert_sha1) before pki_structure.sh runs.
. "${PKI_ROOT}/bin/define_openssl.sh"
INTERMEDIATE_FILES="private/key.pem private/p12 certs/cert.pem certs/chain.pem certs/cer"

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

# Archive only for a real create run: not for --help or --clean, not without
# the CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY precaution, and not when the
# issuer CA is missing (pki_structure.sh reports those cases itself).
# This must run BEFORE pki_structure.sh is sourced: its own "CA file
# already exists" check would otherwise abort first.
ARCHIVE=1
for arg in "$@"; do
    case "${arg}" in
	-h|--help|-c|--clean|-vc|--veryclean) ARCHIVE=0 ;;
    esac
done

if [ "${ARCHIVE}" = "1" ] \
       && [ -n "${CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY}" ] \
       && [ "${CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY}" != "0" ] \
       && [ -f "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".cert.pem ]; then
    # renewal is allowed at any time (WINDOW_ONLY=0), after a confirmation
    pki_ca_prepare "${CERTDIR}" "${CERTNAME}" "${INTERMEDIATE_FILES}" "${NEW_KEY}" 0
fi

. "${SCRIPT_DIR}/pki_structure.sh"

# Never longer than the root's remaining life
DAYS=$(pki_cap_days "${ISSUERCADIR}/certs/${ISSUERCANAME}.cert.pem" "${DAYS}")

# Intermediate encrypted key
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

# Intermediate CA CSR
"${OPENSSL}" req -config "${CERTDIR}"/openssl_"${CERTDIR}".cnf \
	-new -"${HASH_DIGEST}" \
	-key "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-passin file:"${CERTDIR}"/private/passphrase.txt \
	-out "${CERTDIR}"/certs/"${CERTNAME}".csr.pem -batch

# Intermediate CA certificate
if "${OPENSSL}" ca -config openssl.cnf \
	-extfile "${CERTDIR}"/openssl_"${CERTDIR}".cnf \
	-extensions "${CERTDIR}_ca" \
	-days ${DAYS} -notext -md "${HASH_DIGEST}" \
	-in "${CERTDIR}"/certs/"${CERTNAME}".csr.pem \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-passin file:"${ISSUERCADIR}"/private/passphrase.txt -batch
then
    REISSUED=1
    rm "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
else
    # a renewed key is not ours to delete; the EXIT trap restores the archive
    if [ "${PKI_RENEW:-0}" != "1" ]; then
	rm "${CERTDIR}"/private/"${CERTNAME}".key.pem
    fi
    rm "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
    exit 1
fi

# Intermediate CA chain
if [ -f "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem ]; then
    cat "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	"${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem \
	> "${CERTDIR}"/certs/"${CERTNAME}".chain.pem
else
    cat "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	"${ISSUERCADIR}"/certs/"${ISSUERCANAME}".cert.pem \
	> "${CERTDIR}"/certs/"${CERTNAME}".chain.pem
fi

# Intermediate CA chain openssl verification
if [ -f "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem ]; then
    "${OPENSSL}" verify -CAfile "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem \
	"${CERTDIR}"/certs/"${CERTNAME}".chain.pem
else
    "${OPENSSL}" verify -CAfile "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".cert.pem \
	"${CERTDIR}"/certs/"${CERTNAME}".chain.pem
fi

# CA certificate openssl self-verification
if [ -f "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem ]; then
    "${OPENSSL}" verify -CAfile "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem \
	"${CERTDIR}"/certs/"${CERTNAME}".cert.pem
else
    "${OPENSSL}" verify -CAfile "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".cert.pem \
	"${CERTDIR}"/certs/"${CERTNAME}".cert.pem
fi

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

# Copy the new certificate to SHA1-named files. The un-suffixed files stay in
# place because the server, codesign, and S/MIME scripts and
# openssl_intermediate.cnf refer to intermediate.{key,cert,chain}.pem.
CERTSHA1=$(cert_sha1 "${CERTDIR}"/certs/"${CERTNAME}".cert.pem)

cp "${CERTDIR}"/private/{"${CERTNAME}","${CERTNAME}"."${CERTSHA1}"}.key.pem
cp "${CERTDIR}"/certs/{"${CERTNAME}","${CERTNAME}"."${CERTSHA1}"}.cert.pem
cp "${CERTDIR}"/certs/{"${CERTNAME}","${CERTNAME}"."${CERTSHA1}"}.chain.pem
cp "${CERTDIR}"/certs/{"${CERTNAME}","${CERTNAME}"."${CERTSHA1}"}.cer
cp "${CERTDIR}"/private/{"${CERTNAME}","${CERTNAME}"."${CERTSHA1}"}.p12

# Generate the CA's CRL as soon as the CA exists, so the
# crlDistributionPoints URL in every cert it signs resolves immediately.
"${PKI_ROOT}"/bin/create_crl.sh intermediate

if [ -n "${PKI_ARCHIVED_SHA1}" ]; then
    echo "The previous ${CERTNAME} is archived as ${CERTNAME}.${PKI_ARCHIVED_SHA1}.*; it was not revoked." >&2
    if [ "${PKI_RENEW}" = "1" ]; then
	echo "Renewed with the same key: certificates it issued stay valid. Publish the new ${CERTNAME}.cer (bin/publish_crls.sh)." >&2
    else
	echo "This intermediate has a NEW KEY: reissue the server, code signing and S/MIME certificates." >&2
	echo "If the old key was compromised, revoke the old certificate: bin/revoke_certificate.sh ${CERTDIR}/certs/${CERTNAME}.${PKI_ARCHIVED_SHA1}.cert.pem root CACompromise" >&2
    fi
fi

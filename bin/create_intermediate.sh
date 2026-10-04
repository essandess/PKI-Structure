#!/usr/bin/env bash

# create_intermediate.sh
#
# Creates the intermediate CA. If an intermediate CA already exists, the
# user is asked to confirm, then it is moved to SHA1-named files
# (intermediate.${CERTSHA1}.{key,cert,chain}.pem, .cer, .p12), revoked on
# the root once the replacement is confirmed issued, and a new
# intermediate CA is issued in its place.

CATRUE=${CATRUE:-1}
CERTDIR=${CERTDIR:-intermediate}
CERTNAME=${CERTNAME:-intermediate}
ISSUERCADIR=${ISSUERCADIR:-root}
ISSUERCANAME=${ISSUERCANAME:-root}

# 10 years (plus leap days, half of root)
DAYS=3653

ALGORITHM=${ALGORITHM:-EC}
EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-384}
RSA_KEYGEN_BITS=${RSA_KEYGEN_BITS:-3072}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

. "${SCRIPT_DIR}/pki_common.sh"
INTERMEDIATE_FILES="private/key.pem private/p12 certs/cert.pem certs/chain.pem certs/cer"

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
    trap 'pki_restore_archived_cert "${CERTDIR}" "${CERTNAME}" "${INTERMEDIATE_FILES}"' EXIT
    pki_archive_existing_cert "${CERTDIR}" "${CERTNAME}" "${INTERMEDIATE_FILES}"
fi

. "${SCRIPT_DIR}/pki_structure.sh"

# Intermediate encrypted key
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

# Intermediate CA CSR
"${OPENSSL}" req -config "${CERTDIR}"/openssl_"${CERTDIR}".cnf \
	-new -"${HASH_DIGEST}" \
	-key "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-passin file:"${CERTDIR}"/private/passphrase.txt \
	-out "${CERTDIR}"/certs/"${CERTNAME}".csr.pem -batch

# Intermediate CA certificate
if \
    "${OPENSSL}" ca -config openssl.cnf \
	-days ${DAYS} -notext -md "${HASH_DIGEST}" \
	-extfile "${CERTDIR}"/openssl_"${CERTDIR}".cnf -extensions v3_intermediate_ca \
	-in "${CERTDIR}"/certs/"${CERTNAME}".csr.pem \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-passin file:"${ISSUERCADIR}"/private/passphrase.txt -batch
then
    REISSUED=1
    NEW_SERIAL=$("${OPENSSL}" x509 -in "${CERTDIR}/certs/${CERTNAME}.cert.pem" -noout -serial | sed 's|^serial=||')
    pki_revoke_matching_cn "${ISSUERCADIR}" openssl.cnf "${ORG_NAME} Intermediate CA" "${NEW_SERIAL}" root
    rm "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
else
    rm "${CERTDIR}"/private/"${CERTNAME}".key.pem
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

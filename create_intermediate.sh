#!/usr/bin/env bash

# create_intermediate.sh
#
# Creates the intermediate CA. If an intermediate CA already exists, it is
# first moved to SHA1-named files (intermediate.${CERTSHA1}.{key,cert,chain}.pem,
# .cer, .p12) and a new intermediate CA is issued in its place.

CATRUE=${CATRUE:-1}
CERTDIR=${CERTDIR:-intermediate}
CERTNAME=${CERTNAME:-intermediate}
ISSUERCADIR=${ISSUERCADIR:-ca}
ISSUERCANAME=${ISSUERCANAME:-ca}

ALGORITHM=${ALGORITHM:-EC}
EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-384}
RSA_KEYGEN_BITS=${RSA_KEYGEN_BITS:-3072}

# Files that make up the intermediate CA, as <subdirectory>/<suffix>
INTERMEDIATE_FILES="private/key.pem private/p12 certs/cert.pem certs/chain.pem certs/cer"

# SHA1 fingerprint of a PEM certificate: lowercase, no colons
cert_sha1() {
    openssl x509 -noout -fingerprint -sha1 -inform pem -in "$1" \
	| sed -e 's|^.*Fingerprint=||' -e 's|:||g' \
	| tr '[:upper:]' '[:lower:]'
}

# Move an existing intermediate CA to SHA1-named files so that a new one can
# be issued. This must run before pki_structure.sh, whose "CA file already
# exists" check would otherwise abort. passphrase.txt is left in place: it
# protects both the archived key and the new key.
archive_existing_intermediate() {
    local old_cert="${CERTDIR}/certs/${CERTNAME}.cert.pem"
    [ -f "${old_cert}" ] || return 0

    local sha1
    sha1=$(cert_sha1 "${old_cert}")
    if [ -z "${sha1}" ]; then
	echo "Error: could not compute the SHA1 fingerprint of '${old_cert}'." >&2
	exit 1
    fi
    ARCHIVED_SHA1="${sha1}"

    echo "Archiving existing ${CERTNAME} CA as ${CERTNAME}.${ARCHIVED_SHA1}.*" >&2
    local item dir ext
    for item in ${INTERMEDIATE_FILES}; do
	dir=${item%%/*}
	ext=${item#*/}
	if [ -f "${CERTDIR}/${dir}/${CERTNAME}.${ext}" ]; then
	    mv -f "${CERTDIR}/${dir}/${CERTNAME}.${ext}" \
	       "${CERTDIR}/${dir}/${CERTNAME}.${ARCHIVED_SHA1}.${ext}"
	fi
    done
}

# If issuing the new intermediate CA fails, put the previous one back so the
# server, codesign, and S/MIME scripts still have a working issuer.
restore_archived_intermediate() {
    if [ -z "${ARCHIVED_SHA1}" ] || [ -n "${REISSUED}" ]; then
	return 0
    fi
    echo "Reissuing the ${CERTNAME} CA failed; restoring the previous one." >&2
    local item dir ext
    for item in ${INTERMEDIATE_FILES}; do
	dir=${item%%/*}
	ext=${item#*/}
	if [ -f "${CERTDIR}/${dir}/${CERTNAME}.${ARCHIVED_SHA1}.${ext}" ]; then
	    cp -p "${CERTDIR}/${dir}/${CERTNAME}.${ARCHIVED_SHA1}.${ext}" \
	       "${CERTDIR}/${dir}/${CERTNAME}.${ext}"
	fi
    done
}

# Archive only for a real create run: not for --help or --clean, not without
# the CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY precaution, and not when the
# issuer CA is missing (pki_structure.sh reports those cases itself).
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
    trap restore_archived_intermediate EXIT
    archive_existing_intermediate
fi

. pki_structure.sh

# 6 years, half of CA
DAYS=2191

# Intermediate encrypted key
case ${ALGORITHM} in
    EC)
	openssl genpkey -out "${CERTDIR}"/private/"${CERTNAME}".key.pem \
		-algorithm EC -pkeyopt ec_paramgen_curve:"${EC_PARAMGEN_CURVE}" -aes256 \
		-pass file:"${CERTDIR}"/private/passphrase.txt
	;;
    RSA)
	openssl genpkey -out "${CERTDIR}"/private/"${CERTNAME}".key.pem \
		-algorithm RSA -pkeyopt rsa_keygen_bits:"${RSA_KEYGEN_BITS}" -aes256 \
		-pass file:"${CERTDIR}"/private/passphrase.txt
	;;
    *)
	echo "Unknown algorithm '${ALGORITHM}'"
	exit 1
esac

# Intermediate CA CSR
openssl req -config "${CERTDIR}"/openssl_"${CERTDIR}".cnf \
	-new -"${HASH_DIGEST}" \
	-key "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-passin file:"${CERTDIR}"/private/passphrase.txt \
	-out "${CERTDIR}"/certs/"${CERTNAME}".csr.pem -batch

# Intermediate CA certificate
if \
    openssl ca -config openssl.cnf \
	-days ${DAYS} -notext -md ${HASH_DIGEST} -extensions v3_intermediate_ca \
	-in "${CERTDIR}"/certs/"${CERTNAME}".csr.pem \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-passin file:"${ISSUERCADIR}"/private/passphrase.txt -batch
then
    REISSUED=1
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
    openssl verify -CAfile "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem \
	"${CERTDIR}"/certs/"${CERTNAME}".chain.pem
else
    openssl verify -CAfile "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".cert.pem \
	"${CERTDIR}"/certs/"${CERTNAME}".chain.pem
fi

# CA certificate openssl self-verification
if [ -f "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem ]; then
    openssl verify -CAfile "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem \
	"${CERTDIR}"/certs/"${CERTNAME}".cert.pem
else
    openssl verify -CAfile "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".cert.pem \
	"${CERTDIR}"/certs/"${CERTNAME}".cert.pem
fi

# Convert to .cer and .p12 for storage
openssl x509 -outform der -in "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cer

# N.b. passphrase must be repeated on two lines in passphrase.txt
# https://developer.apple.com/forums/thread/697030
openssl pkcs12 -legacy -export -out "${CERTDIR}"/private/"${CERTNAME}".p12 \
	-inkey "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-in "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-passin file:"${CERTDIR}"/private/passphrase.txt \
	-passout file:"${CERTDIR}"/private/passphrase.txt
# verify .p12 passphrase
openssl pkcs12 -legacy -noout -in "${CERTDIR}"/private/"${CERTNAME}".p12 \
	-passin file:"${CERTDIR}"/private/passphrase.txt

# Copy the new certificate to SHA1-named files. The un-suffixed files stay in
# place because the server, codesign, and S/MIME scripts and
# openssl_intermediate.cnf refer to intermediate.{key,cert,chain}.pem.
CERTSHA1=$(cert_sha1 "${CERTDIR}"/certs/"${CERTNAME}".cert.pem)

cp "${CERTDIR}"/private/{"${CERTNAME}","${CERTNAME}"."${CERTSHA1}"}.key.pem
cp "${CERTDIR}"/certs/{"${CERTNAME}","${CERTNAME}"."${CERTSHA1}"}.cert.pem
cp "${CERTDIR}"/certs/{"${CERTNAME}","${CERTNAME}"."${CERTSHA1}"}.chain.pem
cp "${CERTDIR}"/certs/{"${CERTNAME}","${CERTNAME}"."${CERTSHA1}"}.cer
cp "${CERTDIR}"/private/{"${CERTNAME}","${CERTNAME}"."${CERTSHA1}"}.p12

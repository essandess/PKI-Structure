#!/usr/bin/env bash

# create_smime.sh
#
# Usage: create_smime.sh [-a|--algorithm EC|RSA] [-c|--clean|-vc|--veryclean] EMAIL CERTNAME
#
# Creates a signature and an encryption S/MIME certificate for EMAIL. If
# certificates named CERTNAME already exist, they are first moved to
# SHA1-named files, ${CERTNAME}-{signature,encryption}.${CERTSHA1}.{key,cert,chain}.pem,
# .cer, and .p12, and new certificates are issued in their place.

# 3 years and a month
DAYS=1126

CATRUE=${CATRUE:-0}
CERTDIR=${CERTDIR:-smime}
CERTNAME=${CERTNAME:-}
ISSUERCADIR=${ISSUERCADIR:-intermediate}
ISSUERCANAME=${ISSUERCANAME:-intermediate}

EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-256}
RSA_KEYGEN_BITS=${RSA_KEYGEN_BITS:-3072}

POSITIONAL_ARGS_USAGE=${POSITIONAL_ARGS_USAGE:-EMAIL CERTNAME}

# Files that make up one S/MIME certificate, as <subdirectory>/<suffix>
SMIME_FILES="private/key.pem private/p12 certs/cert.pem certs/chain.pem certs/cer"

# SHA1 fingerprint of a PEM certificate: lowercase, no colons
cert_sha1() {
    openssl x509 -noout -fingerprint -sha1 -inform pem -in "$1" \
	| sed -e 's|^.*Fingerprint=||' -e 's|:||g' \
	| tr '[:upper:]' '[:lower:]'
}

# Move existing signature/encryption certificates for CERTNAME to SHA1-named
# files so that new ones can be issued. Each one is named after its own
# fingerprint, so the signature and encryption archives never collide.
# passphrase.txt is left in place: it protects the archived and new keys.
archive_existing_smime() {
    local ext old_cert sha1 item dir suffix
    for ext in signature encryption; do
	old_cert="${CERTDIR}/certs/${CERTNAME}-${ext}.cert.pem"
	[ -f "${old_cert}" ] || continue

	sha1=$(cert_sha1 "${old_cert}")
	if [ -z "${sha1}" ]; then
	    echo "Error: could not compute the SHA1 fingerprint of '${old_cert}'." >&2
	    exit 1
	fi
	ARCHIVED="${ARCHIVED} ${ext}:${sha1}"

	echo "Archiving existing ${CERTNAME}-${ext} certificate as ${CERTNAME}-${ext}.${sha1}.*" >&2
	for item in ${SMIME_FILES}; do
	    dir=${item%%/*}
	    suffix=${item#*/}
	    if [ -f "${CERTDIR}/${dir}/${CERTNAME}-${ext}.${suffix}" ]; then
		mv -f "${CERTDIR}/${dir}/${CERTNAME}-${ext}.${suffix}" \
		   "${CERTDIR}/${dir}/${CERTNAME}-${ext}.${sha1}.${suffix}"
	    fi
	done
    done
}

# If issuing the new certificates fails part way, put the previous pair back
# so the signature and encryption certificates stay consistent.
restore_archived_smime() {
    if [ -z "${ARCHIVED}" ] || [ -n "${REISSUED}" ]; then
	return 0
    fi
    echo "Reissuing the ${CERTNAME} S/MIME certificates failed; restoring the previous ones." >&2
    local pair ext sha1 item dir suffix
    for pair in ${ARCHIVED}; do
	ext=${pair%%:*}
	sha1=${pair#*:}
	for item in ${SMIME_FILES}; do
	    dir=${item%%/*}
	    suffix=${item#*/}
	    if [ -f "${CERTDIR}/${dir}/${CERTNAME}-${ext}.${sha1}.${suffix}" ]; then
		cp -p "${CERTDIR}/${dir}/${CERTNAME}-${ext}.${sha1}.${suffix}" \
		   "${CERTDIR}/${dir}/${CERTNAME}-${ext}.${suffix}"
	    fi
	done
    done
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/pki_structure.sh"

# pki_structure.sh has consumed the option flags; EMAIL and CERTNAME remain.
if [ "$#" -ne 2 ]; then
    echo "Error: expected 2 arguments (EMAIL CERTNAME), got $#." >&2
    echo "Usage: $(basename "$0") [-a|--algorithm EC|RSA] [-c|--clean|-vc|--veryclean] EMAIL CERTNAME" >&2
    echo "To reissue all S/MIME certificates, run ./create_organization_smime_pki.sh; existing ones are archived under their SHA1." >&2
    exit 1
fi
EMAIL="$1"
CERTNAME="$2"

# pki_structure.sh checked for existing files before CERTNAME was known, so
# archive any existing certificates here.
trap restore_archived_smime EXIT
archive_existing_smime

# Anything still present is a key without a certificate, which can't be
# archived under a fingerprint.
for EXTENSION in signature encryption; do
    for f in "${CERTDIR}/private/${CERTNAME}-${EXTENSION}.key.pem" \
	     "${CERTDIR}/certs/${CERTNAME}-${EXTENSION}.cert.pem"; do
	if [ -f "${f}" ]; then
	    echo "Error: '${f}' exists but has no matching certificate to archive it under. Remove it, or clean with: $0 -vc" >&2
	    exit 1
	fi
    done
done

for EXTENSION in signature encryption; do
    # Encryption cert is always RSA: Apple Mail (macOS/iOS) does not support
    # ECDH-based S/MIME encryption certificates, only ECDSA signing. Do not
    # change this to honor ${ALGORITHM}=EC for the encryption cert.
    if [ "${ALGORITHM}" == "EC" ] && [ ${EXTENSION} != "encryption" ]; then
	openssl genpkey \
		-out "${CERTDIR}"/private/"${CERTNAME}"-${EXTENSION}.key.pem \
		-algorithm EC -pkeyopt ec_paramgen_curve:"${EC_PARAMGEN_CURVE}" -aes256 \
		-pass file:"${CERTDIR}"/private/passphrase.txt
	HASH_DIGEST=${EC_HASH_DIGEST}
    else
	openssl genpkey \
		-out "${CERTDIR}"/private/"${CERTNAME}"-${EXTENSION}.key.pem \
		-algorithm RSA -pkeyopt rsa_keygen_bits:"${RSA_KEYGEN_BITS}" -aes256 \
		-pass file:"${CERTDIR}"/private/passphrase.txt
	HASH_DIGEST=${RSA_HASH_DIGEST}
    fi

    # Server CSR
    openssl req -config "${CERTDIR}"/openssl_"${CERTDIR}".cnf \
	    -new -"${HASH_DIGEST}" \
	    -key "${CERTDIR}"/private/"${CERTNAME}"-${EXTENSION}.key.pem \
	    -passin file:"${CERTDIR}"/private/passphrase.txt \
	    -out "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.csr.pem -batch

    # Server certificate
    if \
	openssl ca -config "${CERTDIR}"/openssl_"${CERTDIR}".cnf \
		-extensions smime_${EXTENSION} \
		-days ${DAYS} -notext -md ${HASH_DIGEST} \
		-in "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.csr.pem \
		-out "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.cert.pem \
		-passin file:"${ISSUERCADIR}"/private/passphrase.txt \
		-subj "/CN=${EMAIL} - ${EXTENSION}/emailAddress=${EMAIL}/O=${ORG_NAME}/OU=${ORG_NAME} S\\/MIME/L=${ORG_LOCALITY}/ST=${ORG_STATE}/C=${ORG_COUNTRY}" \
		-batch
    then
	rm "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.csr.pem
    else
	rm "${CERTDIR}"/private/"${CERTNAME}"-${EXTENSION}.key.pem
	rm "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.csr.pem
	exit 1
    fi

    # Server chain
    if [ -f "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem ]; then
	cat "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.cert.pem \
	    "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem \
	    > "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.chain.pem
    else
	cat "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.cert.pem \
	    "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".cert.pem \
	    > "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.chain.pem
    fi

    # Intermediate CA chain openssl verification
    if [ -f "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem ]; then
	openssl verify -CAfile "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem \
	    "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.chain.pem
    else
	openssl verify -CAfile "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".cert.pem \
	    "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.chain.pem
    fi

    # CA certificate openssl self-verification
    if [ -f "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem ]; then
	openssl verify -CAfile "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".chain.pem \
	    "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.cert.pem
    else
	openssl verify -CAfile "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".cert.pem \
	    "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.cert.pem
    fi

    # Convert to .cer and .p12 for storage
    openssl x509 -outform der \
	    -in "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.cert.pem \
	    -out "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.cer

    # N.b. passphrase.txt holds two independent secrets: line 1 (-passin)
# unlocks the private key, line 2 (-passout) is the .p12 export password.
    # https://developer.apple.com/forums/thread/697030
    openssl pkcs12 -legacy -export \
		-out "${CERTDIR}"/private/"${CERTNAME}"-${EXTENSION}.p12 \
		-inkey "${CERTDIR}"/private/"${CERTNAME}"-${EXTENSION}.key.pem \
		-in "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.cert.pem \
		-passin file:"${CERTDIR}"/private/passphrase.txt \
		-passout file:"${CERTDIR}"/private/passphrase.txt
    # verify .p12 passphrase
    openssl pkcs12 -legacy -noout -in "${CERTDIR}"/private/"${CERTNAME}"-${EXTENSION}.p12 \
	    -passin "pass:$(sed -n 2p "${CERTDIR}"/private/passphrase.txt)"
done

# Both certificates were issued; the previous pair no longer needs restoring.
REISSUED=1

# Copy the new certificates to SHA1-named files, as create_intermediate.sh does.
for EXTENSION in signature encryption; do
    CERTSHA1=$(cert_sha1 "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.cert.pem)
    for item in ${SMIME_FILES}; do
	dir=${item%%/*}
	suffix=${item#*/}
	cp -p "${CERTDIR}/${dir}/${CERTNAME}-${EXTENSION}.${suffix}" \
	   "${CERTDIR}/${dir}/${CERTNAME}-${EXTENSION}.${CERTSHA1}.${suffix}"
    done
done

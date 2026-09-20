#!/usr/bin/env bash

# create_smime.sh

ORGANIZATION=${ORGANIZATION:-MyOrganization}

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

. pki_structure.sh

if [ "$#" -ne 2 ]; then
    echo "Error: expected 2 arguments (EMAIL CERTNAME), got $#." >&2
    echo "Usage: $(basename "$0") [-a|--algorithm EC|RSA] [-c|--clean|-vc|--veryclean] EMAIL CERTNAME" >&2
    echo "To regenerate all S/MIME certificates: $0 -vc && ./create_organization_smime_pki.sh" >&2
    exit 1
fi
EMAIL="$1"
CERTNAME="$2"

# pki_structure.sh checked this before CERTNAME was known, so check it here
for EXTENSION in signature encryption; do
    for f in "${CERTDIR}/private/${CERTNAME}-${EXTENSION}.key.pem" \
             "${CERTDIR}/certs/${CERTNAME}-${EXTENSION}.cert.pem"; do
        if [ -f "${f}" ]; then
            echo "Error: '${f}' already exists. Clean first with: $0 -vc" >&2
            exit 1
        fi
    done
done

for EXTENSION in signature encryption; do
    # Certificate encrypted key
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
		-subj "/CN=${EMAIL} - ${EXTENSION}/emailAddress=${EMAIL}/O=${ORGANIZATION}/OU=${ORGANIZATION} S\\/MIME/L=${ORG_LOCALITY}/ST=${ORG_STATE}/C=${ORG_COUNTRY}" \
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
    
    # N.b. passphrase must be repeated on two lines in passphrase.txt
    # https://developer.apple.com/forums/thread/697030
    openssl pkcs12 -legacy -export \
		-out "${CERTDIR}"/private/"${CERTNAME}"-${EXTENSION}.p12 \
		-inkey "${CERTDIR}"/private/"${CERTNAME}"-${EXTENSION}.key.pem \
		-in "${CERTDIR}"/certs/"${CERTNAME}"-${EXTENSION}.cert.pem \
		-passin file:"${CERTDIR}"/private/passphrase.txt \
		-passout file:"${CERTDIR}"/private/passphrase.txt
    # verify .p12 passphrase
    openssl pkcs12 -legacy -noout -in "${CERTDIR}"/private/"${CERTNAME}"-${EXTENSION}.p12 \
	    -passin file:"${CERTDIR}"/private/passphrase.txt    
done

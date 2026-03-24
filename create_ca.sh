#!/bin/sh

# create_ca.sh

CATRUE=${CATRUE:-1}
CERTDIR=${CERTDIR:-ca}
CERTNAME=${CERTNAME:-ca}

. pki_structure.sh

# CA encrypted key
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

# CA certificate
openssl req -config openssl.cnf \
	-new -x509 -days "${DAYS}" -"${HASH_DIGEST}" \
	-extensions v3_ca \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-key "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-passin file:"${CERTDIR}"/private/passphrase.txt -batch

# CA certificate openssl self-verification
openssl verify -CAfile "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	"${CERTDIR}"/certs/"${CERTNAME}".cert.pem

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

#!/usr/bin/env bash

# create_root.sh

CATRUE=${CATRUE:-1}
CERTDIR=${CERTDIR:-root}
CERTNAME=${CERTNAME:-root}

ALGORITHM=${ALGORITHM:-EC}
EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-384}
RSA_KEYGEN_BITS=${RSA_KEYGEN_BITS:-3072}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/pki_structure.sh"

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

# cert text
show_cert_text "${CERTDIR}"/certs/"${CERTNAME}".cert.pem

# Convert to .cer and .p12 for storage
openssl x509 -outform der -in "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cer

# N.b. passphrase.txt holds two independent secrets: line 1 (-passin)
# unlocks the private key, line 2 (-passout) is the .p12 export password.
# man openssl-passphrase-options
openssl pkcs12 -legacy -export -out "${CERTDIR}"/private/"${CERTNAME}".p12 \
	-inkey "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-in "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-passin file:"${CERTDIR}"/private/passphrase.txt \
	-passout file:"${CERTDIR}"/private/passphrase.txt
# verify .p12 passphrase
openssl pkcs12 -legacy -noout -in "${CERTDIR}"/private/"${CERTNAME}".p12 \
	-passin "pass:$(sed -n 2p "${CERTDIR}"/private/passphrase.txt)"

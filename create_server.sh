#!/bin/sh

# create_server.sh

SERVERFQDN=${SERVERFQDN:-hostname.myorganization.org}

# https://support.apple.com/en-us/HT210176
DAYS=825

CATRUE=${CATRUE:-0}
CERTDIR=${CERTDIR:-server}
CERTNAME=${CERTNAME:-${SERVERFQDN}}
ISSUERCADIR=${ISSUERCADIR:-intermediate}
ISSUERCANAME=${ISSUERCANAME:-intermediate}
EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-256}
RSA_KEYGEN_BITS=${RSA_KEYGEN_BITS:-2048}

. pki_structure.sh

# Certificate encrypted key
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

# Server CSR
openssl req -config "${CERTDIR}"/openssl_"${CERTDIR}".cnf \
	-new -"${HASH_DIGEST}" \
	-key "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-passin file:"${CERTDIR}"/private/passphrase.txt \
	-out "${CERTDIR}"/certs/"${CERTNAME}".csr.pem -batch

# Server certificate
if \
    openssl ca -config "${CERTDIR}"/openssl_"${CERTDIR}".cnf \
	-days ${DAYS} -notext -md ${HASH_DIGEST} -extensions server_cert \
	-in "${CERTDIR}"/certs/"${CERTNAME}".csr.pem \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-passin file:"${ISSUERCADIR}"/private/passphrase.txt \
	-batch
then
    rm "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
else
    rm "${CERTDIR}"/private/"${CERTNAME}".key.pem
    rm "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
    exit 1
fi

# Server chain
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

# decrypt private key
case ${ALGORITHM} in
    EC)
        openssl ec -in "${CERTDIR}"/private/"${CERTNAME}".key.pem -out "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted -passin file:"${CERTDIR}"/private/passphrase.txt
        ;;
    RSA)
        openssl rsa -in "${CERTDIR}"/private/"${CERTNAME}".key.pem -out "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted -passin file:"${CERTDIR}"/private/passphrase.txt
        ;;
    *)
	echo "Unknown algorithm '${ALGORITHM}'"
	exit 1
esac

# rename certificate
CERTSHA1=$(openssl x509 -noout -fingerprint -sha1 -inform pem \
		   -in "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	       | sed -e 's|^sha1 Fingerprint=||' \
	       | sed -e 's|:||g' \
	       | tr '[:upper:]' '[:lower:]' \
	)

mv "${CERTDIR}"/private/{"${CERTNAME}","${SERVERFQDN}"."${CERTSHA1}"}.key.pem
mv "${CERTDIR}"/private/{"${CERTNAME}","${SERVERFQDN}"."${CERTSHA1}"}.key.pem.decrypted
mv "${CERTDIR}"/private/{"${CERTNAME}","${SERVERFQDN}"."${CERTSHA1}"}.p12
mv "${CERTDIR}"/certs/{"${CERTNAME}","${SERVERFQDN}"."${CERTSHA1}"}.cer
mv "${CERTDIR}"/certs/{"${CERTNAME}","${SERVERFQDN}"."${CERTSHA1}"}.cert.pem
mv "${CERTDIR}"/certs/{"${CERTNAME}","${SERVERFQDN}"."${CERTSHA1}"}.chain.pem

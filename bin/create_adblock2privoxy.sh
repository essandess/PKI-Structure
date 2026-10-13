#!/usr/bin/env bash

# create_adblock2privoxy.sh

SERVERFQDN=${SERVERFQDN:-adblock2privoxy-nginx}

# https://support.apple.com/en-us/HT210176
DAYS=825

CATRUE=${CATRUE:-0}
CERTDIR=${CERTDIR:-privoxy/adblock2privoxy}
CERTNAME=${CERTNAME:-${SERVERFQDN}}
ISSUERCADIR=${ISSUERCADIR:-privoxy}
ISSUERCANAME=${ISSUERCANAME:-privoxy}

ALGORITHM=${ALGORITHM:-EC}
EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-256}
HASH_DIGEST=${HASH_DIGEST:-sha256}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

. "${SCRIPT_DIR}/pki_common.sh"
. "${SCRIPT_DIR}/pki_structure.sh"

# Never longer than the issuer's remaining life
DAYS=$(pki_cap_days "${ISSUERCADIR}/certs/${ISSUERCANAME}.cert.pem" "${DAYS}")

# Certificate encrypted key
case ${ALGORITHM} in
    EC)
	"${OPENSSL}" genpkey -out "${CERTDIR}"/private/"${CERTNAME}".key.pem \
		-algorithm EC -pkeyopt ec_paramgen_curve:"${EC_PARAMGEN_CURVE}" -aes256 \
		-pass file:"${CERTDIR}"/private/passphrase.txt
	"${OPENSSL}" ec -in "${CERTDIR}"/private/"${CERTNAME}".key.pem \
		-passin file:"${CERTDIR}"/private/passphrase.txt \
		-out "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted
chmod 0600 "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted	;;
    RSA)
	"${OPENSSL}" genpkey -out "${CERTDIR}"/private/"${CERTNAME}".key.pem \
		-algorithm RSA -pkeyopt rsa_keygen_bits:"${RSA_KEYGEN_BITS}" -aes256 \
		-pass file:"${CERTDIR}"/private/passphrase.txt
	"${OPENSSL}" rsa -in "${CERTDIR}"/private/"${CERTNAME}".key.pem \
		-passin file:"${CERTDIR}"/private/passphrase.txt \
		-out "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted
chmod 0600 "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted	;;
    *)
	echo "Unknown algorithm '${ALGORITHM}'"
	exit 1
esac

# Server CSR
"${OPENSSL}" req -config "${CERTDIR}"/openssl_"${CERTDIR##*/}".cnf \
	-new -"${HASH_DIGEST}" \
	-key "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	-passin file:"${CERTDIR}"/private/passphrase.txt \
	-out "${CERTDIR}"/certs/"${CERTNAME}".csr.pem -batch

# Server certificate
if "${OPENSSL}" ca -config "${CERTDIR}"/openssl_"${CERTDIR##*/}".cnf \
	-extensions "${CERTDIR##*/}" \
	-keyfile "${ISSUERCADIR}"/private/"${ISSUERCANAME}".key.pem \
	-cert "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".cert.pem \
	-days ${DAYS} -notext -md "${HASH_DIGEST}" \
	-in "${CERTDIR}"/certs/"${CERTNAME}".csr.pem \
	-out "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
	-passin file:"${ISSUERCADIR}"/private/passphrase.txt \
	-batch
then
    if ! pki_assert_leaf_scope "${CERTDIR}/certs/${CERTNAME}.cert.pem" adblock2privoxy; then
        pki_revoke_unscoped "${CERTDIR}/openssl_${CERTDIR##*/}.cnf" "${ISSUERCADIR}" "${CERTDIR}/certs/${CERTNAME}.cert.pem" privoxy
        rm -f "${CERTDIR}"/private/"${CERTNAME}".key.pem "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted "${CERTDIR}"/certs/"${CERTNAME}".csr.pem "${CERTDIR}"/certs/"${CERTNAME}".cert.pem
        exit 1
    fi
    NEW_SERIAL=$("${OPENSSL}" x509 -in "${CERTDIR}/certs/${CERTNAME}.cert.pem" -noout -serial | sed 's|^serial=||')
    pki_revoke_matching_cn "${ISSUERCADIR}" "${CERTDIR}/openssl_${CERTDIR##*/}.cnf" "${CERTNAME}" "${NEW_SERIAL}" privoxy
    rm "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
else
    rm "${CERTDIR}"/private/"${CERTNAME}".key.pem
    rm "${CERTDIR}"/private/"${CERTNAME}".key.pem.decrypted
    rm "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
    exit 1
fi

pki_finish_cert "${CERTDIR}" "${CERTNAME}" "${ISSUERCADIR}" "${ISSUERCANAME}"

# rename certificate
pki_sha1_files mv "${CERTDIR}" "${CERTNAME}" "${SERVERFQDN}" \
    "private/key.pem private/key.pem.decrypted private/p12 certs/cer certs/cert.pem certs/chain.pem"

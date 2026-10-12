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

# Scope (see openssl_${CERTDIR}.cnf): intermediate is limited to TLS server and
# code signing certificates by extendedKeyUsage and critical nameConstraints
# (permitted DNS: DOMAIN_NAME); intermediate_smime
# (bin/create_intermediate_smime.sh sets CERTDIR=intermediate_smime) is limited
# to emailProtection. The new certificate is checked for these restrictions.

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
# what is reissued after a new key
case "${CERTDIR}" in
    intermediate_smime) LEAVES="S/MIME" ;;
    *) LEAVES="server and code signing" ;;
esac

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

# nameConstraints of the TLS / code signing intermediate (its openssl cnf reads
# DOMAIN_NAME from the environment).
DOMAIN_NAME="${DOMAIN_NAME:-}"
if [ "${CERTDIR}" = "intermediate" ]; then
    if [ -z "${DOMAIN_NAME}" ]; then
        echo "Error: set DOMAIN_NAME in pki_identity.env: the DNS domain the intermediate may issue for." >&2
        exit 1
    fi
    case "${SERVER_FQDN:-}" in
        "${DOMAIN_NAME}"|*".${DOMAIN_NAME}") ;;
        *)
            echo "Error: SERVER_FQDN '${SERVER_FQDN:-}' is not within DOMAIN_NAME '${DOMAIN_NAME}'; the server certificate would violate the intermediate's nameConstraints." >&2
            exit 1
            ;;
    esac
fi
export DOMAIN_NAME

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
	-passin file:"${ISSUERCADIR}"/private/passphrase.txt \
        -batch
then
    # a section missing from the cnf would silently issue an unrestricted CA
    if ! pki_assert_ca_scope "${CERTDIR}/certs/${CERTNAME}.cert.pem" "${CERTDIR}"; then
        echo "Error: the new ${CERTNAME} certificate lacks the restrictions of ${CERTDIR}/openssl_${CERTDIR}.cnf ([ ${CERTDIR}_ca ]); revoking it." >&2
        "${OPENSSL}" ca -config openssl.cnf \
                -revoke "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
                -crl_reason superseded \
                -passin file:"${ISSUERCADIR}"/private/passphrase.txt || true
        "${PKI_ROOT}"/bin/create_crl.sh "${ISSUERCANAME}" || true
        if [ "${PKI_RENEW:-0}" != "1" ]; then
            rm -f "${CERTDIR}"/private/"${CERTNAME}".key.pem
        fi
        rm -f "${CERTDIR}"/certs/"${CERTNAME}".cert.pem "${CERTDIR}"/certs/"${CERTNAME}".csr.pem
        exit 1
    fi
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

pki_finish_cert "${CERTDIR}" "${CERTNAME}" "${ISSUERCADIR}" "${ISSUERCANAME}"

# Copy the new certificate to SHA1-named files. The un-suffixed files stay in
# place because the server, codesign, and S/MIME scripts and
# openssl_intermediate.cnf refer to intermediate.{key,cert,chain}.pem.
pki_sha1_files cp "${CERTDIR}" "${CERTNAME}" "${CERTNAME}" "${INTERMEDIATE_FILES}"

# Generate the CA's CRL as soon as the CA exists, so the
# crlDistributionPoints URL in every cert it signs resolves immediately.
"${PKI_ROOT}"/bin/create_crl.sh "${CERTDIR}"

if [ -n "${PKI_ARCHIVED_SHA1}" ]; then
    echo "The previous ${CERTNAME} is archived as ${CERTNAME}.${PKI_ARCHIVED_SHA1}.*; it was not revoked." >&2
    if [ "${PKI_RENEW}" = "1" ]; then
	echo "Renewed with the same key: certificates it issued stay valid. Publish the new ${CERTNAME}.cer (bin/publish_crls.sh)." >&2
    else
	echo "This ${CERTDIR} has a NEW KEY: reissue the ${LEAVES} certificates." >&2
	echo "If the old key was compromised, revoke the old certificate: bin/revoke_certificate.sh ${CERTDIR}/certs/${CERTNAME}.${PKI_ARCHIVED_SHA1}.cert.pem root CACompromise" >&2
    fi
fi

#!/usr/bin/env bash

# create_smime.sh
#
# Usage: create_smime.sh [-a|--algorithm EC|RSA] [-c|--clean] EMAIL CERTNAME
#
# Creates a signature and an encryption S/MIME certificate for EMAIL, issued by
# the S/MIME intermediate (intermediate_smime/). If
# certificates named CERTNAME already exist, they are first moved to
# SHA1-named files, ${CERTNAME}-{signature,encryption}.${CERTSHA1}.{key,cert,chain}.pem,
# .cer and .p12, and new certificates are issued in their place.
# Any other still-valid certificate the intermediate CA has on record under
# the same CommonName (EMAIL - signature / EMAIL - encryption) is revoked as
# superseded, but only once BOTH replacements are issued and complete: if
# anything fails before that, the previous files are restored and nothing is
# revoked.
#
# Each issuance gets its own random .p12 export password, shared by the signature
# and encryption .p12 and kept in the keychain (bin/pki_keychain.py get --cert CERT
# --field p12). Give it to the person who receives the .p12 and to nobody else.

# https://support.apple.com/en-us/HT210176
# Technically longer acceptable for noncommercial S/MIME, 
# but not not recommended or guaranteed to be accepted
# (shortened if the intermediate ends sooner)
DAYS=825

CATRUE=${CATRUE:-0}
CERTDIR=${CERTDIR:-smime}
CERTNAME=${CERTNAME:-}
ISSUERCADIR=${ISSUERCADIR:-intermediate_smime}
ISSUERCANAME=${ISSUERCANAME:-intermediate_smime}

EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-256}
RSA_KEYGEN_BITS=${RSA_KEYGEN_BITS:-3072}

POSITIONAL_ARGS_USAGE=${POSITIONAL_ARGS_USAGE:-EMAIL CERTNAME}

# Files that make up one S/MIME certificate, as <subdirectory>/<suffix>
SMIME_FILES="private/key.pem private/p12 certs/cert.pem certs/chain.pem certs/cer"

# Archive each existing signature/encryption certificate of CERTNAME under its
# own fingerprint, so that new ones can be issued. Key passphrases stay in the
# keychain: an archived key keeps its entry.
ARCHIVED=()
archive_existing_smime() {
    local ext

    for ext in signature encryption; do
	pki_archive_existing_cert "${CERTDIR}" "${CERTNAME}-${ext}" "${SMIME_FILES}"
	if [ -n "${PKI_ARCHIVED_SHA1}" ]; then
	    ARCHIVED+=("${ext}:${PKI_ARCHIVED_SHA1}")
	fi
    done
}

# If issuing fails part way, revoke what was issued (never delivered) and put
# the previous pair back, so signature and encryption stay consistent.
restore_archived_smime() {
    local s pair

    [ -z "${REISSUED}" ] || return 0
    for s in ${REVOKE_SERIAL[@]+"${REVOKE_SERIAL[@]}"}; do
	pki_revoke_unscoped "${ISSUERCADIR}" "${ISSUERCADIR}/newcerts/${s}.pem"
    done
    for pair in ${ARCHIVED[@]+"${ARCHIVED[@]}"}; do
	pki_restore_archived_cert "${CERTDIR}" "${CERTNAME}-${pair%%:*}" \
	    "${SMIME_FILES}" "${pair#*:}"
    done
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

. "${SCRIPT_DIR}/pki_common.sh"
. "${SCRIPT_DIR}/pki_structure.sh"

# pki_structure.sh has consumed the option flags; EMAIL and CERTNAME remain.
if [ "$#" -ne 2 ]; then
    echo "Error: expected 2 arguments (EMAIL CERTNAME), got $#." >&2
    echo "Usage: $(basename "$0") [-a|--algorithm EC|RSA] [-c|--clean] EMAIL CERTNAME" >&2
    echo "To reissue all S/MIME certificates, run ./create_organization_smime.sh; existing ones are archived under their SHA1." >&2
    exit 1
fi
EMAIL="$1"
CERTNAME="$2"
EMAIL_SUBJ=${EMAIL//+/\\+}   # '+' separates RDN values in -subj

# EMAIL goes into -subj, CERTNAME into file names: no '/', '\' or '..'.
if ! [[ "${EMAIL}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] \
       || ! [[ "${CERTNAME}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
    echo "Error: invalid EMAIL, or CERTNAME not [A-Za-z0-9_.-]." >&2
    exit 1
fi

# The CN is "EMAIL - ROLE" and X.509 caps a CN at 64 characters (OpenSSL
# enforces it whatever the cnf says): refuse now, before any key or
# certificate exists. "encryption" is the longer role, so it decides.
CN_LONGEST="${EMAIL} - encryption"
if [ "${#CN_LONGEST}" -gt 64 ]; then
    echo "Error: EMAIL '${EMAIL}' is too long:" >&2
    echo "the CN '${CN_LONGEST}' would be ${#CN_LONGEST} characters;" >&2
    echo "X.509 allows 64, so EMAIL may have at most 51." >&2
    exit 1
fi

# Never longer than the intermediate's remaining life
DAYS=$(pki_cap_days "${ISSUERCADIR}/certs/${ISSUERCANAME}.cert.pem" "${DAYS}")

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
	    echo "Error: '${f}' exists but has no matching certificate to archive it under. Remove it, or clean with: $0 -c" >&2
	    exit 1
	fi
    done
done

# One .p12 password per issuance: the signature's, shared by the encryption's
P12_LIKE=""

# Predecessors to revoke once everything below has succeeded
REVOKE_CN=()
REVOKE_SERIAL=()

for EXTENSION in signature encryption; do
    # Encryption cert is always RSA: Apple Mail (macOS/iOS) does not support
    # ECDH-based S/MIME encryption certificates, only ECDSA signing. Do not
    # change this to honor ${ALGORITHM}=EC for the encryption cert.
    if [ "${ALGORITHM}" == "EC" ] && [ "${EXTENSION}" != "encryption" ]; then
	SMIME_ALG=EC SMIME_HASH=${EC_HASH_DIGEST}
    else
	SMIME_ALG=RSA SMIME_HASH=${RSA_HASH_DIGEST}
    fi
    ALGORITHM=${SMIME_ALG} HASH_DIGEST=${SMIME_HASH} pki_issue_leaf \
	"${CERTNAME}-${EXTENSION}" "${CERTDIR}/openssl_${CERTDIR}.cnf" \
	"${CERTDIR}_${EXTENSION}" "smime_${EXTENSION}" "${EMAIL} - ${EXTENSION}" \
	-subj "/CN=${EMAIL_SUBJ} - ${EXTENSION}/emailAddress=${EMAIL_SUBJ}/O=${ORG_NAME}/OU=${ORG_NAME} S\\/MIME/L=${ORG_LOCALITY}/ST=${ORG_STATE}/C=${ORG_COUNTRY}"
    # not revoked yet: see the end of this script
    REVOKE_CN+=("${EMAIL} - ${EXTENSION}")
    REVOKE_SERIAL+=("${NEW_SERIAL}")

    # .p12 password: shared by the pair (keychain)
    pki_finish_cert "${CERTDIR}" "${CERTNAME}-${EXTENSION}" "${ISSUERCADIR}" "${ISSUERCANAME}" "${P12_LIKE}"
    P12_LIKE="${CERTDIR}/certs/${CERTNAME}-${EXTENSION}.cert.pem"
done

# Both certificates were issued; the previous pair no longer needs restoring.
REISSUED=1

# Copy the new certificates to SHA1-named files, as create_intermediate.sh does.
for EXTENSION in signature encryption; do
    pki_sha1_files cp "${CERTDIR}" "${CERTNAME}-${EXTENSION}" "${CERTNAME}-${EXTENSION}" "${SMIME_FILES}"
done

# Only now, with both replacements complete, revoke what they supersede.
for i in "${!REVOKE_CN[@]}"; do
    pki_revoke_matching_cn "${ISSUERCADIR}" "${REVOKE_CN[i]}" "${REVOKE_SERIAL[i]}"
done

echo "The .p12 password of ${CERTNAME} (give it only to the recipient):" >&2
echo "  bin/pki_keychain.py get --field p12 \\" >&2
echo "    --cert ${CERTDIR}/certs/${CERTNAME}-signature.cert.pem" >&2

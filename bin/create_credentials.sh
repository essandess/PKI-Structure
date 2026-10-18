#!/usr/bin/env bash

# create_credentials.sh -- build a macOS credential installer from the PKI tree.
#
# Usage: create_credentials.sh [--user-keychain] [--with-privoxy] [--extra-pki-dir DIR]...
#                              [--allow-expired-encryption]
#                              [--allow-superseded-encryption]
#                              [--allow-signature-with-encryption] ['NAME_GLOB' ...]
#        create_credentials.sh --ca-certs-only [--user-keychain]
#
# Writes ONE installer, mdm/credentials/install_credentials_<stem>.sh,
# after listing its payload and asking for confirmation (PKI_ASSUME_YES=1
# skips the prompt). The payload is a tar.xz, base64-encoded with openssl,
# appended to the script. <stem> is the globs with glob characters spelled
# out (see installer_name), "nosmimes" without globs, "cacerts" with
# --ca-certs-only.
#
# Always single-quote each 'NAME_GLOB': the shell must not expand it. The
# script matches it, as a bash glob with brace expansion, against the S/MIME
# certificate names in smime/certs, for example 'persona_*' or
# 'personb_{gmail,comcast}_2026'. The installer holds the certificates
# matching any 'NAME_GLOB'; with none, no S/MIME certificates are included.
# --extra-pki-dir DIR (repeatable) also searches DIR/smime, a PKI tree with
# the same layout, e.g. an older one holding expired certificates. Its root,
# intermediate and CRLs, if present, are used for validation too.
# Each .p12 must open with its keychain password (bin/pki_keychain.py; one per
# issuance).
#
# Installer contents:
#   CA certificates  root (trusted), valid intermediate, valid intermediate_smime
#                    (if it exists); with --with-privoxy also the privoxy CA
#                    (trusted for TLS only); public certificates only. The root and the intermediate are
#                    always included: the installer's signature is checked
#                    against them. They go to the System keychain (sudo,
#                    payload directory system/), or with --user-keychain to
#                    the user's login keychain (no sudo, directory user/).
#   S/MIME           matching .p12 files, including expired ones, imported
#                    into the login keychain, with their SECRET password
#                    files (<name>.p12.pass).
# Server certificates are not included: the installed CAs already validate
# them. Items that do not exist are reported and left out of the payload,
# except the root and the intermediate, which are required. The installer
# confirms each item and stores no passwords. Its --tar-only flag writes the
# payload, still encrypted when it is, to credentials_<stem>.txz[.enc] in the
# current directory.
#
# Encryption: when S/MIME .p12 files are included, the tar holds their secret
# password files and is therefore encrypted (openssl enc, PBKDF2) with a new
# random password (pki_random_password). That password is stored in the PKI
# keychain (bin/pki_keychain.py) as the entry install_credentials_<stem>.sh and
# the installer asks for it on the terminal, never in argv or the environment.
# Retrieve it with: bin/pki_keychain.py installer-get --name NAME. Send the
# installer and its password by different channels.
# mdm/ holds the installers; keep it out of version control. CA secret keys
# and their passwords are never included.
#
# --ca-certs-only: the payload holds only the public CA certificates (root,
# valid intermediate, S/MIME intermediate; privoxy CA only with
# --with-privoxy): no .p12 files, no passwords, not
# encrypted. They are imported as above and the root is trusted. Takes no
# 'NAME_GLOB' and no --extra-pki-dir.
#
# Signature: every installer is signed with the code signing certificate
# (the newest valid codesign/certs/codesign.<sha1>.cert.pem and its
# codesign/private/codesign.<sha1>.key.pem,
# key passphrase from the PKI keychain; see
# PKI_CODESIGN_DIR and PKI_CODESIGN_NAME). It must be valid, chain to the
# root, and allow code signing. The signature is a detached PKCS#7 (DER)
# block inside the installer, between __SIGNATURE_BELOW__ and
# __PAYLOAD_BELOW__. It covers all of the installer except that block: the
# script text and the encrypted payload. The installer checks it BEFORE
# decrypting or unpacking the payload, against the root and intermediates
# carried in the signature block. A chain carried inside the file cannot prove
# who made the file, so the installer also anchors the root: it must already
# be installed on the machine, or match PKI_ROOT_SHA256, or be confirmed by
# the user against a fingerprint received separately.
#
# Validation, before anything enters the payload (unexpired CRLs found in
# root/ and intermediate/, or named by PKI_ROOT_CRL / PKI_INTERMEDIATE_CRL):
#   root          must verify against itself
#   intermediate  must verify against the root, root CRL checked
#   privoxy CA    must verify against itself (it is self-signed)
#   code signing  must verify against the root through a valid intermediate,
#                 CRLs checked, and carry the codeSigning extendedKeyUsage
#   S/MIME        must verify against the root through a valid intermediate,
#                 CRLs of the whole chain checked (openssl verify
#                 -crl_check_all)
# Old encryption certificates, for decrypting old mail. An S/MIME ENCRYPTION
# certificate that is expired, or revoked as "superseded" (create_smime.sh sets
# this on reissue), is left out unless you opt in:
#   --allow-expired-encryption      include expired encryption certificates
#   --allow-superseded-encryption   include those revoked as superseded
#   --allow-signature-with-encryption
#                                   accept encryption certificates whose keyUsage
#                                   also allows signing (--extra-pki-dir only)
# (one that is both needs both). Policy table: bin/pki_validate.py.
#
# Environment: PKI_ASSUME_YES, PKI_ROOT_CRL, PKI_INTERMEDIATE_CRL,
# PKI_PRIVOXY_DIRS (default privoxy), PKI_CODESIGN_DIR (default codesign),
# PKI_CODESIGN_NAME (default codesign). The installer reads PKI_ASSUME_YES,
# PKI_ROOT_SHA256 and PKI_P12_PASSWORD_<GROUP>.

# exit when any command fails
set -e

set -E   # make the ERR trap fire inside functions and subshells
set -o pipefail
shopt -s inherit_errexit
trap 'rc=$?; echo "Error: $(basename "$0") failed (exit ${rc}) at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

shopt -s nullglob

umask 077

INVOKE_DIR="${PWD}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

. "${SCRIPT_DIR}/pki_common.sh"
. "${PKI_ROOT}/bin/define_openssl.sh"
. "${PKI_ROOT}/bin/define_python.sh"

for fn in cert_sha1 cert_is_ca pki_random_password; do
    declare -F "${fn}" >/dev/null \
        || { echo "Error: ${fn} is not defined by bin/pki_common.sh." >&2; exit 1; }
done

OUTDIR=mdm/credentials
ENC_CIPHER=aes-256-cbc   # payload encryption (openssl enc)
ENC_ITER=600000          # PBKDF2 iterations (needs OpenSSL 1.1.1+/LibreSSL 3.1+)
ROOT_CERT=root/certs/root.cert.pem
PRIVOXY_DIRS=${PKI_PRIVOXY_DIRS:-privoxy}
CODESIGN_DIR=${PKI_CODESIGN_DIR:-codesign}
CODESIGN_NAME=${PKI_CODESIGN_NAME:-codesign}
SMIME_RE='^(.+)-(signature|encryption)(\.[0-9a-fA-F]{40})?\.cert\.pem$'
# Characters allowed in a NAME_GLOB. Nothing that is shell syntax, because
# brace expansion is done with eval (see expand_name_glob).
NAME_GLOB_RE='^[][A-Za-z0-9_.,*?{}!^-]+$'

CA_CERTS_ONLY=0
ALLOW_EXPIRED_ENC=0
ALLOW_SUPERSEDED_ENC=0
ALLOW_SIG_ENC=0
USER_KEYCHAIN=0
WITH_PRIVOXY=0     # the privoxy CA is trusted by devices that use the proxy only
CA_DOMAIN=system   # payload directory and keychain of the CA certificates
HELP=0
NAMES=()
EXTRA_DIRS=()

die() {
    echo "Error: $*" >&2
    exit 1
}

"${PYTHON}" -c 'import cryptography' 2>/dev/null \
    || die "${PYTHON} with the 'cryptography' package is required (certificate validation)."

warn() {
    echo "Warning: $*" >&2
}

# add_extra_dir DIR: remember DIR (relative to where the script was run)
add_extra_dir() {
    local d
    d=$(cd "${INVOKE_DIR}" && cd "$1" 2>/dev/null && pwd) \
        || die "--extra-pki-dir '$1' is not a directory."
    [ -d "${d}/smime" ] || die "--extra-pki-dir '$1' has no smime subdirectory."
    EXTRA_DIRS+=("${d}")
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --ca-certs-only)
            CA_CERTS_ONLY=1
            shift
            ;;
        --user-keychain)
            USER_KEYCHAIN=1
            CA_DOMAIN=user
            shift
            ;;
        --with-privoxy)
            WITH_PRIVOXY=1
            shift
            ;;
        --allow-expired-encryption)
            ALLOW_EXPIRED_ENC=1
            shift
            ;;
        --allow-superseded-encryption)
            ALLOW_SUPERSEDED_ENC=1
            shift
            ;;
        --allow-signature-with-encryption)
            ALLOW_SIG_ENC=1
            shift
            ;;
        --extra-pki-dir)
            [ $# -ge 2 ] || die "--extra-pki-dir needs a DIR argument."
            add_extra_dir "$2"
            shift 2
            ;;
        --extra-pki-dir=*)
            add_extra_dir "${1#*=}"
            shift
            ;;
        -h|--help)
            HELP=1
            shift
            ;;
        -*)
            die "unknown option '$1'"
            ;;
        *)
            [[ "$1" =~ ${NAME_GLOB_RE} ]] \
                || die "invalid 'NAME_GLOB' '$1' (allowed: letters, digits, _ . - , * ? [ ] { } ! ^); quote it so the shell does not expand it."
            NAMES+=("$1")
            shift
            ;;
    esac
done

if [ "${HELP}" != "0" ]; then
    cat <<USAGE
Usage:

$(basename "$0") [--user-keychain] [--with-privoxy] [--extra-pki-dir DIR]...
    [--allow-expired-encryption]
    [--allow-superseded-encryption] [--allow-signature-with-encryption]
    ['NAME_GLOB' ...]
$(basename "$0") --ca-certs-only [--user-keychain]

Creates ONE installer, ./${OUTDIR}/install_credentials_<stem>.sh, with the
root and intermediate CA certificates (both required; the privoxy CA only
with --with-privoxy) and the S/MIME certificates matching any
'NAME_GLOB'. <stem> is the globs with glob characters spelled out
(* S, ? Q, { LB, } RB, [ LBK, ] RBK, , C, !/^ N); nosmimes without globs;
cacerts with --ca-certs-only.

Single-quote every 'NAME_GLOB' so the shell does not expand it against the
current directory. The script matches it, as a bash glob with brace
expansion, against the S/MIME certificate names in smime/certs
(persona_gmail_2026), for example:
  'persona_*'  'personb_{gmail,comcast}_2026'
Without 'NAME_GLOB' no S/MIME certificates are included.
The payload is listed and confirmed (y/N) before the installer is written;
PKI_ASSUME_YES=1 skips the prompt.

When it includes S/MIME certificates, the installer's payload also holds the
secret .p12 password files, so the payload is encrypted with a new random
password, stored in the PKI keychain as the entry install_credentials_<stem>.sh
(bin/pki_keychain.py installer-get --name NAME). The installer asks for that
password; send it by a different channel than the installer.

Every installer is signed with the code signing certificate (codesign/ by
default; PKI_CODESIGN_DIR, PKI_CODESIGN_NAME). The installer checks the
signature before it installs anything.

Every certificate is validated first: the intermediate and the code signing
certificate against the root, the S/MIME certificates against the root
through a valid intermediate, with the CRLs checked (an unexpired CRL is
required). An S/MIME ENCRYPTION certificate that is expired, or revoked as
"superseded" (what create_smime.sh sets when it reissues one), is left out
unless you opt in, to decrypt old mail:
  --allow-expired-encryption      include expired encryption certificates
  --allow-superseded-encryption   include those revoked as superseded
  --allow-signature-with-encryption
                                  accept encryption certificates whose keyUsage
                                  also allows signing (--extra-pki-dir only)
Expired or revoked signature certificates are always rejected.

  --user-keychain         install the CA certificates into the user's login
                          keychain (payload directory user/, no sudo)
                          instead of the System keychain (system/, sudo)
  --with-privoxy         also include the privoxy CA (trusted for TLS only);
                          default: not included
  --extra-pki-dir DIR     also look for S/MIME certificates in DIR/smime, a
                          PKI tree with the same layout (for example an older
                          one with expired certificates); repeatable. Its
                          root, intermediate and CRLs also serve validation.
  --ca-certs-only         create an installer with only the public CA
                          certificates (root, valid intermediate,
                          S/MIME intermediate; privoxy CA with --with-privoxy):
                          no .p12 files, no passwords; the root is
                          trusted. Not encrypted.
                          Takes no 'NAME_GLOB' or --extra-pki-dir.

Server certificates are not included. The installer's --tar-only flag writes
its payload (still encrypted, if it is) to credentials_<stem>.txz, or
credentials_<stem>.txz.enc when encrypted, in the current directory.
USAGE
    exit 0
fi

if [ "${CA_CERTS_ONLY}" = "1" ]; then
    [ "${#NAMES[@]}" -eq 0 ] || die "--ca-certs-only does not take 'NAME_GLOB' arguments"
    [ "${#EXTRA_DIRS[@]}" -eq 0 ] || die "--ca-certs-only does not use --extra-pki-dir"
fi

: "${OPENSSL:?OPENSSL is not set by bin/define_openssl.sh}"

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/pki-credentials.XXXXXX")
trap 'rm -rf "${STAGE}"' EXIT

# S/MIME sources: this PKI tree first, then each --extra-pki-dir. Each source
# is a separate password group because each tree has its own keychain.
SM_DIRS=("${PKI_ROOT}")
SM_GROUPS=(smime)
for d in "${EXTRA_DIRS[@]}"; do
    base="smime-${d##*/}"
    g="${base}"
    n=2
    while [[ " ${SM_GROUPS[*]} " == *" ${g} "* ]]; do
        g="${base}-${n}"
        n=$((n + 1))
    done
    SM_DIRS+=("${d}")
    SM_GROUPS+=("${g}")
done

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

# confirm MESSAGE: yes/no question; PKI_ASSUME_YES (not 0) answers yes.
confirm() {
    local reply

    if [ "${PKI_ASSUME_YES:-0}" != "0" ]; then
        return 0
    fi
    {
        printf '%s [y/N] ' "$1" >/dev/tty
        IFS= read -r reply </dev/tty
    } 2>/dev/null || return 1
    [[ "${reply}" =~ ^[Yy]$ ]]
}

cert_serial() {
    "${OPENSSL}" x509 -noout -serial -in "$1" | sed 's|^serial=||' | tr '[:lower:]' '[:upper:]'
}

cert_is_current() {
    "${OPENSSL}" x509 -checkend 0 -noout -in "$1" >/dev/null 2>&1
}

cert_enddate() {
    "${OPENSSL}" x509 -noout -enddate -in "$1" | sed 's|^notAfter=||'
}

# date_epoch "Oct  3 08:32:07 2026 GMT" -> seconds since the epoch
date_epoch() {
    date -u -d "$1" +%s 2>/dev/null || date -u -j -f '%b %e %T %Y %Z' "$1" +%s
}

cert_enddate_epoch() {
    date_epoch "$(cert_enddate "$1")"
}

# cert_cn CERT: the common name, reduced to characters that are safe in a
# file name
cert_cn() {
    local cn

    cn=$("${OPENSSL}" x509 -noout -subject -nameopt multiline,utf8 -in "$1" | sed -n 's/^ *commonName *= //p' | head -n 1)
    cn=$(printf '%s' "${cn}" | tr -c 'A-Za-z0-9 ._@+=,()-' '_' | sed -e 's/  */ /g' -e 's/^[ ._-]*//' -e 's/ *$//' | cut -c1-80)
    printf '%s' "${cn:-certificate}"
}

# cert_expiry_date CERT: notAfter as YYYY-MM-DD (UTC)
cert_expiry_date() {
    local epoch

    epoch=$(cert_enddate_epoch "$1")
    date -u -d "@${epoch}" +%Y-%m-%d 2>/dev/null || date -u -r "${epoch}" +%Y-%m-%d
}

# cert_file_name CERT: "<common name> :: <expiry date> :: <last six of sha1>",
# the name (without extension) of a certificate's files in the payload. The
# installer reads the name and the expiry back out of it for its prompts.
cert_file_name() {
    local sha1

    sha1=$(cert_sha1 "$1")
    printf '%s :: %s :: %s' "$(cert_cn "$1")" "$(cert_expiry_date "$1")" "${sha1: -6}"
}

# parse_name NAME: split a file name made by cert_file_name into CN, EXPIRY, ID
parse_name() {
    local rest

    CN="${1%% :: *}"
    rest="${1#* :: }"
    EXPIRY="${rest%% :: *}"
    ID="${rest#* :: }"
}

# describe NAME [NOTE]: 'CN' (expires DATE, id ID) [NOTE]
describe() {
    local when=expires

    parse_name "$1"
    if [[ "${EXPIRY}" < "$(date +%Y-%m-%d)" ]]; then
        when=EXPIRED
    fi
    printf "'%s' (%s %s, id %s)" "${CN}" "${when}" "${EXPIRY}" "${ID}"
    if [ -n "${2:-}" ]; then
        printf ' [%s]' "$2"
    fi
}

# verify_error OUTPUT: the first "error N at D depth lookup: ..." message
verify_error() {
    local e

    e=$(printf '%s\n' "$1" | sed -n 's/^error [0-9]* at [0-9]* depth lookup: //p' | head -n 1)
    printf '%s' "${e:-does not verify}"
}

verify_root() {
    [ -f "${ROOT_CERT}" ] || die "root certificate '${ROOT_CERT}' not found."
    "${OPENSSL}" verify -CAfile "${ROOT_CERT}" "${ROOT_CERT}" >/dev/null 2>&1 \
        || die "root certificate '${ROOT_CERT}' does not verify (expired?)."
}

# ---------------------------------------------------------------------
# Trust context: what every certificate is validated against. Built from
# this PKI tree and from each --extra-pki-dir tree (the same layout).
#   ANCHORS  root certificates that verify now
#   CRL_ALL  unexpired CRLs from root/ and intermediate/ (CRL_PEMS: one each)
#   INTS     intermediates the root accepts now (with its CRL)
#   INT_MAIN those of them that are in this PKI tree
# ---------------------------------------------------------------------

collect_anchors() {
    local tree r

    ANCHORS="${STAGE}/trust/anchors.pem"
    ANCHOR_COUNT=0
    : > "${ANCHORS}"
    for tree in "${SM_DIRS[@]}"; do
        r="${tree}/root/certs/root.cert.pem"
        [ -f "${r}" ] || continue
        if ! cert_is_ca "${r}"; then
            warn "ignoring root certificate ${r}: not a CA certificate (basicConstraints)"
        elif "${OPENSSL}" verify -CAfile "${r}" "${r}" >/dev/null 2>&1; then
            cat "${r}" >> "${ANCHORS}"
            ANCHOR_COUNT=$((ANCHOR_COUNT + 1))
        else
            warn "ignoring root certificate ${r}: does not verify (expired?)"
        fi
    done
}

collect_crls() {
    local tree f out next n=0 now candidates=()

    CRL_ALL="${STAGE}/trust/crls.pem"
    CRL_PEMS=()
    now=$(date +%s)

    for tree in "${SM_DIRS[@]}"; do
        candidates+=("${tree}"/root/crl/* "${tree}"/root/*.crl "${tree}"/root/*.crl.pem
                     "${tree}"/intermediate/crl/* "${tree}"/intermediate/*.crl "${tree}"/intermediate/*.crl.pem
                     "${tree}"/intermediate_smime/crl/* "${tree}"/intermediate_smime/*.crl
                     "${tree}"/intermediate_smime/*.crl.pem)
    done
    if [ -n "${PKI_ROOT_CRL:-}" ]; then
        candidates+=("${PKI_ROOT_CRL}")
    fi
    if [ -n "${PKI_INTERMEDIATE_CRL:-}" ]; then
        candidates+=("${PKI_INTERMEDIATE_CRL}")
    fi

    for f in "${candidates[@]}"; do
        [ -f "${f}" ] || continue
        n=$((n + 1))
        out="${STAGE}/trust/crl.${n}.pem"
        if grep -aq -- '-----BEGIN X509 CRL-----' "${f}"; then
            cp "${f}" "${out}"
        elif ! "${OPENSSL}" crl -inform der -in "${f}" -out "${out}" 2>/dev/null; then
            continue   # not a CRL
        fi
        next=$("${OPENSSL}" crl -noout -nextupdate -in "${out}" 2>/dev/null | sed 's|^nextUpdate=||') || true
        if [ -n "${next}" ] && [ "$(date_epoch "${next}")" -le "${now}" ]; then
            warn "ignoring expired CRL ${f}"
            continue
        fi
        CRL_PEMS+=("${out}")
    done

    [ "${#CRL_PEMS[@]}" -gt 0 ] \
        || die "no unexpired CRL found in root/crl or intermediate/crl; create them with bin/create_crl.sh, or set PKI_ROOT_CRL / PKI_INTERMEDIATE_CRL."
    cat "${CRL_PEMS[@]}" > "${CRL_ALL}"
}

collect_intermediates() {
    local i tree f sha1 out seen=" "

    INTS="${STAGE}/trust/intermediates.pem"
    INT_MAIN=()
    : > "${INTS}"

    for i in "${!SM_DIRS[@]}"; do
        tree="${SM_DIRS[i]}"
        if [ "${i}" -eq 0 ]; then
            tree=.
        fi
        for f in "${tree}/intermediate/certs/intermediate.cert.pem" "${tree}"/intermediate/certs/*.cert.pem \
                 "${tree}/intermediate_smime/certs/intermediate_smime.cert.pem" \
                 "${tree}"/intermediate_smime/certs/*.cert.pem; do
            [ -f "${f}" ] || continue
            f=${f#./}

            sha1=$(cert_sha1 "${f}")
            case "${seen}" in
                *" ${sha1} "*) continue ;;
            esac
            seen="${seen}${sha1} "

            if out=$("${OPENSSL}" verify -crl_check -CRLfile "${CRL_ALL}" -CAfile "${ANCHORS}" "${f}" 2>&1); then
                cat "${f}" >> "${INTS}"
                if [ "${i}" -eq 0 ]; then
                    INT_MAIN+=("${f}")
                fi
            else
                warn "ignoring intermediate ${f}: $(verify_error "${out}")"
            fi
        done
    done
}

# collect_index_args: --index FILE for each tree's S/MIME and TLS intermediate.
collect_index_args() {
    local tree f

    INDEX_ARGS=()
    for tree in "${SM_DIRS[@]}"; do
        for f in "${tree}/intermediate_smime/index.txt" "${tree}/intermediate/index.txt"; do
            if [ -f "${f}" ]; then
                INDEX_ARGS+=(--index "${f}")
            fi
        done
    done
    [ "${#INDEX_ARGS[@]}" -gt 0 ] || die "no intermediate index.txt found; cannot check revocation status."
}

# Every installer is signed and carries the root and the intermediate, so
# the trust context is always needed.
build_trust_context() {
    mkdir -p "${STAGE}/trust"
    collect_anchors
    if [ "${ANCHOR_COUNT}" -eq 0 ]; then
        die "no valid root certificate to validate against (${ROOT_CERT})."
    fi
    collect_crls
    collect_intermediates
    # roots + valid intermediates, and every issuer database, for pki_validate.py
    CA_BUNDLE="${STAGE}/trust/ca_bundle.pem"
    cat "${ANCHORS}" "${INTS}" > "${CA_BUNDLE}"
    collect_index_args
}

# Sets INTERMEDIATE_PEM to the valid intermediate of this tree expiring last.
pick_main_intermediate() {
    local d="$1" f epoch best_epoch=0

    INTERMEDIATE_PEM=""
    for f in "${INT_MAIN[@]}"; do
        [[ "${f}" == "${d}"/* ]] || continue
        epoch=$(cert_enddate_epoch "${f}")
        if [ -z "${INTERMEDIATE_PEM}" ] || [ "${epoch}" -gt "${best_epoch}" ]; then
            INTERMEDIATE_PEM="${f}"
            best_epoch="${epoch}"
        fi
    done
    [ -n "${INTERMEDIATE_PEM}" ]   # fails if DIR has no valid intermediate; callers decide
}

# verify_chain [options] CERT: verify CERT against the root through the valid
# intermediates, checking the CRLs of the whole chain.
verify_chain() {
    "${OPENSSL}" verify -x509_strict -crl_check_all -CRLfile "${CRL_ALL}" -CAfile "${ANCHORS}" \
        -untrusted "${INTS}" "$@" 2>&1
}

# validate_smime_cert CERT ROLE: 0 accepted, 1 rejected; sets CERT_STATE.
# ROLE is the file-name role (signature|encryption); policy: bin/pki_validate.py.
validate_smime_cert() {
    local f="$1" role="$2" extra="${3:-0}" args=()

    if [ "${role}" = encryption ]; then
        if [ "${ALLOW_EXPIRED_ENC}" = 1 ]; then args+=(--allow-expired); fi
        if [ "${ALLOW_SUPERSEDED_ENC}" = 1 ]; then args+=(--allow-superseded); fi
        if [ "${ALLOW_SIG_ENC}" = 1 ] && [ "${extra}" = 1 ]; then
            args+=(--allow-signature-with-encryption)   # extra trees only
        fi
    fi
    if CERT_STATE=$("${PYTHON}" "${SCRIPT_DIR}/pki_validate.py" "${role}" "${f}" \
            --ca-bundle "${CA_BUNDLE}" --crl-bundle "${CRL_ALL}" \
            "${INDEX_ARGS[@]}" ${args[@]+"${args[@]}"} 2>"${STAGE}/validate.err"); then
        if [ "${CERT_STATE}" != valid ]; then
            warn "accepting ${CERT_STATE} ${role} certificate ${f} (for decrypting old mail only)"
        fi
        return 0
    fi
    warn "rejecting ${f}: $(cat "${STAGE}/validate.err")"
    return 1
}

# p12_password P12 CERT TREE: set P12PW to the password that opens the .p12: its key's
# keychain entry (the main tree's, or an extra tree's keepassxc/keychain).
# Returns 1 if there is none or it does not open the .p12.
p12_password() {
    local p12="$1" cert="$2" tree="$3" pw

    P12PW=""
    if [ "${tree}" = "${PKI_ROOT}" ]; then
        pw=$(pki_kc get --cert "${cert}" --field p12 2>/dev/null) || return 1
    else
        [ -d "${tree}/keepassxc/keychain" ] || return 1
        pw=$(PKI_KEYCHAIN_DIR="${tree}/keepassxc/keychain" PKI_KEYCHAIN_KEYFILE="${tree}/keepassxc/keyfile/pki-structure.keyx" \
                 pki_kc get --cert "${cert}" --field p12 2>/dev/null) || return 1
    fi
    [ -n "${pw}" ] || return 1
    "${OPENSSL}" pkcs12 -legacy -noout -in "${p12}" -passin fd:3 \
        3< <(printf '%s\n' "${pw}") >/dev/null 2>&1 || return 1
    P12PW="${pw}"
}

# p12_check_content P12 PASSWORD CERT: succeeds if the .p12 holds CERT (read from inside
# it) and the private key that belongs to it. On failure prints the reason, returns 1.
p12_check_content() {
    local p12="$1" pw="$2" cert="$3" tmp="${STAGE}/p12check.pem" ck pk

    if ! "${OPENSSL}" pkcs12 -legacy -in "${p12}" -clcerts -nokeys -passin fd:3 -out "${tmp}" \
            3< <(printf '%s\n' "${pw}") 2>/dev/null; then
        echo "cannot read the certificate inside it"
        return 1
    fi
    if ! grep -q 'BEGIN CERTIFICATE' "${tmp}"; then
        echo "it holds no certificate paired with a private key"
        return 1
    fi
    if [ "$(cert_sha1 "${tmp}")" != "$(cert_sha1 "${cert}")" ]; then
        echo "it holds a different certificate than ${cert}"
        return 1
    fi

    ck=$("${OPENSSL}" x509 -noout -pubkey -in "${tmp}")
    pk=$("${OPENSSL}" pkcs12 -legacy -in "${p12}" -nocerts -nodes -passin fd:3 \
             3< <(printf '%s\n' "${pw}") 2>/dev/null | "${OPENSSL}" pkey -pubout 2>/dev/null) || true
    if [ -z "${pk}" ] || [ "${pk}" != "${ck}" ]; then
        echo "its private key does not belong to its certificate"
        return 1
    fi
}

# stage_p12_password PW DEST: write PW alone to DEST (mode 0600 by umask).
stage_p12_password() {
    [ -n "$1" ] || die "empty .p12 password"
    printf '%s\n' "$1" > "$2"
}

# ---------------------------------------------------------------------
# The signature
# ---------------------------------------------------------------------

# find_codesign_signer -- pick the code-signing certificate for create_credentials.sh.
#
# Bash counterpart of find_signer() in configurate_yaml.py:
# the NEWEST certificate named ${CODESIGN_NAME}.<sha1>.cert.pem in
# ${CODESIGN_DIR}/certs that is
#   * in date (not expired, not yet valid),
#   * 'V' in the issuing CA's index.txt (revoked, superseded and 'E'
#     certificates are never accepted for signing),
#   * allowed to sign code (ExtendedKeyUsage, when present),
#   * verified against the root through a valid, verified intermediate with
#     the CRLs of the whole chain checked (verify_chain).
# Sets SIGNER_CERT, SIGNER_SHA1, SIGNER_KEY, SIGNER_PASSFILE. PKI_CODESIGN_SHA1
# (optional) picks one specific signer. ISSUERCADIR (default intermediate)
# names the CA whose index.txt is consulted.

# codesign_index_status INDEX SERIAL -> V, R, E, other status letter, or none
codesign_index_status() {
    awk -F'\t' -v s="$2" '
        BEGIN { sub(/^0+/, "", s) }
        { a = toupper($4); sub(/^0+/, "", a) }
        a == s { print $1; found = 1; exit }
        END { if (!found) print "none" }' "$1"
}

find_codesign_signer() {
    local certdir=${CODESIGN_DIR:-codesign}
    local certname=${CODESIGN_NAME:-codesign}
    local want=${PKI_CODESIGN_SHA1:-}
    local idx="${ISSUERCADIR:-intermediate}/index.txt"
    local f b sha1 st out eku epoch best_epoch=0 now usable=0 why

    SIGNER_CERT="" SIGNER_SHA1="" SIGNER_KEY="" SIGNER_PASSFILE=""

    # needs the trust context (ANCHORS, INTS, CRL_ALL): build_trust_context
    [ -s "${INTS:-}" ] \
        || die "no valid intermediate to verify the code-signing certificate with."
    [ -f "${idx}" ] \
        || die "${idx} not found; cannot check whether code-signing certificates are revoked."
    now=$(date +%s)

    for f in "${certdir}/certs/${certname}".*.cert.pem; do
        b=${f##*/}
        sha1=${b#"${certname}."}
        sha1=${sha1%.cert.pem}
        [[ "${sha1}" =~ ^[0-9a-f]{40}$ ]] || continue
        if [ -n "${want}" ] && [ "${sha1}" != "${want}" ]; then continue; fi

        why=""
        epoch=$(date_epoch "$("${OPENSSL}" x509 -noout -startdate -in "${f}" | sed 's|^notBefore=||')")
        if [ "${epoch}" -gt "${now}" ]; then
            why="not valid yet"
        elif ! cert_is_current "${f}"; then
            why="expired"
        else
            st=$(codesign_index_status "${idx}" "$(cert_serial "${f}")")
            case "${st}" in
                V) ;;
                R) why="revoked (a signing certificate is never accepted when revoked or superseded)" ;;
                E) why="index.txt status 'E' (expired)" ;;
                none) why="serial not in ${idx} (cannot confirm it is not revoked)" ;;
                *) why="index.txt status '${st}' (expected V)" ;;
            esac
        fi
        if [ -z "${why}" ]; then
            eku=$("${OPENSSL}" x509 -noout -ext extendedKeyUsage -in "${f}" 2>/dev/null || true)
            if ! grep -qi 'Code Signing' <<<"${eku}"; then
                why="ExtendedKeyUsage does not include codeSigning"
            fi
        fi
        if [ -z "${why}" ]; then
            # chain, CRLs, index.txt, EKUs incl. the issuing CA's (one validator)
            if ! out=$("${PYTHON}" "${SCRIPT_DIR}/pki_validate.py" codesign "${f}" \
                           --ca-bundle "${CA_BUNDLE}" --crl-bundle "${CRL_ALL}" \
                           "${INDEX_ARGS[@]}" 2>&1); then
                why="${out}"
            fi
        fi
        if [ -n "${why}" ]; then
            warn "skipping code-signing certificate ${b}: ${why}"
            continue
        fi

        usable=$((usable + 1))
        if [ "${epoch}" -gt "${best_epoch}" ]; then   # newest notBefore wins
            best_epoch=${epoch}
            SIGNER_CERT=${f}
            SIGNER_SHA1=${sha1}
        fi
    done

    if [ -z "${SIGNER_CERT}" ]; then
        die "no usable code-signing certificate '${certname}.<sha1>.cert.pem' in ${certdir}/certs${want:+ with sha1 ${want}} (see the reasons above)."
    fi
    if [ "${usable}" -gt 1 ]; then
        echo "Note: ${usable} usable code-signing certificates; using the newest" >&2
        echo "(${SIGNER_SHA1})." >&2
        echo "Set PKI_CODESIGN_SHA1 to override." >&2
    fi

    SIGNER_KEY="${certdir}/private/${certname}.${SIGNER_SHA1}.key.pem"
    
    [ -f "${SIGNER_KEY}" ] || die "missing ${SIGNER_KEY}"
    
    echo "Code-signing certificate: ${SIGNER_CERT}" >&2
}

# load_codesign: the certificate that signs the installer: the newest valid
# ${CODESIGN_NAME}.<sha1>.cert.pem (find_codesign_signer). Sets CS_CERT,
# CS_KEY. It must verify against the root
# through a valid intermediate, with the CRLs checked, and allow code signing.
load_codesign() {
    local f out text

    find_codesign_signer
    CS_CERT="${SIGNER_CERT}"
    CS_KEY="${SIGNER_KEY}"
    
    for f in "${CS_CERT}" "${CS_KEY}"; do
        [ -f "${f}" ] \
            || die "'${f}' not found. The installer is signed with the code signing certificate (PKI_CODESIGN_DIR, PKI_CODESIGN_NAME)."
    done
    if ! out=$(verify_chain "${CS_CERT}"); then
        die "code signing certificate ${CS_CERT}: $(verify_error "${out}")"
    fi
    text=$("${OPENSSL}" x509 -noout -ext extendedKeyUsage -in "${CS_CERT}" 2>/dev/null) || text=""
    [[ "${text}" == *"Code Signing"* ]] \
        || die "${CS_CERT} does not allow code signing (extendedKeyUsage)."
    if cert_is_ca "${CS_CERT}"; then
        die "${CS_CERT} is a CA certificate."
    fi
}

# sign_content CONTENT SIG: detached PKCS#7 signature (DER) of CONTENT. The
# signer's certificate, the valid intermediates and the root go into the
# signature, so the installer can authenticate before it opens the payload.
sign_content() {
    cat "${INTS}" "${ROOT_CERT}" > "${STAGE}/trust/sigchain.pem"
    "${OPENSSL}" smime -sign -binary -md sha256 -in "$1" \
        -signer "${CS_CERT}" -inkey "${CS_KEY}" -passin fd:3 3< <(pki_kc get --cert "${CS_CERT}") \
        -certfile "${STAGE}/trust/sigchain.pem" -outform DER -out "$2"
    # self-check, as the installer will do it
    "${OPENSSL}" smime -verify -binary -inform DER -in "$2" -content "$1" \
        -CAfile "${ANCHORS}" -purpose any -out /dev/null 2>/dev/null \
        || die "the signature made with ${CS_CERT} does not verify (key does not match the certificate?)."
}

# ---------------------------------------------------------------------
# Staging the payload
# ---------------------------------------------------------------------

MANIFEST="${STAGE}/common/manifest"

# stage_ca_cert TYPE GROUP PEM
# TYPE is root or ca. The public certificate goes to ${CA_DOMAIN}/ in the
# payload (system/ or user/), as DER, named by cert_file_name. The root is
# trusted from it. No private key is ever staged for a CA.
stage_ca_cert() {
    local type="$1" group="$2" pem="$3" name sha1

    name=$(cert_file_name "${pem}")
    sha1=$(cert_sha1 "${pem}")
    [ ! -e "${STAGE}/common/${CA_DOMAIN}/${name}.cer" ] \
        || die "payload file name '${name}' is used twice (the same certificate, or a clash of the last six sha1 digits)."

    "${OPENSSL}" x509 -outform der -in "${pem}" -out "${STAGE}/common/${CA_DOMAIN}/${name}.cer"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${CA_DOMAIN}-${type}" "${group}" "${sha1}" 0 "${name}" "" >> "${MANIFEST}"
}

# stage_ca_dir DIR: stage every unexpired certificate in DIR/certs as a
# public CA certificate (its private key is never included).
stage_ca_dir() {
    local d="$1" f sha1 seen=" " found=0
    local files=("${d}"/certs/*.cert.pem)

    if [ "${#files[@]}" -eq 0 ]; then
        echo "Note: no certificates exist in '${d}/certs'; none will be included in the payload." >&2
        return 0
    fi

    for f in "${files[@]}"; do
        sha1=$(cert_sha1 "${f}")
        case "${seen}" in
            *" ${sha1} "*) continue ;;
        esac
        seen="${seen}${sha1} "

        # a self-signed CA: must say CA:TRUE and verify against itself (checks expiry)
        if ! cert_is_ca "${f}"; then
            warn "skipping ${f}: not a CA certificate (basicConstraints)"
            continue
        fi
        if ! "${OPENSSL}" verify -CAfile "${f}" "${f}" >/dev/null 2>&1; then
            warn "skipping ${f}: does not verify (expired?)"
            continue
        fi

        stage_ca_cert root "${d}" "${f}"   # a self-signed root of its own; trusted for TLS only
        found=1
    done

    if [ "${found}" = 0 ]; then
        warn "no usable certificates found in ${d}/certs"
    fi
}

# The CA certificates: the root, the valid intermediate and the privoxy CA.
# The root and the intermediate are required (the installer's signature is
# checked against them); the privoxy CA is skipped if it does not exist.
build_common() {
    local d f have_int=0

    mkdir -p "${STAGE}/common/${CA_DOMAIN}"
    : > "${MANIFEST}"

    [ -f "${ROOT_CERT}" ] \
        || die "the root CA (${ROOT_CERT}) does not exist; it is always included in the payload."
    verify_root
    stage_ca_cert root root "${ROOT_CERT}"

    for f in intermediate/certs/intermediate.cert.pem intermediate/certs/intermediate.*.cert.pem; do
        if [ -f "${f}" ]; then
            have_int=1
        fi
    done
    [ "${have_int}" = 1 ] \
        || die "no intermediate CA exists in intermediate/certs; it is always included in the payload."
    pick_main_intermediate intermediate \
        || die "no valid intermediate certificate found in intermediate/certs."
    echo "Using intermediate: ${INTERMEDIATE_PEM}" >&2
    stage_ca_cert ca intermediate "${INTERMEDIATE_PEM}"
    # The S/MIME intermediate (emailProtection only) validates the S/MIME
    # certificates; it is included whenever it exists.
    if pick_main_intermediate intermediate_smime; then
        echo "Using S/MIME intermediate: ${INTERMEDIATE_PEM}" >&2
        stage_ca_cert ca intermediate_smime "${INTERMEDIATE_PEM}"
    else
        echo "Note: no valid intermediate_smime certificate;" >&2
        echo "S/MIME certificates cannot validate." >&2
    fi

    # opt-in: the privoxy CA is for TLS interception on proxy clients only
    if [ "${WITH_PRIVOXY}" = 1 ]; then
        for d in ${PRIVOXY_DIRS}; do
            stage_ca_dir "${d}"
        done
    fi
}

# S/MIME certificate names (the part before -signature/-encryption) found in
# any source tree.
list_smime_certnames() {
    local sd f b

    for sd in "${SM_DIRS[@]}"; do
        for f in "${sd}"/smime/certs/*.cert.pem; do
            b=${f##*/}
            if [[ "${b}" =~ ${SMIME_RE} ]]; then
                echo "${BASH_REMATCH[1]}"
            fi
        done
    done | sort -u
}

# expand_name_glob GLOB -> one pattern per line. Only brace expansion is
# performed here (noglob); GLOB was checked against NAME_GLOB_RE.
expand_name_glob() {
    ( set -f; eval "printf '%s\\n' $1" )
}

# select_certnames GLOB -> SEL_CERTNAMES: the certificate names matching GLOB.
# Returns 1 if none match.
select_certnames() {
    local p c patterns=()

    SEL_CERTNAMES=()
    while IFS= read -r p; do
        patterns+=("${p}")
    done < <(expand_name_glob "$1")

    for c in "${ALL_CERTNAMES[@]}"; do
        for p in "${patterns[@]}"; do
            # shellcheck disable=SC2053
            if [[ "${c}" == ${p} ]]; then
                SEL_CERTNAMES+=("${c}")
                break
            fi
        done
    done
    [ "${#SEL_CERTNAMES[@]}" -gt 0 ]
}

# installer_name GLOB -> GLOB with glob characters spelled out, so that file
# names are free of them: * S, ? Q, { LB, } RB, [ LBK, ] RBK, comma C,
# ! and ^ N.
installer_name() {
    local in="$1" out="" ch i

    for ((i = 0; i < ${#in}; i++)); do
        ch="${in:i:1}"
        case "${ch}" in
            '*') out+=S ;;
            '?') out+=Q ;;
            '{') out+=LB ;;
            '}') out+=RB ;;
            '[') out+=LBK ;;
            ']') out+=RBK ;;
            ',') out+=C ;;
            '!'|'^') out+=N ;;
            *) out+="${ch}" ;;
        esac
    done
    printf '%s' "${out}"
}

# build_payload_dir -> ${STAGE}/payload: the staged system items plus the
# S/MIME .p12 files of SEL_CERTNAMES from every source, each with its
# .p12.pass; sets SMIME_COUNT
build_payload_dir() {
    local dir="${STAGE}/payload" i sd group src f b certname ext role why sha1 name p12 pf line rc state seen=" " count=0 rejected=0
    local psrc pwfile pwid grp

    rm -rf "${dir}"
    mkdir -p "${dir}/smime"
    cp -R "${STAGE}/common/." "${dir}/"

    for i in "${!SM_DIRS[@]}"; do
        sd="${SM_DIRS[i]}"
        group="${SM_GROUPS[i]}"
        src=""
        if [ "${i}" -gt 0 ]; then
            src=" [from ${sd##*/}]"
        fi

        for f in "${sd}"/smime/certs/*.cert.pem; do
            b=${f##*/}
            [[ "${b}" =~ ${SMIME_RE} ]] || continue
            certname="${BASH_REMATCH[1]}"
            ext="${BASH_REMATCH[2]}"

            case " ${SEL_CERTNAMES[*]} " in
                *" ${certname} "*) ;;
                *) continue ;;
            esac

            p12="${sd}/smime/private/${b%.cert.pem}.p12"
            if [ ! -f "${p12}" ]; then
                warn "${f} has no ${p12}; skipping"
                continue
            fi

            sha1=$(cert_sha1 "${f}")
            case "${seen}" in
                *" ${sha1} "*) continue ;;
            esac
            seen="${seen}${sha1} "

            # the .p12 must open with its keychain password and hold this certificate with its key
            if ! p12_password "${p12}" "${f}" "${sd}"; then
                warn "skipping ${p12}: no keychain entry opens it"
                rejected=$((rejected + 1))
                continue
            fi
            if ! why=$(p12_check_content "${p12}" "${P12PW}" "${f}"); then
                warn "skipping ${p12}: ${why}"
                rejected=$((rejected + 1))
                continue
            fi
            # one password per issuance
            pwid=$(printf '%s' "${P12PW}" | "${OPENSSL}" dgst -sha256 | sed 's/.*= *//' | cut -c1-6)
            grp="${group}/${certname}/${pwid}"

            # the name gives the role; a keyUsage that does not fit it is rejected
            role="${ext}"

            # must verify against the root through a valid intermediate, CRLs checked
            if ! validate_smime_cert "${f}" "${role}" "$((i > 0))"; then
                rejected=$((rejected + 1))
                continue
            fi
            state="${CERT_STATE}"

            name=$(cert_file_name "${f}")
            [ ! -e "${dir}/smime/${name}.p12" ] \
                || die "payload file name '${name}' is used twice (a clash of the last six sha1 digits)."
            cp "${p12}" "${dir}/smime/${name}.p12"
            # the secret that opens this .p12; the payload is encrypted
            stage_p12_password "${P12PW}" "${dir}/smime/${name}.p12.pass"
            printf 'smime\t%s\t%s\t1\t%s\t%s\n' "${grp}" "${sha1}" "${name}" \
                   "${role}, ${state}${src}" >> "${dir}/manifest"
            count=$((count + 1))
        done
    done

    SMIME_COUNT="${count}"
    echo "${count} S/MIME certificate(s) selected, ${rejected} rejected" >&2
}

# show_payload OUT DIR: list what goes into the tar payload
show_payload() {
    local out="$1" dir="$2" type group sha1 haskey file note kind keys=0 items=0 pws=0 f

    echo >&2
    echo "${out} will contain:" >&2
    while IFS=$'\t' read -r -u 3 type group sha1 haskey file note; do
        kind="certificate"
        if [ "${haskey}" = 1 ]; then
            kind="PRIVATE KEY"
            keys=$((keys + 1))
        fi
        items=$((items + 1))
        printf '  %-12s %-11s %s\n' "${kind}" "${type}" "$(describe "${file}" "${note}")" >&2
    done 3< "${dir}/manifest"
    if [ "${ENCRYPT}" = 1 ]; then
        for f in "${dir}"/smime/*.p12.pass; do
            pws=$((pws + 1))
        done
        echo "  ${items} item(s), ${keys} private key(s), ${pws} SECRET .p12 password file(s)." >&2
        echo "  The payload will be encrypted with a new installer password, stored in the" >&2
        echo "  PKI keychain as '${out##*/}'." >&2
    else
        echo "  ${items} item(s), ${keys} private key(s); no passwords are included." >&2
    fi
    echo "  Signed with: '$(cert_cn "${CS_CERT}")' (expires $(cert_expiry_date "${CS_CERT}"))" >&2
}

# write_installer LABEL DIR OUT TARNAME [PASSWORD]
# Layout of OUT: the script, __SIGNATURE_BELOW__, the base64 signature,
# __PAYLOAD_BELOW__, the base64 payload. The signature covers everything but
# its own lines. With a PASSWORD the tar.xz is encrypted with it (openssl
# enc); the password goes to openssl on fd 3, never in argv or the
# environment.
write_installer() {
    local label="$1" dir="$2" out="$3" tarname="$4" password="${5:-}"
    local head="${STAGE}/installer.head" payload="${STAGE}/installer.payload"
    local content="${STAGE}/installer.content" sig="${STAGE}/installer.sig"

    export COPYFILE_DISABLE=1   # no AppleDouble files in the tar on macOS
    {
        printf '#!/usr/bin/env bash\n'
        printf '# Credentials installer: %s\n' "${label}"
        printf '# Generated %s. No passwords are stored in this file.\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '\n'
        # label and tarname contain only validated characters (NAME_GLOB_RE
        # and installer_name), so plain double quotes are enough. The
        # PAYLOAD_ENCRYPTED, ENC_CIPHER and ENC_ITER lines must stay within
        # the first 20 lines: create_keepass_entry.sh reads them there.
        printf 'INSTALL_FOR="%s"\n' "${label}"
        printf 'SYSTEM_KEYCHAIN="%s"\n' /Library/Keychains/System.keychain
        printf 'TAR_NAME="%s"\n' "${tarname}"
        if [ -n "${password}" ]; then
            printf 'PAYLOAD_ENCRYPTED=1\n'
            printf 'ENC_CIPHER="%s"\n' "${ENC_CIPHER}"
            printf 'ENC_ITER="%s"\n' "${ENC_ITER}"
        else
            printf 'PAYLOAD_ENCRYPTED=0\n'
        fi
        cat <<'INSTALLER'

set -eo pipefail
umask 077


usage() {
    cat <<USAGE
Usage: $(basename "$0") [--system-only | --user-only] [--list] [--tar-only] [--check-signature-integrity]

Installs the credentials bundled in this script (${INSTALL_FOR}).
Run it as yourself (not with sudo); sudo is requested only for the System keychain.

  --system-only  only the System keychain items (sudo)
  --user-only    only the login keychain items: S/MIME identities, and the
                 CA certificates if the payload has them in user/ (no sudo)
  --list         show what is included and exit
  --tar-only     only write the payload (still encrypted, if it is) to
                 ./${TAR_NAME} and exit
  --check-signature-integrity
                 only check the signature of this script against the root
                 and intermediates in its signature block and exit: 0 if
                 valid, non-zero if not. No password, nothing decrypted or
                 unpacked, root not anchored. Needs only openssl.
                 For an untrusted copy use bin/verify_installer.sh

Before anything is installed, the signature of this script is checked: it
must come from a code signing certificate that chains to the root CA in its
signature block, before the payload is decrypted or unpacked. If that root is not already installed on this machine, you are
asked to compare its SHA-256 fingerprint with one you received separately;
set PKI_ROOT_SHA256 to that fingerprint to have it checked for you
(PKI_ASSUME_YES alone never accepts an unknown root).

You are asked (y/N) before each certificate is added; set PKI_ASSUME_YES=1
to answer yes to everything. A .p12 password the payload does not hold is
asked for when needed; to avoid the prompt set PKI_P12_PASSWORD_<GROUP>, for
example PKI_P12_PASSWORD_SMIME (GROUP is the name shown in the prompt,
upper-cased, with other characters replaced by _).

An encrypted payload (PAYLOAD_ENCRYPTED=1 in this script) asks for the
installer password, which the sender provides separately. It is read from the
terminal only, never from the environment, and it also supplies the .p12
passwords, which are inside the payload.
USAGE
}


# confirm MESSAGE: yes/no question; PKI_ASSUME_YES (not 0) answers yes.
confirm() {
    local reply

    if [ "${PKI_ASSUME_YES:-0}" != "0" ]; then
        printf '%s [y/N] y (PKI_ASSUME_YES)\n' "$1"
        return 0
    fi
    {
        printf '%s [y/N] ' "$1" >/dev/tty
        IFS= read -r reply </dev/tty
    } 2>/dev/null || return 1
    [[ "${reply}" =~ ^[Yy]$ ]]
}


# The keychain listings are long: read them into a variable, so that grep -q
# cannot close the pipe early and fail the pipeline under pipefail.

# der_sha256 FILE: SHA-256 (hex) of a DER certificate, computed from the bytes,
# never taken from the manifest
der_sha256() {
    openssl x509 -inform der -in "$1" -outform der 2>/dev/null \
        | openssl dgst -sha256 | sed 's/^.*= *//'
}


# kc_has_cert KEYCHAIN SHA256: true if a certificate in KEYCHAIN has this
# SHA-256, computed here from each certificate's own bytes
kc_has_cert() {
    local line buf="" want="$2" h

    [ -n "${want}" ] || return 1
    while IFS= read -r line; do
        case "${line}" in
            *"BEGIN CERTIFICATE"*)
                buf="${line}"$'\n'
                ;;
            *"END CERTIFICATE"*)
                buf+="${line}"$'\n'
                h=$(printf '%s' "${buf}" | openssl x509 -outform der 2>/dev/null \
                        | openssl dgst -sha256 | sed 's/^.*= *//')
                if [ "${h}" = "${want}" ]; then
                    return 0
                fi
                buf=""
                ;;
            *)
                if [ -n "${buf}" ]; then
                    buf+="${line}"$'\n'
                fi
                ;;
        esac
    done < <(security find-certificate -a -p "$1" 2>/dev/null)
    return 1
}


# kc_has_identity KEYCHAIN SHA1 (certificate with its private key)
kc_has_identity() {
    local out

    out=$(security find-identity "$1" 2>/dev/null) || true
    grep -qi " $2 " <<<"${out}"
}


# login_keychain: path of the user's login keychain
login_keychain() {
    local k="${HOME}/Library/Keychains/login.keychain-db"

    if [ ! -f "${k}" ]; then
        k="${HOME}/Library/Keychains/login.keychain"
    fi
    printf '%s' "${k}"
}


# sec_quote WORD: WORD quoted for `security -i`, which reads commands from
# stdin, so a password never appears in argv.
sec_quote() {
    local s=${1//\\/\\\\}

    printf '"%s"' "${s//\"/\\\"}"
}


# import_into_keychain USE_SUDO(0|1) KEYCHAIN FILE PASSWORD [extra security args]
# An item that is already present counts as success.
import_into_keychain() {
    local use_sudo="$1" keychain="$2" file="$3" password="$4" out rc=0 nl=$'\n'
    local words=(import "${file}" -k "${keychain}") w line="" cmd=(security -i)

    shift 4
    if [ -n "${password}" ]; then
        words+=(-P "${password}")
    fi
    words+=("$@")
    for w in "${words[@]}"; do
        line+="$(sec_quote "${w}") "
    done
    if [ "${use_sudo}" = 1 ]; then
        cmd=(sudo "${cmd[@]}")
    fi

    # `security -i` reports errors on stderr and may still exit 0
    out=$(printf '%s\n' "${line}" | "${cmd[@]}" 2>&1) || rc=$?
    if [ "${rc}" -ne 0 ] || [[ "${out}" == *"security:"* ]]; then
        case "${out}" in
            *"already exists"*)
                echo "    already present"
                return 0
                ;;
        esac
        printf '    %s\n' "${out//${nl}/${nl}    }" >&2
        return 1
    fi
    echo "    imported"
}


# p12_label FILE PASSWORD: the label macOS gives the key it imports from FILE:
# the certificate's common name. Prints nothing if it cannot be read. The
# password goes to openssl through the environment, never argv. Plain openssl,
# so that the macOS-native one is enough.
p12_label() {
    PKI_TMP_PW="$2" openssl pkcs12 -in "$1" -nokeys -clcerts -passin env:PKI_TMP_PW 2>/dev/null \
        | openssl x509 -noout -subject -nameopt multiline,utf8 2>/dev/null \
        | sed -n '/^ *commonName *=/{s/^ *commonName *= *//p;q;}' || true
}


# get_password GROUP -> sets PASSWORD. Uses PKI_P12_PASSWORD_<GROUP> if set,
# otherwise asks once on the terminal.
get_password() {
    local group="$1" var pw

    var="PKI_P12_PASSWORD_$(printf '%s' "${group}" | tr '[:lower:]' '[:upper:]' | tr -c 'A-Z0-9' '_')"
    if [ -z "${!var:-}" ]; then
        {
            printf "Password for the '%s' .p12 files: " "${group}" >/dev/tty
            IFS= read -r -s pw </dev/tty
            printf '\n' >/dev/tty
        } 2>/dev/null || return 1
        printf -v "${var}" '%s' "${pw}"
    fi
    PASSWORD="${!var}"
}


# get_installer_password -> sets INSTALLER_PASSWORD. Read from the terminal
# only (as create_keepass_entry.sh reads its master password): not from argv,
# not from the environment.
INSTALLER_PASSWORD=""

get_installer_password() {
    local pw

    if [ ! -r /dev/tty ]; then
        echo "No terminal to ask for the installer password." >&2
        return 1
    fi
    IFS= read -r -s -p "Installer password: " pw </dev/tty \
        || return 1
    echo >&2
    [ -n "${pw}" ] || return 1
    INSTALLER_PASSWORD="${pw}"
}


# The payload: a base64 encoded tar.xz at the end of this script, after the
# __PAYLOAD_BELOW__ line. Plain openssl, so that the macOS-native one is
# enough.
payload_raw() {
    sed '1,/^__PAYLOAD_BELOW__$/d' "$0" | openssl base64 -d
}


# payload: the tar.xz, decrypted first when the payload is encrypted. The
# password reaches openssl on fd 3, never in argv.
payload() {
    if [ "${PAYLOAD_ENCRYPTED}" = 1 ]; then
        payload_raw | openssl enc -d "-${ENC_CIPHER}" -pbkdf2 -md sha256 \
            -iter "${ENC_ITER}" -pass fd:3 3< <(printf '%s\n' "${INSTALLER_PASSWORD}")
    else
        payload_raw
    fi
}


DO_SYSTEM=1
DO_USER=1
LIST=0
TAR_ONLY=0
VALIDATE_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --system-only) DO_USER=0 ;;
        --user-only) DO_SYSTEM=0 ;;
        --list) LIST=1 ;;
        --tar-only) TAR_ONLY=1 ;;
        --check-signature-integrity) VALIDATE_ONLY=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
    shift
done


if [ "${TAR_ONLY}" = 1 ]; then
    if [ -e "${TAR_NAME}" ]; then
        echo "${TAR_NAME} already exists; not overwriting it." >&2
        exit 1
    fi
    if ! payload_raw > "${TAR_NAME}.part"; then
        rm -f "${TAR_NAME}.part"
        echo "Could not decode the payload." >&2
        exit 1
    fi
    mv "${TAR_NAME}.part" "${TAR_NAME}"
    echo "Wrote ${TAR_NAME}"
    exit 0
fi

if [ "${VALIDATE_ONLY}" != 1 ] && [ "$(uname -s)" != "Darwin" ]; then
    echo "This installer is for macOS." >&2
    exit 1
fi
if [ "${VALIDATE_ONLY}" != 1 ] && [ "$(id -u)" -eq 0 ]; then
    echo "Run this as the target user, not as root: the S/MIME identities go into that user's keychain." >&2
    exit 1
fi


WORK=$(mktemp -d "${TMPDIR:-/tmp}/pki-install.XXXXXX")
trap 'rm -rf "${WORK}"' EXIT
export COPYFILE_DISABLE=1

MANIFEST="${WORK}/manifest"


FAILURES=0

fail() {
    echo "  FAILED: $*" >&2
    FAILURES=$((FAILURES + 1))
}


# parse_name NAME: split a payload file name without its extension,
# "common name :: YYYY-MM-DD :: id", into CN, EXPIRY and ID
parse_name() {
    local rest

    CN="${1%% :: *}"
    rest="${1#* :: }"
    EXPIRY="${rest%% :: *}"
    ID="${rest#* :: }"
}


# describe NAME [NOTE]: 'CN' (expires DATE, id ID) [NOTE]
describe() {
    local when=expires

    parse_name "$1"
    if [[ "${EXPIRY}" < "$(date +%Y-%m-%d)" ]]; then
        when=EXPIRED
    fi
    printf "'%s' (%s %s, id %s)" "${CN}" "${when}" "${EXPIRY}" "${ID}"
    if [ -n "${2:-}" ]; then
        printf ' [%s]' "$2"
    fi
}


list_items() {
    local type group sha1 haskey file note

    while IFS=$'\t' read -r -u 3 type group sha1 haskey file note; do
        echo "${type}: $(describe "${file}" "${note}")"
    done 3< "${MANIFEST}"
}


signature_failed() {
    echo "SIGNATURE CHECK FAILED: $1" >&2
    if [ -n "${2:-}" ]; then
        printf '%s\n' "$2" >&2
    fi
    echo "Nothing was installed. Do not use this installer." >&2
    exit 1
}


ROOT_SUBJECT=""
ROOT_PEM=""
ROOT_SHA256=""


# cert_field FILE subject|issuer: the name, without the "subject=" prefix
cert_field() {
    openssl x509 -noout "-$2" -nameopt RFC2253 -in "$1" | sed "s/^$2= *//"
}


# pem_sha256 FILE: SHA-256 (hex) of the DER bytes of a PEM certificate
pem_sha256() {
    openssl x509 -in "$1" -outform der 2>/dev/null | openssl dgst -sha256 | sed 's/^.*= *//'
}


# signer_issuer_ok SIGNER: the CA that issued SIGNER must allow codeSigning
# (`-purpose any` ignores CA EKUs). The issuer is the block certificate through
# which SIGNER verifies to the root; a CA with no EKU is refused.
signer_issuer_ok() {
    local f eku

    if openssl verify -CAfile "${ROOT_PEM}" "$1" >/dev/null 2>&1; then
        return 0   # issued by the root itself
    fi
    for f in "${WORK}"/.sigcert.*.pem; do
        [ -f "${f}" ] || continue
        openssl verify -CAfile "${ROOT_PEM}" -untrusted "${f}" "$1" \
            >/dev/null 2>&1 || continue
        eku=$(openssl x509 -noout -ext extendedKeyUsage -in "${f}" 2>/dev/null) \
            || eku=""
        case "${eku}" in
            *"Code Signing"*) return 0 ;;
        esac
    done
    return 1
}


# verify_signature: runs BEFORE the payload is decrypted or parsed. The
# detached PKCS#7 (between __SIGNATURE_BELOW__ and __PAYLOAD_BELOW__) carries
# the signer, the intermediates and the root. The signed content is all of
# this file except those lines (script text and encrypted payload). The chain
# must end at the one self-signed certificate in the block, and the signer
# must be a non-CA code signing certificate. That proves the file is intact,
# not who made it: see confirm_root_anchor.
verify_signature() {
    local signed="${WORK}/.signed" sig="${WORK}/.signature.der"
    local bundle="${WORK}/.sigcerts.pem" signer="${WORK}/.signer.pem"
    local f out text roots=0

    awk '/^__SIGNATURE_BELOW__$/ { print; skip = 1; next }
         /^__PAYLOAD_BELOW__$/ { skip = 0 }
         !skip { print }' "$0" > "${signed}"
    awk '/^__SIGNATURE_BELOW__$/ { skip = 1; next }
         /^__PAYLOAD_BELOW__$/ { skip = 0 }
         skip' "$0" | openssl base64 -d > "${sig}" 2>/dev/null || true
    [ -s "${sig}" ] || signature_failed "this installer carries no signature."

    openssl pkcs7 -inform DER -in "${sig}" -print_certs -out "${bundle}" 2>/dev/null \
        || signature_failed "the signature block is unreadable."
    awk -v p="${WORK}/.sigcert" '
        /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s.%d.pem", p, n) }
        f { print > f }
        /-----END CERTIFICATE-----/ { close(f); f = "" }' "${bundle}"

    ROOT_PEM=""
    for f in "${WORK}"/.sigcert.*.pem; do
        [ -f "${f}" ] || continue
        if [ "$(cert_field "${f}" subject)" = "$(cert_field "${f}" issuer)" ]; then
            roots=$((roots + 1))
            ROOT_PEM=${f}
        fi
    done
    [ "${roots}" -eq 1 ] \
        || signature_failed "the signature block must carry exactly one self-signed root CA certificate (found ${roots})."

    if ! out=$(openssl smime -verify -binary -inform DER -in "${sig}" -content "${signed}" \
                   -CAfile "${ROOT_PEM}" -purpose any -signer "${signer}" -out /dev/null 2>&1); then
        signature_failed "this installer was changed after it was signed, or was not signed by a certificate that chains to the root CA in its signature block." "${out}"
    fi
    # EKU and basicConstraints only: -text would also match the subject
    # (OU=... Code Signing). -purpose any above checks the chain, not the EKU.
    text=$(openssl x509 -noout -ext extendedKeyUsage -in "${signer}" 2>/dev/null) || text=""
    case "${text}" in
        *"Code Signing"*) ;;
        *) signature_failed "the signer's extendedKeyUsage does not include codeSigning." ;;
    esac
    text=$(openssl x509 -noout -ext basicConstraints -in "${signer}" 2>/dev/null) || text=""
    case "${text}" in
        *"CA:TRUE"*) signature_failed "the signer is a CA certificate." ;;
    esac
    signer_issuer_ok "${signer}" \
        || signature_failed "the signer's issuing CA does not allow codeSigning."

    ROOT_SHA256=$(pem_sha256 "${ROOT_PEM}")
    [ -n "${ROOT_SHA256}" ] || signature_failed "cannot compute the SHA-256 of the root CA."
    ROOT_SUBJECT=$(cert_field "${ROOT_PEM}" subject)
    echo "Signature OK: signed by $(cert_field "${signer}" subject),"
    echo "  chaining to the root CA ${ROOT_SUBJECT} (SHA-256 ${ROOT_SHA256})."
}


# confirm_root_anchor: the chain inside this file cannot show who made it
# (whoever builds an installer can include their own root). Accept the root
# only if it is already installed here, or matches PKI_ROOT_SHA256, or the
# user confirms its fingerprint against one received separately. Runs before
# the payload is decrypted. Digests are computed from the certificate bytes.
confirm_root_anchor() {
    local want

    if [ -n "${PKI_ROOT_SHA256:-}" ]; then
        want=$(printf '%s' "${PKI_ROOT_SHA256}" | tr -d ': ' | tr '[:upper:]' '[:lower:]')
        if [ "${want}" != "${ROOT_SHA256}" ]; then
            echo "FAILED: the root CA's SHA-256 (${ROOT_SHA256}) is not PKI_ROOT_SHA256. Nothing was installed." >&2
            exit 1
        fi
        echo "The root CA matches PKI_ROOT_SHA256."
        return 0
    fi
    if kc_has_cert "${SYSTEM_KEYCHAIN}" "${ROOT_SHA256}" || kc_has_cert "$(login_keychain)" "${ROOT_SHA256}"; then
        echo "The root CA is already installed on this machine."
        return 0
    fi
    echo "This root CA is not installed on this machine yet:"
    echo "  ${ROOT_SUBJECT}"
    echo "  SHA-256 ${ROOT_SHA256}"
    echo "Compare the fingerprint with one you received separately from this installer."
    if [ "${PKI_ASSUME_YES:-0}" != "0" ]; then
        echo "PKI_ASSUME_YES does not accept an unknown root; set PKI_ROOT_SHA256 to its fingerprint." >&2
        exit 1
    fi
    if ! confirm "Does it match, and do you want to go on?"; then
        echo "Nothing was installed." >&2
        exit 1
    fi
}


payload_rejected() {
    echo "Payload rejected: $1" >&2
    echo "Nothing was installed." >&2
    exit 1
}


# unpack_payload: only after verify_signature and confirm_root_anchor.
# Decrypts to a file, lists the archive and accepts only plain files and
# directories under ./manifest, ./system, ./user and ./smime (no absolute
# paths, "..", links or control characters), then extracts and checks that the
# payload's own root CA is the anchored one.
unpack_payload() {
    local txz="${WORK}/.payload.txz" names="${WORK}/.names" verbose="${WORK}/.verbose"
    local attempts=0 n type group sha1 haskey file note roots=0

    if [ "${PAYLOAD_ENCRYPTED}" = 1 ]; then
        while :; do
            get_installer_password || { echo "No installer password given." >&2; exit 1; }
            if payload > "${txz}" 2>/dev/null && tar -tJf "${txz}" > "${names}" 2>/dev/null; then
                break
            fi
            rm -f "${txz}"
            attempts=$((attempts + 1))
            if [ "${attempts}" -ge 3 ]; then
                echo "Could not decrypt the payload: wrong password?" >&2
                exit 1
            fi
            echo "Could not decrypt the payload: wrong password? Try again." >&2
        done
        INSTALLER_PASSWORD=""
    else
        payload > "${txz}"
        tar -tJf "${txz}" > "${names}" 2>/dev/null || payload_rejected "unreadable archive."
    fi

    tar -tvJf "${txz}" > "${verbose}" 2>/dev/null || payload_rejected "unreadable archive."
    [ "$(wc -l < "${names}")" = "$(wc -l < "${verbose}")" ] \
        || payload_rejected "member names are not one per line."
    if grep -q '[[:cntrl:]]' "${names}"; then
        payload_rejected "a member name has a control character."
    fi
    if grep -Eq '^[^-d]' "${verbose}" || grep -Eq ' (link to|->) ' "${verbose}"; then
        payload_rejected "the archive holds a link or a special file."
    fi
    while IFS= read -r n; do
        case "${n}" in
            /*|..|../*|*/../*|*/..) payload_rejected "unsafe member path '${n}'." ;;
            .|./|./manifest|./system|./system/*|./user|./user/*|./smime|./smime/*) ;;
            *) payload_rejected "unexpected member '${n}'." ;;
        esac
    done < "${names}"

    tar -xJf "${txz}" -C "${WORK}"
    rm -f "${txz}" "${names}" "${verbose}"

    [ -f "${MANIFEST}" ] || payload_rejected "no manifest."
    while IFS=$'\t' read -r -u 3 type group sha1 haskey file note; do
        case "${file}" in
            ""|*/*) payload_rejected "bad file name in the manifest." ;;
        esac
        if [ "${group}" = root ]; then
            case "${type}" in
                system-root|user-root)
                    [ "$(der_sha256 "${WORK}/${type%%-*}/${file}.cer")" = "${ROOT_SHA256}" ] \
                        || payload_rejected "its root CA is not the anchored root."
                    roots=$((roots + 1))
                    ;;
            esac
        fi
    done 3< "${MANIFEST}"
    [ "${roots}" -eq 1 ] || payload_rejected "it must hold exactly one PKI root CA."

    grep -q '^system-' "${MANIFEST}" || DO_SYSTEM=0
    grep -Eq '^(user-|smime)' "${MANIFEST}" || DO_USER=0
}

SUDO_READY=0

ensure_sudo() {
    if [ "${SUDO_READY}" = 0 ]; then
        sudo -v
        SUDO_READY=1
    fi
}


# install_keychain DOMAIN: "system" (System keychain, with sudo) or "user"
# (login keychain, no sudo). The payload manifest lists the items; the type
# system-root, system-ca, user-root, user-ca or smime tells which domain an
# item belongs to, and the file name carries the common name and expiry that
# the prompts show.
install_keychain() {
    local domain="$1" keychain heading where trustfor use_sudo
    local type group sha1 haskey file note kind dir path desc present withkey msg trusted
    local imported=0
    local acl=()
    local key_labels=() label seen_labels

    if [ "${domain}" = system ]; then
        keychain="${SYSTEM_KEYCHAIN}"
        heading="System keychain"
        where="the System keychain"
        trustfor="for all users"
        use_sudo=1
    else
        keychain=$(login_keychain)
        if [ ! -f "${keychain}" ]; then
            fail "login keychain not found"
            return 0
        fi
        heading="Login keychain"
        where="your login keychain"
        trustfor="for your account"
        use_sudo=0
        if [ -d /System/Applications/Mail.app ]; then
            acl=(-T /System/Applications/Mail.app)
        fi
    fi

    echo "== ${heading} =="

    while IFS=$'\t' read -r -u 3 type group sha1 haskey file note; do
        case "${type}" in
            "${domain}"-root) kind=root; dir="${domain}" ;;
            "${domain}"-ca) kind=ca; dir="${domain}" ;;
            smime) kind=smime; dir=smime ;;
            *) continue ;;
        esac
        if [ "${kind}" = smime ] && [ "${domain}" != user ]; then
            continue
        fi
        desc=$(describe "${file}" "${note}")

        if [ "${haskey}" = 1 ]; then
            path="${WORK}/${dir}/${file}.p12"
        else
            path="${WORK}/${dir}/${file}.cer"
        fi

        # Never trust a manifest digest. The root being trusted must be the
        # exact certificate verify_signature/confirm_root_anchor approved.
        if [ "${kind}" = root ] && [ "${group}" = root ] \
               && [ "$(der_sha256 "${path}")" != "${ROOT_SHA256}" ]; then
            fail "root CA ${desc} is not the anchored root; not trusting it"
            continue
        fi

        # CA certificates: compare real SHA-256. Identities (.p12) are not
        # pre-checked (the manifest SHA-1 is untrusted); import reports duplicates.
        present=0
        if [ "${haskey}" != 1 ]; then
            if kc_has_cert "${keychain}" "$(der_sha256 "${path}")"; then present=1; fi
        fi
        if [ "${present}" = 1 ] && [ "${kind}" != root ]; then
            echo "- ${desc}: already present"
            continue
        fi

        withkey=""
        if [ "${haskey}" = 1 ]; then
            withkey=" AND ITS PRIVATE KEY"
        fi
        case "${kind}" in
            root)
                scope=""
                trustpol=()
                if [ "${group}" != root ]; then
                    # not the PKI root (e.g. the privoxy interception CA): TLS only
                    scope=" for TLS only"
                    trustpol=(-p ssl)
                fi
                if [ "${present}" = 1 ]; then
                    msg="Trust the ROOT CA ${desc} ${trustfor}${scope} (already in ${where})?"
                else
                    msg="Add the ROOT CA ${desc}${withkey} to ${where} and trust it ${trustfor}${scope}?"
                fi
                ;;
            ca) msg="Add CA certificate ${desc}${withkey} to ${where}?" ;;
            smime) msg="Add S/MIME certificate ${desc} and its private key to ${where}?" ;;
        esac
        if ! confirm "- ${msg}"; then
            echo "    skipped"
            continue
        fi
        if [ "${use_sudo}" = 1 ]; then
            ensure_sudo
        fi

        if [ "${present}" = 1 ]; then
            echo "    already present"
        elif [ "${haskey}" = 1 ]; then
            if [ -f "${path}.pass" ]; then
                # one password per .p12, from the encrypted payload
                PASSWORD=$(sed -n 1p "${path}.pass")
                PASSWORD=${PASSWORD%$'\r'}
                if [ -z "${PASSWORD}" ]; then
                    fail "empty password file for ${desc}"
                    continue
                fi
            elif ! get_password "${group}"; then
                fail "no password available for '${group}'"
                continue
            fi
            import_into_keychain "${use_sudo}" "${keychain}" "${path}" "${PASSWORD}" ${acl[@]+"${acl[@]}"} \
                || { fail "${desc}"; continue; }
            imported=$((imported + 1))
            key_labels+=("$(p12_label "${path}" "${PASSWORD}")")
        else
            import_into_keychain "${use_sudo}" "${keychain}" "${path}" "" \
                || { fail "${desc}"; continue; }
        fi

        if [ "${kind}" = root ]; then
            trusted=0
            if [ "${use_sudo}" = 1 ]; then
                if sudo security add-trusted-cert -d -r trustRoot ${trustpol[@]+"${trustpol[@]}"} -k "${keychain}" "${WORK}/${dir}/${file}.cer"; then
                    trusted=1
                fi
            elif security add-trusted-cert -r trustRoot ${trustpol[@]+"${trustpol[@]}"} -k "${keychain}" "${WORK}/${dir}/${file}.cer"; then
                trusted=1
            fi
            if [ "${trusted}" = 1 ]; then
                echo "    trusted as root"
            else
                fail "trusting ${desc}"
            fi
        fi
    done 3< "${MANIFEST}"

    if [ "${domain}" = user ] && [ "${imported}" -gt 0 ]; then
        echo "Allowing Mail to use the new keys (asks for your login keychain password)..."
        # Only the keys just imported, by label. Without -l this changes the
        # partition list of every signing key in the login keychain. The tool
        # takes one -l, so it runs once per distinct label.
        seen_labels="|"
        for label in ${key_labels[@]+"${key_labels[@]}"}; do
            if [ -z "${label}" ]; then
                echo "  warning: could not read a key label; its partition list was not changed (Mail may ask for access)" >&2
                continue
            fi
            case "${seen_labels}" in
                *"|${label}|"*) continue ;;
            esac
            seen_labels="${seen_labels}${label}|"
            security set-key-partition-list -S apple-tool:,apple: -s -l "${label}" "${keychain}" >/dev/null \
                || echo "  warning: set-key-partition-list failed for '${label}'; Mail may ask for access to that key" >&2
        done
    fi
}


verify_signature
if [ "${VALIDATE_ONLY}" = 1 ]; then
    echo "Integrity check only (--check-signature-integrity): the file is unchanged since it was signed; the root was not anchored and nothing was decrypted or installed."
    exit 0
fi

confirm_root_anchor
unpack_payload

if [ "${LIST}" = 1 ]; then
    list_items
    exit 0
fi

echo "Installing credentials: ${INSTALL_FOR}"

if [ "${DO_SYSTEM}" = 1 ]; then
    install_keychain system
fi
if [ "${DO_USER}" = 1 ]; then
    install_keychain user
fi

PASSWORD=""
if [ "${FAILURES}" -gt 0 ]; then
    echo "Finished with ${FAILURES} failure(s)." >&2
    exit 1
fi
echo "Done."
exit 0
INSTALLER
        printf '__SIGNATURE_BELOW__\n'
    } > "${head}"

    {
        printf '__PAYLOAD_BELOW__\n'
        if [ -n "${password}" ]; then
            tar -cJf - -C "${dir}" . \
                | "${OPENSSL}" enc "-${ENC_CIPHER}" -pbkdf2 -md sha256 \
                      -iter "${ENC_ITER}" -salt -pass fd:3 3< <(printf '%s\n' "${password}") \
                | "${OPENSSL}" base64
        else
            tar -cJf - -C "${dir}" . | "${OPENSSL}" base64
        fi
    } > "${payload}"

    # sign everything except the signature's own lines
    cat "${head}" "${payload}" > "${content}"
    sign_content "${content}" "${sig}"

    {
        cat "${head}"
        "${OPENSSL}" base64 -in "${sig}"
        cat "${payload}"
    } > "${out}"
    chmod 0750 "${out}"   # the project's mode for scripts; the contents are encrypted or public
}

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

mkdir -p "${OUTDIR}"
chmod 0700 "${OUTDIR%/*}" "${OUTDIR}"   # the installers are private

SEL_CERTNAMES=()

build_trust_context
load_codesign
build_common

ALL_CERTNAMES=()
while IFS= read -r c; do
    ALL_CERTNAMES+=("${c}")
done < <(list_smime_certnames)

# S/MIME certificates matching any 'NAME_GLOB'
UNION=()
if [ "${#NAMES[@]}" -eq 0 ]; then
    echo "Note: no 'NAME_GLOB' given; no S/MIME certificates are included." >&2
else
    for n in "${NAMES[@]}"; do
        select_certnames "${n}" \
            || die "'NAME_GLOB' '${n}' matches no S/MIME certificate name (is it single-quoted?)."
        for c in "${SEL_CERTNAMES[@]}"; do
            case " ${UNION[*]} " in
                *" ${c} "*) ;;
                *) UNION+=("${c}") ;;
            esac
        done
    done
fi
SEL_CERTNAMES=("${UNION[@]}")

if [ "${#NAMES[@]}" -eq 0 ]; then
    stem=nosmimes
    if [ "${CA_CERTS_ONLY}" = "1" ]; then
        stem=cacerts
    fi
    label="CA certificates"
else
    stem=""
    for n in "${NAMES[@]}"; do
        stem="${stem:+${stem}_}$(installer_name "${n}")"
    done
    label="${NAMES[*]}"
fi

build_payload_dir
if [ "${#NAMES[@]}" -gt 0 ] && [ "${SMIME_COUNT}" -eq 0 ]; then
    die "none of the matching S/MIME certificates can be included (no .p12, or rejected by validation: see above)."
fi

# The payload is secret, and so encrypted, when it holds .p12 password files
ENCRYPT=0
if [ "${SMIME_COUNT}" -gt 0 ]; then
    ENCRYPT=1
fi

out="${OUTDIR}/install_credentials_${stem}.sh"
show_payload "${out}" "${STAGE}/payload"

if confirm "Create ${out}?"; then
    tarname="credentials_${stem}.txz"
    installer_pw=""
    if [ "${ENCRYPT}" = 1 ]; then
        tarname="${tarname}.enc"
        pki_kc verify >/dev/null   # the password is stored there: check before building
        installer_pw=$(pki_random_password)
    fi
    write_installer "${label}" "${STAGE}/payload" "${out}" "${tarname}" "${installer_pw}"
    echo "Created ${out}" >&2
    echo "  signed with '$(cert_cn "${CS_CERT}")'." >&2
    if [ "${ENCRYPT}" = 1 ]; then
        if ! printf '%s\n' "${installer_pw}" | pki_kc installer-set --name "${out##*/}"; then
            rm -f "${out}"
            die "cannot store the installer password in the PKI keychain; ${out} removed."
        fi
        installer_pw=""
        echo "The installer password (SECRET) is in the PKI keychain," >&2
        echo "entry ${out##*/}:" >&2
        echo "  bin/pki_keychain.py installer-get --name NAME" >&2
        echo "Send it by a different channel than the installer." >&2
    fi
    echo "Send the root CA's SHA-256 fingerprint separately too, so it" >&2
    echo "can be checked on a machine that does not have the root yet:" >&2
    fp=$("${OPENSSL}" x509 -noout -fingerprint -sha256 -in "${ROOT_CERT}" | sed 's/^.*=//')
    printf '  %s\n  %s\n' "${fp:0:47}" "${fp:48}" >&2
else
    echo "Skipped ${out}" >&2
    echo "(answer y at the prompt, or set PKI_ASSUME_YES=1)." >&2
fi

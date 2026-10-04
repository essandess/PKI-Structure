#!/usr/bin/env bash

# create_credentials.sh -- build a macOS credential installer from the PKI tree.
#
# Usage: create_credentials.sh [--user-keychain] [--extra-pki-dir DIR]...
#                              ['NAME_GLOB' ...]
#        create_credentials.sh --ca-only [--user-keychain]
#
# Writes ONE installer, credentials/install_credentials_<stem>.sh, after
# listing its payload and asking for confirmation (PKI_ASSUME_YES=1 skips
# the prompt). The payload is a tar.xz, base64-encoded with openssl, appended
# to the script. <stem> is the globs with glob characters spelled out (see
# installer_name), "nosmimes" without globs, "caonly" with --ca-only.
#
# Always single-quote each 'NAME_GLOB': the shell must not expand it. The
# script matches it, as a bash glob with brace expansion, against the S/MIME
# certificate names in smime/certs, for example 'persona_*' or
# 'personb_{gmail,comcast}_2026'. The installer holds the certificates
# matching any 'NAME_GLOB'; with none, no S/MIME certificates are included.
# --extra-pki-dir DIR (repeatable) also searches DIR/smime, a PKI tree with
# the same layout, e.g. an older one holding expired certificates. Its root,
# intermediate and CRLs, if present, are used for validation too. Each such
# tree gets its own password prompt in the installer, and each of its .p12
# files must open with a line of that tree's smime/private/passphrase.txt
# (line 2, else line 1); the script reports which line, never the password.
#
# Installer contents:
#   CA certificates  root (trusted), valid intermediate, privoxy CA; public
#                    certificates only. They go to the System keychain (sudo,
#                    payload directory system/), or with --user-keychain to
#                    the user's login keychain (no sudo, directory user/).
#   S/MIME           matching .p12 files, including expired ones, imported
#                    into the login keychain.
# Server certificates are not included: the installed CAs already validate
# them. Items that do not exist are reported and left out of the payload.
# The installer confirms each item and stores no passwords; .p12 passwords
# are prompted for or read from PKI_P12_PASSWORD_<GROUP>. Its --tar-only
# flag writes the payload to credentials_<stem>.txz in the current directory.
#
# --ca-only: the payload holds only root.p12 and the valid intermediate .p12
# (password protected), imported and trusted like the CA certificates above.
# Creating it needs no sudo.
#
# Validation, before anything enters the payload (unexpired CRLs found in
# root/ and intermediate/, or named by PKI_ROOT_CRL / PKI_INTERMEDIATE_CRL):
#   root          must verify against itself
#   intermediate  must verify against the root, root CRL checked
#   privoxy CA    must verify against itself (it is self-signed)
#   S/MIME        must verify against the root through a valid intermediate,
#                 CRLs of the whole chain checked (openssl verify
#                 -crl_check_all)
# Exception, for decrypting old mail only: an S/MIME ENCRYPTION certificate
# may be expired, or revoked with reason "superseded" (which is what
# create_smime.sh sets on reissue), and is then included with a warning. A
# signature certificate is never accepted when expired or revoked, nor an
# encryption certificate whose keyUsage allows signing or that is revoked
# for any other reason.
#
# Environment: PKI_ASSUME_YES, PKI_ROOT_CRL, PKI_INTERMEDIATE_CRL,
# PKI_PRIVOXY_DIRS (default privoxy).

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

for fn in cert_sha1 cert_smime_role cert_is_ca; do
    declare -F "${fn}" >/dev/null \
        || { echo "Error: ${fn} is not defined by bin/pki_common.sh (append pki_common_additions.sh to it)." >&2; exit 1; }
done

OUTDIR=credentials
ROOT_CERT=root/certs/root.cert.pem
ROOT_P12=root/private/root.p12
PRIVOXY_DIRS=${PKI_PRIVOXY_DIRS:-privoxy}
SMIME_RE='^(.+)-(signature|encryption)(\.[0-9a-fA-F]{40})?\.cert\.pem$'
# Characters allowed in a NAME_GLOB. Nothing that is shell syntax, because
# brace expansion is done with eval (see expand_name_glob).
NAME_GLOB_RE='^[][A-Za-z0-9_.,*?{}!^-]+$'

CA_ONLY=0
USER_KEYCHAIN=0
CA_DOMAIN=system   # payload directory and keychain of the CA certificates
HELP=0
NAMES=()
EXTRA_DIRS=()

die() {
    echo "Error: $*" >&2
    exit 1
}

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
        --ca-only)
            CA_ONLY=1
            shift
            ;;
        --user-keychain)
            USER_KEYCHAIN=1
            CA_DOMAIN=user
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
    cat <<USEAGE
Useage:

$(basename "$0") [--user-keychain] [--extra-pki-dir DIR]... ['NAME_GLOB' ...]
$(basename "$0") --ca-only [--user-keychain]

Creates ONE installer, ./${OUTDIR}/install_credentials_<stem>.sh, with the
root, intermediate and privoxy CA certificates (those that exist) and the
S/MIME certificates matching any 'NAME_GLOB'. <stem> is the globs with
glob characters spelled out (* S, ? Q, { LB, } RB, [ LBK, ] RBK, , C, !/^ N);
nosmimes without globs; caonly with --ca-only.

Single-quote every 'NAME_GLOB' so the shell does not expand it against the
current directory. The script matches it, as a bash glob with brace
expansion, against the S/MIME certificate names in smime/certs
(persona_gmail_2026), for example:
  'persona_*'  'personb_{gmail,comcast}_2026'
Without 'NAME_GLOB' no S/MIME certificates are included.
The payload is listed and confirmed (y/N) before the installer is written;
PKI_ASSUME_YES=1 skips the prompt.

Every certificate is validated first: the intermediate against the root, the
S/MIME certificates against the root through a valid intermediate, with the
CRLs checked (an unexpired CRL is required). Only an S/MIME encryption
certificate may be expired, or revoked as "superseded", and is then included
with a warning, to decrypt old mail; expired or revoked signature
certificates are always rejected.

  --user-keychain         install the CA certificates into the user's login
                          keychain (payload directory user/, no sudo)
                          instead of the System keychain (system/, sudo)
  --extra-pki-dir DIR     also look for S/MIME certificates in DIR/smime, a
                          PKI tree with the same layout (for example an older
                          one with expired certificates); repeatable. Its
                          root, intermediate and CRLs also serve validation.
                          The installer asks for a separate .p12 password for
                          each tree; each .p12 must open with that tree's
                          smime/private/passphrase.txt.
  --ca-only               create an installer whose payload is only root.p12
                          and the valid intermediate .p12; running that
                          installer imports them and trusts the root

Server certificates are not included. The installer's --tar-only flag writes
its payload to credentials_<stem>.txz in the current directory.
USEAGE
    exit 0
fi

if [ "${CA_ONLY}" = "1" ] && [ "${#NAMES[@]}" -gt 0 ]; then
    die "--ca-only does not take 'NAME_GLOB' arguments"
fi
if [ "${CA_ONLY}" = "1" ] && [ "${#EXTRA_DIRS[@]}" -gt 0 ]; then
    die "--ca-only does not use --extra-pki-dir"
fi

: "${OPENSSL:?OPENSSL is not set by bin/define_openssl.sh}"

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/pki-credentials.XXXXXX")
trap 'rm -rf "${STAGE}"' EXIT

# S/MIME sources: this PKI tree first, then each --extra-pki-dir. Each source
# is a separate password group because each tree has its own passphrase.txt.
SM_DIRS=("${PKI_ROOT}")
SM_GROUPS=(smime)
declare -A GROUP_FILE=() GROUP_LINE=()   # where each password group's password lives
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
                     "${tree}"/intermediate/crl/* "${tree}"/intermediate/*.crl "${tree}"/intermediate/*.crl.pem)
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
        for f in "${tree}/intermediate/certs/intermediate.cert.pem" "${tree}"/intermediate/certs/*.cert.pem; do
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

# Builds the trust context when something needs validating: an intermediate
# in this tree, S/MIME certificates, or --ca-only.
build_trust_context() {
    local f need=0

    if [ "${CA_ONLY}" = 1 ] || [ "${#NAMES[@]}" -gt 0 ]; then
        need=1
    fi
    for f in intermediate/certs/*.cert.pem; do
        need=1
    done
    [ "${need}" = 1 ] || return 0

    mkdir -p "${STAGE}/trust"
    collect_anchors
    if [ "${ANCHOR_COUNT}" -eq 0 ]; then
        if [ "${CA_ONLY}" = 1 ] || [ "${#NAMES[@]}" -gt 0 ]; then
            die "no valid root certificate to validate against (${ROOT_CERT})."
        fi
        return 0
    fi
    collect_crls
    collect_intermediates
}

# Sets INTERMEDIATE_PEM to the valid intermediate of this tree expiring last.
pick_main_intermediate() {
    local f epoch best_epoch=0

    INTERMEDIATE_PEM=""
    for f in "${INT_MAIN[@]}"; do
        epoch=$(cert_enddate_epoch "${f}")
        if [ -z "${INTERMEDIATE_PEM}" ] || [ "${epoch}" -gt "${best_epoch}" ]; then
            INTERMEDIATE_PEM="${f}"
            best_epoch="${epoch}"
        fi
    done
    [ -n "${INTERMEDIATE_PEM}" ] || die "no valid intermediate certificate found in intermediate/certs."
}

# verify_chain [options] CERT: verify CERT against the root through the valid
# intermediates, checking the CRLs of the whole chain.
verify_chain() {
    "${OPENSSL}" verify -crl_check_all -CRLfile "${CRL_ALL}" -CAfile "${ANCHORS}" \
        -untrusted "${INTS}" "$@" 2>&1
}

# The same without any CRL or validity period check (signatures and chain only).
verify_chain_only() {
    "${OPENSSL}" verify -no_check_time -CAfile "${ANCHORS}" -untrusted "${INTS}" "$@" 2>&1
}

# crl_revocation_reason CERT: the reason (e.g. Superseded) under which a CRL
# issued by the certificate's issuer lists it; Unspecified if none is given.
crl_revocation_reason() {
    local f="$1" serial issuer c r

    serial=$(cert_serial "${f}")
    issuer=$("${OPENSSL}" x509 -noout -issuer -in "${f}")
    for c in "${CRL_PEMS[@]}"; do
        [ "$("${OPENSSL}" crl -noout -issuer -in "${c}")" = "${issuer}" ] || continue
        r=$("${OPENSSL}" crl -noout -text -in "${c}" | awk -v s="${serial}" '
            /Serial Number:/ { cur = $NF; next }
            cur == s && /Revocation Date/ { seen = 1 }
            cur == s && /CRL Reason Code/ {
                getline
                gsub(/^[ \t]+|[ \t]+$/, "")
                print
                found = 1
                exit
            }
            END { if (!found && seen) print "Unspecified" }')
        if [ -n "${r}" ]; then
            printf '%s' "${r}"
            return 0
        fi
    done
}

# validate_smime_cert CERT ROLE -> 0 accepted, 1 rejected; sets CERT_STATE.
# ROLE (signature or encryption) comes from cert_smime_role, i.e. from the
# certificate's own properties, not from its file name.
# The certificate must verify against the root through a valid intermediate,
# with the CRLs of the whole chain checked. Only an S/MIME ENCRYPTION
# certificate may deviate, because its key is still needed to decrypt old
# mail: it may be expired, or revoked with reason "superseded" (what
# create_smime.sh sets when it reissues a certificate). A signature
# certificate never may.
validate_smime_cert() {
    local f="$1" role="$2" out err out2 err2 reason expired=0

    CERT_STATE="valid"
    if [ "${role}" != signature ] && [ "${role}" != encryption ]; then
        warn "rejecting ${f}: neither an S/MIME signature nor an encryption certificate (keyUsage/extendedKeyUsage)"
        return 1
    fi

    if out=$(verify_chain "${f}"); then
        return 0
    fi
    err=$(verify_error "${out}")
    if ! cert_is_current "${f}"; then
        expired=1
    fi

    if [ "${role}" = signature ]; then
        if [ "${expired}" = 1 ]; then
            warn "rejecting ${f}: expired signature certificate"
        else
            warn "rejecting ${f}: ${err}"
        fi
        return 1
    fi

    # Encryption certificate. Did only the validity period fail?
    if out2=$(verify_chain -no_check_time "${f}"); then
        if [ "${expired}" = 1 ]; then
            CERT_STATE="expired"
            warn "accepting expired encryption certificate ${f} (for decrypting old mail only)"
            return 0
        fi
        warn "rejecting ${f}: ${err}"
        return 1
    fi

    # Or was it revoked as superseded (and is otherwise sound)?
    err2=$(verify_error "${out2}")
    if [ "${err2}" = "certificate revoked" ]; then
        reason=$(crl_revocation_reason "${f}")
        if [[ "${reason}" == [Ss]uperseded ]] && verify_chain_only "${f}" >/dev/null; then
            CERT_STATE="revoked: superseded"
            if [ "${expired}" = 1 ]; then
                CERT_STATE="expired, revoked: superseded"
            fi
            warn "accepting encryption certificate ${f}: ${CERT_STATE} (for decrypting old mail only)"
            return 0
        fi
        warn "rejecting ${f}: revoked (${reason:-reason unknown})"
        return 1
    fi

    warn "rejecting ${f}: ${err2}"
    return 1
}

# p12_password_line P12 PASSPHRASE_FILE: prints the line (2, else 1) of the
# passphrase file that opens the .p12. Returns 1 if neither does, 2 if the
# passphrase file does not exist.
p12_password_line() {
    local p12="$1" pf="$2" n pw

    [ -f "${pf}" ] || return 2
    for n in 2 1; do
        pw=$(sed -n "${n}p" "${pf}")
        [ -n "${pw}" ] || continue
        if PKI_TMP_PW="${pw}" "${OPENSSL}" pkcs12 -legacy -noout -in "${p12}" \
                -passin env:PKI_TMP_PW >/dev/null 2>&1; then
            printf '%s' "${n}"
            return 0
        fi
    done
    return 1
}

# p12_check_content P12 PASSPHRASE_FILE LINE CERT: succeeds if the .p12 holds
# CERT (same certificate, read from inside the .p12) and the private key that
# belongs to it. On failure prints the reason and returns 1.
p12_check_content() {
    local p12="$1" pf="$2" line="$3" cert="$4" pw tmp="${STAGE}/p12check.pem" ck pk

    pw=$(sed -n "${line}p" "${pf}")
    if ! PKI_TMP_PW="${pw}" "${OPENSSL}" pkcs12 -legacy -in "${p12}" -clcerts -nokeys \
            -passin env:PKI_TMP_PW -out "${tmp}" 2>/dev/null; then
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
    pk=$(PKI_TMP_PW="${pw}" "${OPENSSL}" pkcs12 -legacy -in "${p12}" -nocerts -nodes \
             -passin env:PKI_TMP_PW 2>/dev/null | "${OPENSSL}" pkey -pubout 2>/dev/null) || true
    if [ -z "${pk}" ] || [ "${pk}" != "${ck}" ]; then
        echo "its private key does not belong to its certificate"
        return 1
    fi
}

# note_group_password GROUP PASSPHRASE_FILE LINE: remember where a password
# group's password comes from (shown at the end; never put in the installer).
note_group_password() {
    local g="$1" pf="$2" line="$3"

    if [ -z "${GROUP_FILE[${g}]:-}" ]; then
        GROUP_FILE[${g}]="${pf}"
        GROUP_LINE[${g}]="${line}"
    elif [ "${GROUP_LINE[${g}]}" != "${line}" ]; then
        GROUP_LINE[${g}]="mixed"
    fi
}

# ---------------------------------------------------------------------
# Staging the payload
# ---------------------------------------------------------------------

MANIFEST="${STAGE}/common/manifest"

# stage_ca_cert TYPE GROUP PEM LABEL HASKEY P12
# TYPE is root or ca. The files go to ${CA_DOMAIN}/ in the payload (system/
# or user/). The DER certificate is always staged (the root is trusted from
# it); the .p12 only when HASKEY is 1.
stage_ca_cert() {
    local type="$1" group="$2" pem="$3" label="$4" haskey="$5" p12="$6" sha1

    sha1=$(cert_sha1 "${pem}")
    "${OPENSSL}" x509 -outform der -in "${pem}" -out "${STAGE}/common/${CA_DOMAIN}/${sha1}.cer"
    if [ "${haskey}" = 1 ]; then
        cp "${p12}" "${STAGE}/common/${CA_DOMAIN}/${sha1}.p12"
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "${CA_DOMAIN}-${type}" "${group}" "${sha1}" "${haskey}" "${label}" >> "${MANIFEST}"
}

# stage_ca_dir DIR: stage every unexpired certificate in DIR/certs as a
# public CA certificate (its private key is never included).
stage_ca_dir() {
    local d="$1" f b sha1 seen=" " found=0
    local files=("${d}"/certs/*.cert.pem)

    if [ "${#files[@]}" -eq 0 ]; then
        echo "Note: no certificates exist in '${d}/certs'; none will be included in the payload." >&2
        return 0
    fi

    for f in "${files[@]}"; do
        b=${f##*/}
        b=${b%.cert.pem}

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

        stage_ca_cert ca "${d}" "${f}" "${d}/${b}" 0 ""
        found=1
    done

    if [ "${found}" = 0 ]; then
        warn "no usable certificates found in ${d}/certs"
    fi
}

# The CA certificates: the root, the valid intermediate and the privoxy CA.
# Missing items are noted and skipped.
build_common() {
    local d f have_root=0 have_int=0

    mkdir -p "${STAGE}/common/${CA_DOMAIN}"
    : > "${MANIFEST}"

    if [ -f "${ROOT_CERT}" ]; then
        verify_root
        stage_ca_cert root root "${ROOT_CERT}" "root (trusted)" 0 ""
        have_root=1
    else
        echo "Note: the root CA (${ROOT_CERT}) does not exist; it will not be included in the payload." >&2
    fi

    for f in intermediate/certs/intermediate.cert.pem intermediate/certs/intermediate.*.cert.pem; do
        if [ -f "${f}" ]; then
            have_int=1
        fi
    done
    if [ "${have_int}" = 0 ]; then
        echo "Note: no intermediate CA exists in intermediate/certs; it will not be included in the payload." >&2
    elif [ "${have_root}" = 0 ]; then
        echo "Note: the intermediate CA cannot be validated without the root CA; it will not be included in the payload." >&2
    else
        pick_main_intermediate
        echo "Using intermediate: ${INTERMEDIATE_PEM}" >&2
        stage_ca_cert ca intermediate "${INTERMEDIATE_PEM}" "${INTERMEDIATE_PEM%.cert.pem}" 0 ""
    fi

    for d in ${PRIVOXY_DIRS}; do
        stage_ca_dir "${d}"
    done
}

# check_ca_p12 GROUP P12 PASSPHRASE_FILE CERT
check_ca_p12() {
    local group="$1" p12="$2" pf="$3" cert="$4" line rc=0 why

    line=$(p12_password_line "${p12}" "${pf}") || rc=$?
    case "${rc}" in
        0)
            why=$(p12_check_content "${p12}" "${pf}" "${line}" "${cert}") \
                || die "'${p12}': ${why}."
            note_group_password "${group}" "${pf}" "${line}"
            ;;
        1)
            die "'${p12}' does not open with either of the first two lines of ${pf}."
            ;;
        *)
            warn "${pf} not found: cannot check the password, certificate and key of ${p12}"
            note_group_password "${group}" "${pf}" ""
            ;;
    esac
}

# --ca-only: only root.p12 and the valid intermediate's .p12. Both must exist.
build_ca_only() {
    local base int_p12

    mkdir -p "${STAGE}/common/${CA_DOMAIN}"
    : > "${MANIFEST}"

    verify_root
    pick_main_intermediate
    echo "Using intermediate: ${INTERMEDIATE_PEM}" >&2

    base=${INTERMEDIATE_PEM##*/}
    base=${base%.cert.pem}
    int_p12="intermediate/private/${base}.p12"
    [ -f "${ROOT_P12}" ] || die "'${ROOT_P12}' not found."
    [ -f "${int_p12}" ] || die "'${int_p12}' not found."


    # each .p12 must open with the passphrase.txt next to it and hold the
    # certificate (and its key) that is being installed
    check_ca_p12 root "${ROOT_P12}" root/private/passphrase.txt "${ROOT_CERT}"
    check_ca_p12 intermediate "${int_p12}" intermediate/private/passphrase.txt "${INTERMEDIATE_PEM}"

    stage_ca_cert root root "${ROOT_CERT}" "root (trusted)" 1 "${ROOT_P12}"
    stage_ca_cert ca intermediate "${INTERMEDIATE_PEM}" "${INTERMEDIATE_PEM%.cert.pem}" 1 "${int_p12}"
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
# S/MIME .p12 files of SEL_CERTNAMES from every source; sets SMIME_COUNT
build_payload_dir() {
    local dir="${STAGE}/payload" i sd group src f b certname ext role why sha1 p12 pf line rc state seen=" " count=0 rejected=0

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

            # the .p12 must open with the passphrase.txt of the tree it came from
            # and hold this certificate together with its private key
            pf="${sd}/smime/private/passphrase.txt"
            rc=0
            line=$(p12_password_line "${p12}" "${pf}") || rc=$?
            case "${rc}" in
                0)
                    if ! why=$(p12_check_content "${p12}" "${pf}" "${line}" "${f}"); then
                        warn "skipping ${p12}: ${why}"
                        rejected=$((rejected + 1))
                        continue
                    fi
                    note_group_password "${group}" "${pf}" "${line}"
                    ;;
                1)
                    warn "skipping ${p12}: it does not open with either of the first two lines of ${pf}"
                    rejected=$((rejected + 1))
                    continue
                    ;;
                *)
                    warn "${pf} not found: cannot check the password, certificate and key of ${p12}"
                    note_group_password "${group}" "${pf}" ""
                    ;;
            esac

            # what the certificate itself says it is, not what its file is called
            role=$(cert_smime_role "${f}")
            if [ "${role}" != "${ext}" ]; then
                warn "${f}: named -${ext}, but its keyUsage/extendedKeyUsage give it the role '${role}'; using '${role}'"
            fi

            # must verify against the root through a valid intermediate, CRLs checked
            if ! validate_smime_cert "${f}" "${role}"; then
                rejected=$((rejected + 1))
                continue
            fi
            state="${CERT_STATE}"

            cp "${p12}" "${dir}/smime/${sha1}.p12"
            printf 'smime\t%s\t%s\t1\t%s\n' "${group}" "${sha1}" \
                   "${certname} ${role}, ${state}, until $(cert_enddate "${f}")${src}" >> "${dir}/manifest"
            count=$((count + 1))
        done
    done

    SMIME_COUNT="${count}"
    echo "${count} S/MIME certificate(s) selected, ${rejected} rejected" >&2
}

# show_payload OUT DIR: list the files that go into the tar payload
show_payload() {
    local out="$1" dir="$2" f stem kind label keys=0

    echo >&2
    echo "${out} will contain:" >&2
    while IFS= read -r f; do
        f=${f#./}
        stem=${f##*/}
        stem=${stem%.*}
        label=$(awk -F'\t' -v s="${stem}" '$3 == s { print $1 ": " $5; exit }' "${dir}/manifest")

        case "${f}" in
            manifest)
                kind="list"
                label="items to install"
                ;;
            *.p12)
                kind="PRIVATE KEY"
                keys=$((keys + 1))
                ;;
            *)
                kind="certificate"
                ;;
        esac
        printf '  %-12s %s  [%s]\n' "${kind}" "${label}" "${f}" >&2
    done < <(cd "${dir}" && find . -type f | sort)
    echo "  ${keys} private key(s), password-protected; no passwords are included." >&2
}

# write_installer LABEL DIR OUT TARNAME
write_installer() {
    local label="$1" dir="$2" out="$3" tarname="$4"

    export COPYFILE_DISABLE=1   # no AppleDouble files in the tar on macOS
    {
        printf '#!/usr/bin/env bash\n'
        printf '# Credentials installer: %s\n' "${label}"
        printf '# Generated %s. No passwords are stored in this file.\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '\n'
        # label and tarname contain only validated characters (NAME_GLOB_RE
        # and installer_name), so plain double quotes are enough
        printf 'INSTALL_FOR="%s"\n' "${label}"
        printf 'SYSTEM_KEYCHAIN="%s"\n' /Library/Keychains/System.keychain
        printf 'TAR_NAME="%s"\n' "${tarname}"
        cat <<'INSTALLER'

set -eo pipefail
umask 077


usage() {
    cat <<USAGE
Usage: $(basename "$0") [--system-only | --user-only] [--list] [--tar-only]

Installs the credentials bundled in this script (${INSTALL_FOR}).
Run it as yourself (not with sudo); sudo is requested only for the System keychain.

  --system-only  only the System keychain items (sudo)
  --user-only    only the login keychain items: S/MIME identities, and the
                 CA certificates if the payload has them in user/ (no sudo)
  --list         show what is included and exit
  --tar-only     only write the payload to ./${TAR_NAME} and exit

You are asked (y/N) before each certificate is added; set PKI_ASSUME_YES=1
to answer yes to everything. Each .p12 password is asked for when needed;
to avoid the prompt set PKI_P12_PASSWORD_<GROUP>, for example
PKI_P12_PASSWORD_SMIME (GROUP is the name shown in the prompt, upper-cased,
with other characters replaced by _).
USAGE
}


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


# kc_has_cert KEYCHAIN SHA1
kc_has_cert() {
    security find-certificate -a -Z "$1" 2>/dev/null | grep -qi "^SHA-1 hash: $2\$"
}


# kc_has_identity KEYCHAIN SHA1 (certificate with its private key)
kc_has_identity() {
    security find-identity "$1" 2>/dev/null | grep -qi " $2 "
}


# import_into_keychain USE_SUDO(0|1) KEYCHAIN FILE PASSWORD [extra security args]
# An item that is already present counts as success.
import_into_keychain() {
    local use_sudo="$1" keychain="$2" file="$3" password="$4" out rc=0 nl=$'\n'

    shift 4
    local cmd=(security import "${file}" -k "${keychain}")

    if [ -n "${password}" ]; then
        cmd+=(-P "${password}")
    fi
    cmd+=("$@")
    if [ "${use_sudo}" = 1 ]; then
        cmd=(sudo "${cmd[@]}")
    fi

    out=$("${cmd[@]}" 2>&1) || rc=$?
    if [ "${rc}" -ne 0 ]; then
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


# The payload: a base64 encoded tar.xz appended to this script. Plain
# openssl, so that the macOS-native one is enough.
payload() {
    sed '1,/^__PAYLOAD_BELOW__$/d' "$0" | openssl base64 -d
}


DO_SYSTEM=1
DO_USER=1
LIST=0
TAR_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --system-only) DO_USER=0 ;;
        --user-only) DO_SYSTEM=0 ;;
        --list) LIST=1 ;;
        --tar-only) TAR_ONLY=1 ;;
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
    if ! payload > "${TAR_NAME}.part"; then
        rm -f "${TAR_NAME}.part"
        echo "Could not decode the payload." >&2
        exit 1
    fi
    mv "${TAR_NAME}.part" "${TAR_NAME}"
    echo "Wrote ${TAR_NAME}"
    exit 0
fi

if [ "$(uname -s)" != "Darwin" ]; then
    echo "This installer is for macOS." >&2
    exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
    echo "Run this as the target user, not as root: the S/MIME identities go into that user's keychain." >&2
    exit 1
fi


WORK=$(mktemp -d "${TMPDIR:-/tmp}/pki-install.XXXXXX")
trap 'rm -rf "${WORK}"' EXIT
export COPYFILE_DISABLE=1

payload | tar -xJf - -C "${WORK}"

MANIFEST="${WORK}/manifest"
grep -q '^system-' "${MANIFEST}" || DO_SYSTEM=0
grep -Eq '^(user-|smime)' "${MANIFEST}" || DO_USER=0


FAILURES=0

fail() {
    echo "  FAILED: $*" >&2
    FAILURES=$((FAILURES + 1))
}


list_items() {
    local type group sha1 haskey label

    while IFS=$'\t' read -r -u 3 type group sha1 haskey label; do
        echo "${type}: ${label} (SHA1 ${sha1})"
    done 3< "${MANIFEST}"
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
# item belongs to.
install_keychain() {
    local domain="$1" keychain heading where trustfor use_sudo
    local type group sha1 haskey label kind dir file present withkey msg trusted
    local imported=0
    local acl=()

    if [ "${domain}" = system ]; then
        keychain="${SYSTEM_KEYCHAIN}"
        heading="System keychain"
        where="the System keychain"
        trustfor="for all users"
        use_sudo=1
    else
        keychain="${HOME}/Library/Keychains/login.keychain-db"
        if [ ! -f "${keychain}" ]; then
            keychain="${HOME}/Library/Keychains/login.keychain"
        fi
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

    while IFS=$'\t' read -r -u 3 type group sha1 haskey label; do
        case "${type}" in
            "${domain}"-root) kind=root; dir="${domain}" ;;
            "${domain}"-ca) kind=ca; dir="${domain}" ;;
            smime) kind=smime; dir=smime ;;
            *) continue ;;
        esac
        if [ "${kind}" = smime ] && [ "${domain}" != user ]; then
            continue
        fi
        echo "- ${type}: ${label}"

        if [ "${haskey}" = 1 ]; then
            file="${WORK}/${dir}/${sha1}.p12"
        else
            file="${WORK}/${dir}/${sha1}.cer"
        fi

        present=0
        if [ "${haskey}" = 1 ]; then
            if kc_has_identity "${keychain}" "${sha1}"; then present=1; fi
        elif kc_has_cert "${keychain}" "${sha1}"; then
            present=1
        fi
        if [ "${present}" = 1 ] && [ "${kind}" != root ]; then
            echo "    already present"
            continue
        fi

        withkey=""
        if [ "${haskey}" = 1 ]; then
            withkey=" AND ITS PRIVATE KEY"
        fi
        case "${kind}" in
            root) msg="Add the ROOT CA '${label}'${withkey} to ${where} and trust it ${trustfor}?" ;;
            ca) msg="Add CA certificate '${label}'${withkey} to ${where}?" ;;
            smime) msg="Add this S/MIME certificate and its private key to ${where}?" ;;
        esac
        if ! confirm "    ${msg}"; then
            echo "    skipped"
            continue
        fi
        if [ "${use_sudo}" = 1 ]; then
            ensure_sudo
        fi

        if [ "${present}" = 1 ]; then
            echo "    already present"
        elif [ "${haskey}" = 1 ]; then
            if ! get_password "${group}"; then
                fail "no password available for '${group}'"
                continue
            fi
            if [ "${kind}" = smime ]; then
                import_into_keychain "${use_sudo}" "${keychain}" "${file}" "${PASSWORD}" ${acl[@]+"${acl[@]}"} \
                    || { fail "${label}"; continue; }
            else
                import_into_keychain "${use_sudo}" "${keychain}" "${file}" "${PASSWORD}" -A \
                    || { fail "${label}"; continue; }
            fi
            if [ "${kind}" = smime ]; then
                imported=$((imported + 1))
            fi
        else
            import_into_keychain "${use_sudo}" "${keychain}" "${file}" "" \
                || { fail "${label}"; continue; }
        fi

        if [ "${kind}" = root ]; then
            trusted=0
            if [ "${use_sudo}" = 1 ]; then
                if sudo security add-trusted-cert -d -r trustRoot -k "${keychain}" "${WORK}/${dir}/${sha1}.cer"; then
                    trusted=1
                fi
            elif security add-trusted-cert -r trustRoot -k "${keychain}" "${WORK}/${dir}/${sha1}.cer"; then
                trusted=1
            fi
            if [ "${trusted}" = 1 ]; then
                echo "    trusted as root"
            else
                fail "trusting ${label}"
            fi
        fi
    done 3< "${MANIFEST}"

    if [ "${domain}" = user ] && [ "${imported}" -gt 0 ]; then
        echo "Allowing Mail to use the new keys (asks for your login keychain password)..."
        security set-key-partition-list -S apple-tool:,apple: -s "${keychain}" >/dev/null \
            || echo "  warning: set-key-partition-list failed; Mail may ask for access to the keys" >&2
    fi
}


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
        printf '__PAYLOAD_BELOW__\n'
        tar -cJf - -C "${dir}" . | "${OPENSSL}" base64
    } > "${out}"
    chmod 0700 "${out}"
}

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

mkdir -p "${OUTDIR}"
chmod 0700 "${OUTDIR}"

SEL_CERTNAMES=()

build_trust_context
if [ "${#NAMES[@]}" -gt 0 ] && [ ! -s "${INTS:-}" ]; then
    die "no valid intermediate certificate to validate the S/MIME certificates with."
fi

if [ "${CA_ONLY}" = "1" ]; then
    build_ca_only
    stem=caonly
    label="root and intermediate CA"
else
    build_common

    ALL_CERTNAMES=()
    while IFS= read -r c; do
        ALL_CERTNAMES+=("${c}")
    done < <(list_smime_certnames)

    # S/MIME certificates matching any 'NAME_GLOB'
    UNION=()
    if [ "${#NAMES[@]}" -eq 0 ]; then
        echo "Note: no 'NAME_GLOB' given; no S/MIME certificates will be included in the payload." >&2
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
        label="CA certificates"
    else
        stem=""
        for n in "${NAMES[@]}"; do
            stem="${stem:+${stem}_}$(installer_name "${n}")"
        done
        label="${NAMES[*]}"
    fi
fi

build_payload_dir
if [ "${CA_ONLY}" != "1" ] && [ "${#NAMES[@]}" -gt 0 ] && [ "${SMIME_COUNT}" -eq 0 ]; then
    die "none of the matching S/MIME certificates can be included (no .p12, or rejected by validation: see the warnings above)."
fi
if [ ! -s "${STAGE}/payload/manifest" ]; then
    warn "nothing to include in the payload; no installer created."
    exit 0
fi

out="${OUTDIR}/install_credentials_${stem}.sh"
show_payload "${out}" "${STAGE}/payload"

if confirm "Create ${out}?"; then
    write_installer "${label}" "${STAGE}/payload" "${out}" "credentials_${stem}.txz"
    echo "Created ${out}" >&2

    groups=$(awk -F'\t' '$4 == 1 { print $2 }' "${STAGE}/payload/manifest" | sort -u)
    if [ -n "${groups}" ]; then
        echo "Send these .p12 passwords separately; the installer contains none:" >&2
        while IFS= read -r g; do
            pf="${GROUP_FILE[${g}]:-}"
            line="${GROUP_LINE[${g}]:-}"
            if [ -z "${pf}" ]; then
                echo "  ${g}: not checked" >&2
            elif [ -z "${line}" ]; then
                echo "  ${g}: ${pf} not found" >&2
            elif [ "${line}" = mixed ]; then
                echo "  ${g}: the .p12 files open with different lines of ${pf}" >&2
            else
                echo "  ${g}: line ${line} of ${pf}" >&2
            fi
        done <<< "${groups}"
    fi
else
    echo "Skipped ${out} (answer y at the prompt, or set PKI_ASSUME_YES=1)." >&2
fi

#!/usr/bin/env bash

# create_keepass_entry.sh -- put installer, master, profile secrets in KeePassXC.
#
# Usage: create_keepass_entry.sh --db FILE [--key-file FILE | --no-password]
#            [--title TITLE] [--group PATH] [--individual-smime-passwords]
#            [--force-update] [--no-backup] [--kp-prompt] [-n|--dry-run]
#            [--root-cert FILE] [--export-master] [--master-title TITLE]
#            [INSTALLER|PROFILE]
#        create_keepass_entry.sh --xml-out FILE [--title TITLE]
#            [--group PATH] [--individual-smime-passwords] [--root-cert FILE]
#            [--export-master] [INSTALLER]
#
# INSTALLER: an encrypted installer from create_credentials.sh. Its signature
# is checked, then its keychain password opens the payload; it is never run.
# PROFILE: a name from `pki_keychain.py profile-list`; its .mobileconfig
# (PLAIN TEXT secrets) is attached to the entry 'MDM profile: NAME'.
# --export-master stores the PKI master password. Entries are merged into
# --db (backed up first); UUIDs derive from the title, so re-runs update in
# place. Secrets never appear in argv or the environment. See README.md.
#
# Needs bash 4.4+, openssl, tar with xz, keepassxc-cli 2.7+.

set -Eeuo pipefail
shopt -s nullglob
shopt -u patsub_replacement 2>/dev/null || true   # '&' in ${x//a/&} (5.2)
umask 077

BASH_OK=0
if [ "${BASH_VERSINFO[0]}" -gt 4 ]; then BASH_OK=1; fi
if [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -ge 4 ]; then
    BASH_OK=1
fi
if [ "${BASH_OK}" -eq 0 ]; then
    echo "Error: bash 4.4+ required (this is ${BASH_VERSION})." >&2
    exit 1
fi

case $- in
    *x*) set +x; echo "(xtrace off: it would show passwords)" >&2 ;;
esac
trap 'echo "Error: ${0##*/} failed (exit $?) at line ${LINENO}" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

if [ -f "${SCRIPT_DIR}/define_openssl.sh" ]; then
    . "${SCRIPT_DIR}/define_openssl.sh"
fi
OPENSSL=${OPENSSL:-openssl}
. "${SCRIPT_DIR}/define_python.sh"

die()  { echo "Error: $*" >&2; exit 1; }
warn() { echo "Warning: $*" >&2; }

usage() {
    cat <<'USAGE'
Usage: create_keepass_entry.sh --db FILE [--key-file FILE | --no-password]
         [--title TITLE] [--group PATH] [--individual-smime-passwords]
         [--force-update] [--no-backup] [--kp-prompt] [-n|--dry-run]
         [--root-cert FILE] [--export-master] [--master-title TITLE]
         [INSTALLER|PROFILE]
       create_keepass_entry.sh --xml-out FILE [--group PATH]
         [--individual-smime-passwords] [--root-cert FILE]
         [--export-master] [INSTALLER]

Stores an installer's password (and, with --export-master, the PKI master
password), or a stored MDM profile as an attachment, in a KeePassXC
database. INSTALLER|PROFILE is optional only with --export-master. See the
top of this file for details.
USAGE
}

# Private temporary directory: holds the decrypted payload and the XML
TMPD=""
KP_PASS=""
cleanup() {
    KP_PASS=""
    if [ -n "${TMPD}" ]; then rm -rf "${TMPD}"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

# ---------------------------------------------------------------- options

# not actually an option
KEEPASS_GROUP_NAME="Password"

DB="" KEYFILE="" NOPASS=0 TITLE="" GROUP="" XML_OUT="" ROOT_CERT=""
FORCE=0 BACKUP=1 KP_PROMPT=0 DRYRUN=0 INDIVIDUAL=0
EXPORT_MASTER=0 MASTER_TITLE="PKI-Structure KeePassXC Passphrase"
MASTER_SERVICE="com.github.essandess.pki-structure.keepassxc-passphrase"
ARGS=()

need_arg() { if [ "$1" -lt 2 ]; then die "$2 needs an argument"; fi; }

while [ $# -gt 0 ]; do
    case $1 in
        --db)            need_arg $# "$1"; DB=$2; shift 2 ;;
        --key-file)      need_arg $# "$1"; KEYFILE=$2; shift 2 ;;
        --no-password)   NOPASS=1; shift ;;
        --title)         need_arg $# "$1"; TITLE=$2; shift 2 ;;
        --group)         need_arg $# "$1"; GROUP=$2; shift 2 ;;
        --xml-out)       need_arg $# "$1"; XML_OUT=$2; shift 2 ;;
        --root-cert)     need_arg $# "$1"; ROOT_CERT=$2; shift 2 ;;
        --export-master) EXPORT_MASTER=1; shift ;;
        --master-title)  need_arg $# "$1"; MASTER_TITLE=$2; shift 2 ;;
        --individual-smime-passwords) INDIVIDUAL=1; shift ;;
        --force-update)  FORCE=1; shift ;;
        --no-backup)     BACKUP=0; shift ;;
        --kp-prompt)     KP_PROMPT=1; shift ;;
        -n|--dry-run)    DRYRUN=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        --)              shift; ARGS+=("$@"); break ;;
        -*)              usage >&2; die "unknown option: $1" ;;
        *)               ARGS+=("$1"); shift ;;
    esac
done

if [ "${#ARGS[@]}" -eq 0 ] && [ "${EXPORT_MASTER}" -eq 0 ]; then
    usage >&2; die "no INSTALLER given (or --export-master)"
fi
if [ "${#ARGS[@]}" -gt 1 ]; then die "give at most one INSTALLER"; fi
INSTALLER=${ARGS[0]:-}
# an argument that is not a file names a stored MDM profile
PROFILE=""
if [ -n "${INSTALLER}" ] && [ ! -e "${INSTALLER}" ]; then
    LISTED=$("${PYTHON}" "${SCRIPT_DIR}/pki_keychain.py" profile-list 2>/dev/null) \
        || LISTED=""
    grep -qxF -- "${INSTALLER}" <<<"${LISTED}" \
        || die "'${INSTALLER}' is neither an installer file nor a name in" \
               "'bin/pki_keychain.py profile-list'"
    PROFILE=${INSTALLER}
    INSTALLER=""
    if [ "${EXPORT_MASTER}" -eq 1 ] || [ -n "${XML_OUT}" ]; then
        die "a profile does not combine with --export-master or --xml-out"
    fi
fi
if [ -n "${XML_OUT}" ] && [ -n "${DB}" ]; then
    die "--xml-out and --db are alternatives"
fi
if [ -z "${DB}" ] && [ -z "${XML_OUT}" ] && [ "${DRYRUN}" -eq 0 ]; then
    usage >&2; die "--db FILE is required (or -n, or --xml-out FILE)"
fi
if [ "${NOPASS}" -eq 1 ] && [ -z "${KEYFILE}" ]; then
    die "--no-password needs --key-file"
fi
if [ -n "${KEYFILE}" ] && [ ! -r "${KEYFILE}" ]; then
    die "cannot read key file ${KEYFILE}"
fi
GROUP=${GROUP#/}; GROUP=${GROUP%/}
if [[ ${GROUP} == *//* ]]; then die "--group has an empty path part"; fi

INST_BASE=""
if [ -n "${INSTALLER}" ]; then
    if [ ! -f "${INSTALLER}" ] || [ ! -r "${INSTALLER}" ]; then
        die "cannot read installer ${INSTALLER}"
    fi
    INST_BASE=${INSTALLER##*/}
    if [ -z "${TITLE}" ]; then TITLE="S/MIME installer: ${INST_BASE}"; fi
elif [ -n "${PROFILE}" ]; then
    TITLE=${TITLE:-"MDM profile: ${PROFILE}"}
    GROUP=${GROUP:-Profile}
else
    TITLE=${TITLE:-${MASTER_TITLE}}
fi

# ---------------------------------------------------------------- helpers

declare -A MONTH=([Jan]=01 [Feb]=02 [Mar]=03 [Apr]=04 [May]=05 [Jun]=06
                  [Jul]=07 [Aug]=08 [Sep]=09 [Oct]=10 [Nov]=11 [Dec]=12)

# iso_date "Sep 29 10:30:36 2026 GMT" -> 2026-09-29
iso_date() {
    local mon day clock year zone
    read -r mon day clock year zone <<<"$1"
    printf '%s-%s-%02d' "${year}" "${MONTH[${mon}]:-00}" "$((10#${day}))"
}

if date --version >/dev/null 2>&1; then GNU_DATE=1; else GNU_DATE=0; fi

# file_mtime_iso FILE -> 2026-10-09T12:00:00Z (UTC)
file_mtime_iso() {
    if [ "${GNU_DATE}" -eq 1 ]; then
        date -u -r "$1" '+%Y-%m-%dT%H:%M:%SZ'
    else
        TZ=UTC stat -f '%Sm' -t '%Y-%m-%dT%H:%M:%SZ' "$1"
    fi
}

LEGACY=()
OPENSSL_HELP=$("${OPENSSL}" pkcs12 -help 2>&1 || true)
if [[ ${OPENSSL_HELP} == *-legacy* ]]; then LEGACY=(-legacy); fi

# PROBE_ERR, P_START, P_END describe the last .p12 opened by probe
PROBE_ERR="" P_START="" P_END=""

# probe FILE PASSWORD: succeed if PASSWORD opens FILE. The password goes to
# openssl on a pipe (fd 3), never in argv.
probe() {
    local out pem info key val
    PROBE_ERR=""
    if ! out=$("${OPENSSL}" pkcs12 "${LEGACY[@]}" -in "$1" -nokeys \
                   -clcerts -passin fd:3 3< <(printf '%s\n' "$2") 2>&1); then
        PROBE_ERR=${out%%$'\n'*}
        return 1
    fi
    pem=$(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
              <<<"${out}")
    if [ -z "${pem}" ]; then
        PROBE_ERR="no certificate in the .p12"; return 1
    fi
    if ! info=$("${OPENSSL}" x509 -noout -startdate -enddate \
                    <<<"${pem}" 2>/dev/null); then
        PROBE_ERR="unreadable certificate"; return 1
    fi
    while IFS='=' read -r key val; do
        case ${key} in
            notBefore) P_START=${val} ;;
            notAfter)  P_END=${val} ;;
        esac
    done <<<"${info}"
    return 0
}

# read_pw FILE LINE: that line of FILE, without its newline
read_pw() {
    local v
    v=$(sed -n "${2}p" "$1")
    printf '%s' "${v%$'\r'}"
}

# parse_name NAME: split a payload file name made by create_credentials.sh,
# "common name :: YYYY-MM-DD :: id", into CN, EXPIRY and ID
parse_name() {
    local rest
    CN="${1%% :: *}"
    rest="${1#* :: }"
    EXPIRY="${rest%% :: *}"
    ID="${rest#* :: }"
}

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/kpentry.XXXXXX")
WORK="${TMPD}/payload"
mkdir "${WORK}"
M_TYPE=() M_GROUP=() M_KEY=() M_FILE=() M_NOTE=()
R_FILE=() R_GROUP=() R_SRC=() R_START=() R_END=() R_NOTE=() R_HASH=()
SKIPPED=() G_MEM=() ORDER=()
MOD=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

if [ -n "${INSTALLER}" ]; then   # everything about the installer, up to the plan
# --------------------------------------------- the installer and its payload

# hdr_val NAME: value of NAME="..." in the installer's header lines
HDR=$(sed -n '1,20p' "${INSTALLER}")
hdr_val() {
    sed -n "s/^$1=\"\{0,1\}\([^\"]*\)\"\{0,1\}\$/\1/p" <<<"${HDR}" | head -n 1
}

if ! grep -q '^__PAYLOAD_BELOW__$' "${INSTALLER}" \
   || [ -z "$(hdr_val PAYLOAD_ENCRYPTED)" ]; then
    die "${INSTALLER} is not an installer made by create_credentials.sh"
fi
if [ "$(hdr_val PAYLOAD_ENCRYPTED)" != 1 ]; then
    die "${INST_BASE} is not encrypted (a --ca-only or CA-only installer):" \
        "it has no installer password and holds no .p12 passwords"
fi
ENC_CIPHER=$(hdr_val ENC_CIPHER)
ENC_ITER=$(hdr_val ENC_ITER)
if ! [[ ${ENC_CIPHER} =~ ^[a-z0-9-]+$ ]] || ! [[ ${ENC_ITER} =~ ^[0-9]+$ ]]; then
    die "cannot read the payload encryption settings from ${INST_BASE}"
fi

# the installer password lives in the PKI keychain (a shell variable: not exported, not in argv)
INSTALLER_PW=$("${PYTHON}" "${SCRIPT_DIR}/pki_keychain.py" installer-get --name "${INST_BASE}") \
    || die "no installer password for ${INST_BASE} in the PKI keychain"
[ -n "${INSTALLER_PW}" ] || die "the installer password for ${INST_BASE} is empty"

# extract_payload DIR: the installer's own steps (its payload function, then
# tar -xJf): base64, openssl enc -d with the installer password on fd 3 (never
# in argv), unpack into DIR.
extract_payload() {
    sed '1,/^__PAYLOAD_BELOW__$/d' "${INSTALLER}" | "${OPENSSL}" base64 -d \
        | "${OPENSSL}" enc -d "-${ENC_CIPHER}" -pbkdf2 -md sha256 \
              -iter "${ENC_ITER}" \
              -pass fd:3 3< <(printf '%s\n' "${INSTALLER_PW}") \
        | tar -xJf - -C "$1"
}


# ------------------------------------------- signature of the installer

# create_credentials.sh signs every installer (detached PKCS#7, DER, base64,
# between __SIGNATURE_BELOW__ and __PAYLOAD_BELOW__, covering the file except
# those lines). Check it before the payload is decrypted or unpacked. The
# trust anchor is this PKI tree's own root (or --root-cert), never a root the
# installer carries; the signature block holds the signer and intermediates.
ANCHORS="${TMPD}/anchors.pem"

collect_anchors() {
    local f pem n=0 candidates=()

    : > "${ANCHORS}"
    if [ -n "${ROOT_CERT}" ]; then
        [ -r "${ROOT_CERT}" ] || die "cannot read --root-cert ${ROOT_CERT}"
        candidates=("${ROOT_CERT}")
    else
        candidates=(root/certs/root.cert.pem root/certs/root.*.cert.pem)
    fi
    for f in "${candidates[@]}"; do
        [ -f "${f}" ] || continue
        if ! pem=$("${OPENSSL}" x509 -in "${f}" 2>/dev/null); then
            pem=$("${OPENSSL}" x509 -inform DER -in "${f}" 2>/dev/null) \
                || { warn "ignoring ${f}: not a certificate"; continue; }
        fi
        printf '%s\n' "${pem}" > "${TMPD}/anchor.one.pem"
        if "${OPENSSL}" verify -CAfile "${TMPD}/anchor.one.pem" \
               "${TMPD}/anchor.one.pem" >/dev/null 2>&1; then
            printf '%s\n' "${pem}" >> "${ANCHORS}"
            n=$((n + 1))
        else
            warn "ignoring root certificate ${f}: does not verify (expired?)"
        fi
    done
    if [ "${n}" -eq 0 ]; then
        die "no valid root certificate to check the signature of ${INST_BASE}" \
            "against (looked for root/certs/root*.cert.pem); use --root-cert FILE"
    fi
}

# signer_issuer_ok SIGNER SIG: the CA that issued SIGNER must allow
# codeSigning (`-purpose any` ignores CA EKUs); a CA with no EKU is refused.
signer_issuer_ok() {
    local signer=$1 sig=$2 f eku
    local certs="${TMPD}/sig.certs"

    if "${OPENSSL}" verify -CAfile "${ANCHORS}" "${signer}" >/dev/null 2>&1; then
        return 0   # issued by the root itself
    fi
    "${OPENSSL}" pkcs7 -inform DER -in "${sig}" -print_certs -out "${certs}" \
        2>/dev/null || return 1
    awk -v p="${TMPD}/sig.cert" '
        /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s.%d.pem", p, n) }
        f { print > f }
        /-----END CERTIFICATE-----/ { close(f); f = "" }' "${certs}"
    for f in "${TMPD}"/sig.cert.*.pem; do
        "${OPENSSL}" verify -CAfile "${ANCHORS}" -untrusted "${f}" "${signer}" \
            >/dev/null 2>&1 || continue
        eku=$("${OPENSSL}" x509 -noout -ext extendedKeyUsage -in "${f}" \
                  2>/dev/null) || eku=""
        case "${eku}" in
            *"Code Signing"*) return 0 ;;
        esac
    done
    return 1
}

verify_installer_signature() {
    local signed="${TMPD}/installer.signed" sig="${TMPD}/installer.sig.der"
    local signer="${TMPD}/installer.signer.pem" out text

    if ! grep -q '^__SIGNATURE_BELOW__$' "${INSTALLER}" \
       || ! grep -q '^__PAYLOAD_BELOW__$' "${INSTALLER}"; then
        die "${INST_BASE} has no signature block: it was not made by the" \
            "current create_credentials.sh"
    fi
    awk '/^__SIGNATURE_BELOW__$/ { print; skip = 1; next }
         /^__PAYLOAD_BELOW__$/ { skip = 0 }
         !skip { print }' "${INSTALLER}" > "${signed}"
    awk '/^__SIGNATURE_BELOW__$/ { skip = 1; next }
         /^__PAYLOAD_BELOW__$/ { skip = 0 }
         skip' "${INSTALLER}" | "${OPENSSL}" base64 -d > "${sig}" 2>/dev/null || true
    [ -s "${sig}" ] || die "${INST_BASE} carries no readable signature"

    if ! out=$("${OPENSSL}" smime -verify -binary -inform DER -in "${sig}" \
                   -content "${signed}" -CAfile "${ANCHORS}" -purpose any \
                   -signer "${signer}" -out /dev/null 2>&1); then
        die "SIGNATURE CHECK FAILED for ${INST_BASE}: it was changed after it" \
            "was signed, or not signed by a certificate that chains to this" \
            "PKI's root. ${out}"
    fi
    text=$("${OPENSSL}" x509 -noout -ext extendedKeyUsage -in "${signer}" 2>/dev/null) || text=""
    case "${text}" in
        *"Code Signing"*) ;;
        *) die "the signer of ${INST_BASE} does not have the codeSigning extendedKeyUsage" ;;
    esac
    text=$("${OPENSSL}" x509 -noout -ext basicConstraints -in "${signer}" 2>/dev/null) || text=""
    case "${text}" in
        *"CA:TRUE"*) die "the signer of ${INST_BASE} is a CA certificate" ;;
    esac
    signer_issuer_ok "${signer}" "${sig}" \
        || die "the issuing CA of the signer of ${INST_BASE} does not allow codeSigning"
    echo "Signature OK: ${INST_BASE} signed by" \
         "$("${OPENSSL}" x509 -noout -subject -in "${signer}" | sed 's/^subject= *//')." >&2
}

collect_anchors
verify_installer_signature

if ! extract_payload "${WORK}" 2>/dev/null; then
    die "cannot decrypt the payload of ${INST_BASE} with its keychain password"
fi
if [ ! -f "${WORK}/manifest" ]; then
    die "the decrypted payload has no manifest: wrong password file?"
fi

# manifest: type, group, sha1, haskey, name, note (tab separated)
M_TYPE=() M_GROUP=() M_KEY=() M_FILE=() M_NOTE=()
while IFS=$'\t' read -r type group sha1 haskey file note; do
    M_TYPE+=("${type}"); M_GROUP+=("${group}"); M_KEY+=("${haskey}")
    M_FILE+=("${file}"); M_NOTE+=("${note}")
done < "${WORK}/manifest"

# -------------------------------------- open the payload's .p12 (individual)

R_FILE=() R_GROUP=() R_SRC=() R_START=() R_END=() R_NOTE=() R_HASH=()
SKIPPED=()

if [ "${INDIVIDUAL}" -eq 1 ]; then
    for ((m = 0; m < ${#M_TYPE[@]}; m++)); do
        if [ "${M_TYPE[m]}" != smime ] || [ "${M_KEY[m]}" != 1 ]; then continue; fi
        p12="${WORK}/smime/${M_FILE[m]}.p12"
        if [ ! -f "${p12}" ]; then
            SKIPPED+=("${M_FILE[m]}.p12|listed in the manifest, not in the payload")
            continue
        fi
        if [ ! -f "${p12}.pass" ]; then
            SKIPPED+=("${M_FILE[m]}.p12|the payload holds no password file for it")
            continue
        fi
        pw=$(read_pw "${p12}.pass" 1)
        if [ -z "${pw}" ]; then
            SKIPPED+=("${M_FILE[m]}.p12|its password file is empty")
        elif probe "${p12}" "${pw}"; then
            h=$(printf '%s' "${pw}" | "${OPENSSL}" dgst -sha256 | sed 's/^.* //')
            R_FILE+=("${M_FILE[m]}.p12"); R_GROUP+=("${M_GROUP[m]}")
            R_SRC+=("${p12}.pass"); R_START+=("${P_START}"); R_END+=("${P_END}")
            R_NOTE+=("${M_NOTE[m]}"); R_HASH+=("${h}")
        else
            SKIPPED+=("${M_FILE[m]}.p12|its password does not open it (${PROBE_ERR})")
        fi
        pw=""
    done
    if [ "${#R_FILE[@]}" -eq 0 ] && [ "${#SKIPPED[@]}" -eq 0 ]; then
        die "${INST_BASE} holds no S/MIME .p12 files"
    fi
fi

# ------------------------------------- group by password (= by issuance)

declare -A GIDX=()
G_MEM=() G_SRC=() G_GROUP=() G_LABEL=()
for ((i = 0; i < ${#R_FILE[@]}; i++)); do
    key="${R_HASH[i]}"
    if [ -z "${GIDX[${key}]+x}" ]; then
        GIDX[${key}]=${#G_MEM[@]}
        G_MEM+=(""); G_SRC+=("${R_SRC[i]}"); G_GROUP+=("${R_GROUP[i]}")
        G_LABEL+=("")
    fi
    g=${GIDX[${key}]}
    G_MEM[g]="${G_MEM[g]} ${i}"
done

# The manifest group of a per-issuance password is smime[-dir]/CERTNAME/ID.
GROUP_RE='^[^/]+/(.+)/[0-9a-f]{6}$'
declare -A LABEL_TAKEN=()
for ((g = 0; g < ${#G_MEM[@]}; g++)); do
    dates=()
    for i in ${G_MEM[g]}; do dates+=("$(iso_date "${R_START[i]}")"); done
    mapfile -t dsort < <(printf '%s\n' "${dates[@]}" | sort)
    [[ ${G_GROUP[g]} =~ ${GROUP_RE} ]] \
        || die "unexpected payload group '${G_GROUP[g]}'"
    label="${BASH_REMATCH[1]} [${dsort[0]}]"
    case ${label} in Title|UserName|Password|URL|Notes) label+=" (pw)" ;; esac
    base=${label}; n=2
    while [ -n "${LABEL_TAKEN[${label}]+x}" ]; do
        label="${base} #${n}"
        n=$((n + 1))
    done
    LABEL_TAKEN[${label}]=1
    G_LABEL[g]=${label}
done

ORDER=()
mapfile -t ORDER < <(
    for ((g = 0; g < ${#G_LABEL[@]}; g++)); do
        printf '%s\t%s\n' "${G_LABEL[g]}" "${g}"
    done | sort -t$'\t' -k1,1 | cut -f2)

# Entry time: the installer's mtime (a new password means a new installer), so
# an unchanged installer means no update
if [ "${FORCE}" -eq 1 ]; then
    MOD=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
else
    MOD=$(file_mtime_iso "${INSTALLER}")
fi

fi   # -n INSTALLER

# ------------------------------------------------------------------- plan

print_plan() {
    local g i k s m
    if [ "${EXPORT_MASTER}" -eq 1 ]; then
        echo "Master password: entry '${MASTER_TITLE}'"
        echo "  (PKI keychain item ${MASTER_SERVICE})"
    fi
    if [ -n "${PROFILE}" ]; then
        echo "MDM profile: ${PROFILE} (PKI keychain; PLAIN TEXT passwords)"
        echo "Entry:       ${GROUP}/${TITLE}, attachment ${PROFILE}.mobileconfig"
        echo "Database:    ${DB}"
        return 0
    fi
    if [ -z "${INSTALLER}" ]; then
        echo "Database:    ${DB:-none (--xml-out)}"
        return 0
    fi
    echo "S/MIME installer: ${INSTALLER}"
    echo "Entry title: ${TITLE}${GROUP:+  (group ${GROUP})}"
    if [ -n "${DB}" ]; then echo "Database:    ${DB}"; fi
    echo
    echo "Password field: installer password (PKI keychain);" \
         "it decrypts the payload"
    echo "The payload holds ${#M_TYPE[@]} item(s):"
    for ((m = 0; m < ${#M_TYPE[@]}; m++)); do
        parse_name "${M_FILE[m]}"
        echo "   ${M_TYPE[m]}: '${CN}' (expires ${EXPIRY})"
    done
    if [ "${INDIVIDUAL}" -eq 0 ]; then
        echo
        echo "Individual .p12 passwords: not stored" \
             "(--individual-smime-passwords)"
        return 0
    fi
    echo
    k=0
    for g in "${ORDER[@]}"; do
        k=$((k + 1))
        echo "${k}) ${G_LABEL[g]}"
        for i in ${G_MEM[g]}; do
            echo "   ${R_FILE[i]}"
            echo "       ${R_NOTE[i]}; ends ${R_END[i]}"
        done
        echo "   password: the .p12.pass file(s) in the payload"
    done
    if [ "${#SKIPPED[@]}" -gt 0 ]; then
        echo
        echo "NOT stored (cannot be opened):"
        for s in "${SKIPPED[@]}"; do
            echo "  ${s%%|*}"
            echo "${s#*|}" | fold -s -w 68 | sed 's/^/      /'
        done
    fi
    echo
    echo "${#G_MEM[@]} individual password(s) for ${#R_FILE[@]} .p12 file(s)."
}

print_plan

if [ "${DRYRUN}" -eq 1 ]; then exit 0; fi
if [ "${#SKIPPED[@]}" -gt 0 ] && [ "${PKI_ASSUME_YES:-0}" != "0" ]; then
    die "${#SKIPPED[@]} .p12 cannot be opened (see above)"
fi

confirm() {
    local ans
    if [ "${PKI_ASSUME_YES:-0}" != "0" ]; then return 0; fi
    read -r -p "$1 [y/N] " ans </dev/tty || return 1
    [[ ${ans} =~ ^[yY]([eE][sS])?$ ]]
}
if [ "${PKI_ASSUME_YES:-0}" = "0" ]; then
    echo "(PKI_ASSUME_YES=1 skips prompts.)" >&2
fi

# -------------------------------------------------------------------- XML

TS_OLD="2000-01-01T00:00:00Z"   # never newer than what the database has

# --export-master: read the master password before anything is written
MASTER_PW="" MASTER_MOD=${TS_OLD}
if [ "${EXPORT_MASTER}" -eq 1 ]; then
    MASTER_PW=$("${PYTHON}" "${SCRIPT_DIR}/pki_keychain.py" export-master) \
        || die "cannot read the PKI master password"
    [ -n "${MASTER_PW}" ] || die "the master password is empty"
    MASTER_KEYFILE=${PKI_KEYCHAIN_KEYFILE:-${PKI_ROOT}/keepassxc/keyfile/pki-structure.keyx}
    if [ "${FORCE}" -eq 1 ]; then
        MASTER_MOD=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    elif [ -f "${MASTER_KEYFILE}" ]; then
        MASTER_MOD=$(file_mtime_iso "${MASTER_KEYFILE}")
    fi
fi

# xml_esc STRING ALLOW_NEWLINES: STRING escaped for XML text
xml_esc() {
    local s=$1 t=$1
    if [ "$2" -eq 1 ]; then t=${s//$'\n'/}; fi
    if [[ ${t} =~ [[:cntrl:]] ]]; then
        die "a value contains a control character"
    fi
    s=${s//&/'&amp;'}
    s=${s//</'&lt;'}
    s=${s//>/'&gt;'}
    s=${s//\"/'&quot;'}
    s=${s//\'/'&apos;'}
    printf '%s' "${s}"
}

# det_uuid KEY: 16 bytes derived from KEY, base64 (a KeePass UUID)
det_uuid() {
    printf '%s' "keepass-uuid:$1" | "${OPENSSL}" dgst -sha256 -binary \
        | head -c 16 | "${OPENSSL}" base64 -A
}

emit_times() {   # emit_times MODIFIED
    printf '\t\t\t<Times>\n'
    printf '\t\t\t\t<CreationTime>%s</CreationTime>\n' "$1"
    printf '\t\t\t\t<LastModificationTime>%s</LastModificationTime>\n' "$1"
    printf '\t\t\t\t<LastAccessTime>%s</LastAccessTime>\n' "$1"
    printf '\t\t\t\t<ExpiryTime>%s</ExpiryTime>\n' "$1"
    printf '\t\t\t\t<Expires>False</Expires>\n'
    printf '\t\t\t\t<UsageCount>0</UsageCount>\n'
    printf '\t\t\t\t<LocationChanged>%s</LocationChanged>\n' "${TS_OLD}"
    printf '\t\t\t</Times>\n'
}

emit_group_open() {   # emit_group_open NAME PATH
    local n u
    n=$(xml_esc "$1" 0)
    u=$(det_uuid "group:$2")
    printf '\t\t<Group>\n\t\t\t<UUID>%s</UUID>\n' "${u}"
    printf '\t\t\t<Name>%s</Name>\n' "${n}"
    emit_times "${TS_OLD}"
    printf '\t\t\t<IsExpanded>True</IsExpanded>\n'
}

emit_string() {   # emit_string KEY VALUE [protect]
    local k v p=""
    k=$(xml_esc "$1" 0)
    v=$(xml_esc "$2" 0)
    if [ "${3:-}" = protect ]; then p=' ProtectInMemory="True"'; fi
    printf '\t\t\t<String><Key>%s</Key><Value%s>%s</Value></String>\n' \
        "${k}" "${p}" "${v}"
}

build_notes() {
    local g i m
    echo "S/MIME credentials installer. This Notes text holds no passwords."
    echo "Installer: ${INST_BASE}"
    echo "The Password field is the installer password (PKI keychain: ${INST_BASE});"
    echo "it decrypts the installer's payload."
    echo "Data as of ${MOD} (newest source file)."
    echo
    echo "The installer contains:"
    for ((m = 0; m < ${#M_TYPE[@]}; m++)); do
        parse_name "${M_FILE[m]}"
        echo "  ${M_TYPE[m]}: ${CN} (expires ${EXPIRY}) [${M_NOTE[m]}]"
    done
    if [ "${INDIVIDUAL}" -eq 0 ]; then return 0; fi
    echo
    echo "Each custom attribute is the password of one issuance's .p12 files."
    echo "Copy one: keepassxc-cli clip -a 'ATTRIBUTE' DB 'TITLE'"
    for g in "${ORDER[@]}"; do
        echo
        echo "${G_LABEL[g]}"
        for i in ${G_MEM[g]}; do
            echo "  ${R_FILE[i]}: ${R_NOTE[i]}; ends ${R_END[i]}"
        done
    done
}

emit_entry() {
    local g pw notes
    notes=$(build_notes)
    printf '\t\t<Entry>\n\t\t\t<UUID>%s</UUID>\n' \
        "$(det_uuid "entry:${GROUP}/${TITLE}")"
    printf '\t\t\t<IconID>0</IconID>\n\t\t\t<Tags>pki;smime</Tags>\n'
    emit_times "${MOD}"
    emit_string Title "${TITLE}"
    emit_string UserName ""
    pw=${INSTALLER_PW}
    emit_string Password "${pw}" protect
    emit_string URL ""
    printf '\t\t\t<String><Key>Notes</Key><Value>%s</Value></String>\n' \
        "$(xml_esc "${notes}" 1)"
    for g in "${ORDER[@]}"; do
        pw=$(read_pw "${G_SRC[g]}" 1)
        emit_string "${G_LABEL[g]}" "${pw}" protect
    done
    pw=""
    printf '\t\t</Entry>\n'
}

build_master_notes() {
    echo "PKI-Structure KeePassXC master password. This Notes text holds no secrets."
    echo "Master: root file keepassxc/master/pki-structure.pass, else"
    echo "login keychain item ${MASTER_SERVICE}."
    echo "keepassxc/keychain/pki-structure.kdbx opens only with it and the key"
    echo "file keepassxc/keyfile/pki-structure.keyx: back up all three."
    echo "Data as of ${MASTER_MOD}."
}

emit_master_entry() {
    local notes
    notes=$(build_master_notes)
    printf '\t\t<Entry>\n\t\t\t<UUID>%s</UUID>\n' \
        "$(det_uuid "entry:${GROUP}/${MASTER_TITLE}")"
    printf '\t\t\t<IconID>0</IconID>\n\t\t\t<Tags>pki;master</Tags>\n'
    emit_times "${MASTER_MOD}"
    emit_string Title "${MASTER_TITLE}"
    emit_string UserName ""
    emit_string Password "${MASTER_PW}" protect
    emit_string URL ""
    printf '\t\t\t<String><Key>Notes</Key><Value>%s</Value></String>\n' \
        "$(xml_esc "${notes}" 1)"
    printf '\t\t</Entry>\n'
}

emit_xml() {
    local parts=() p path=""
    printf '<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n'
    printf '<KeePassFile>\n\t<Meta>\n'
    printf '\t\t<Generator>%s</Generator>\n' "${0##*/}"
    printf '\t</Meta>\n\t<Root>\n'
    emit_group_open "${KEEPASS_GROUP_NAME}" ""
    if [ -n "${GROUP}" ]; then IFS=/ read -r -a parts <<<"${GROUP}"; fi
    for p in "${parts[@]}"; do
        path="${path}/${p}"
        emit_group_open "${p}" "${path}"
    done
    if [ -n "${INSTALLER}" ]; then emit_entry; fi
    if [ "${EXPORT_MASTER}" -eq 1 ]; then emit_master_entry; fi
    for p in "${parts[@]}"; do printf '\t\t</Group>\n'; done
    printf '\t\t</Group>\n\t</Root>\n</KeePassFile>\n'
}

if [ -n "${XML_OUT}" ]; then
    if [ -d "${XML_OUT}" ]; then die "${XML_OUT} is a directory"; fi
    warn "${XML_OUT} will hold the passwords in PLAIN TEXT;" \
         "delete it after use"
    if [ -e "${XML_OUT}" ] || [ -L "${XML_OUT}" ]; then
        if ! confirm "${XML_OUT} exists. Overwrite it?"; then
            die "Aborted; ${XML_OUT} is unchanged."
        fi
        rm -f -- "${XML_OUT}"   # replaced, not written through: new file, 0600
    elif ! confirm "Write it?"; then
        die "Aborted."
    fi
    ( set -o noclobber; emit_xml > "${XML_OUT}" )
    echo "Wrote ${XML_OUT} (mode 0600)."
    exit 0
fi

# ------------------------------------------------------- merge into the DB

KPCLI=""
for c in "${KEEPASSXC_CLI:-}" keepassxc-cli \
         /Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli; do
    if [ -n "${c}" ] && command -v "${c}" >/dev/null 2>&1; then
        KPCLI=$(command -v "${c}"); break
    fi
done
if [ -z "${KPCLI}" ]; then
    die "keepassxc-cli not found (install KeePassXC, or set KEEPASSXC_CLI)"
fi
if [ ! -f "${DB}" ]; then
    die "no database ${DB}. This merges into an existing one;" \
        "to start one: keepassxc-cli db-create -p ${DB}"
fi
if [ ! -w "${DB}" ]; then die "cannot write ${DB}"; fi

if ! confirm "Merge this entry into ${DB##*/}?"; then die "Aborted."; fi

if [ "${NOPASS}" -eq 0 ] && [ "${KP_PROMPT}" -eq 0 ]; then
    if [ ! -r /dev/tty ]; then die "no terminal for the master password"; fi
    IFS= read -r -s -p "Master password of ${DB##*/}: " KP_PASS </dev/tty \
        || die "no master password read"
    echo >&2
fi

# kp NLINES ARGS...: run keepassxc-cli with NLINES copies of the master
# password on stdin (none with --kp-prompt or --no-password)
kp() {
    local n=$1 i
    shift
    if [ "${KP_PROMPT}" -eq 1 ] || [ "${NOPASS}" -eq 1 ] \
       || [ "${n}" -eq 0 ]; then
        "${KPCLI}" "$@"
    else
        for ((i = 0; i < n; i++)); do printf '%s\n' "${KP_PASS}"; done \
            | "${KPCLI}" "$@"
    fi
}

IMPORT_ARGS=() DB_ARGS=() IMP_LINES=0
if [ "${NOPASS}" -eq 0 ]; then IMPORT_ARGS+=(-p); IMP_LINES=2; fi
if [ -n "${KEYFILE}" ]; then
    IMPORT_ARGS+=(--set-key-file "${KEYFILE}")
    DB_ARGS+=(-k "${KEYFILE}")
fi
if [ "${NOPASS}" -eq 1 ]; then DB_ARGS+=(--no-password); fi

# ------------------------------------------------ MDM profile (attachment)

# backup_db: copy --db to DB.bak-<time> unless --no-backup
backup_db() {
    local bak

    if [ "${BACKUP}" -eq 1 ]; then
        bak="${DB}.bak-$(date -u '+%Y%m%dT%H%M%SZ')"
        cp -p "${DB}" "${bak}"
        chmod 0600 "${bak}"
        echo "Backup: ${bak}"
    fi
}

# keepassxc-cli cannot import attachments from XML, so a profile goes into
# --db directly: group, entry, attachment. Unchanged content is skipped.
if [ -n "${PROFILE}" ]; then
    ENTRY="${GROUP}/${TITLE}"
    PROFILE_FILE="${TMPD}/${PROFILE}.mobileconfig"
    "${PYTHON}" "${SCRIPT_DIR}/pki_keychain.py" profile-get --name "${PROFILE}" \
        --out "${PROFILE_FILE}" 2>"${TMPD}/profile.err" \
        || { cat "${TMPD}/profile.err" >&2; die "cannot extract profile '${PROFILE}'"; }
    SHA=$("${OPENSSL}" dgst -sha256 "${PROFILE_FILE}" | sed 's/^.*= *//')
    LISTING=$(kp 1 ls -R -f "${DB_ARGS[@]}" "${DB}")
    HAVE_ENTRY=0
    if grep -qxF -- "${ENTRY}" <<<"${LISTING}"; then HAVE_ENTRY=1; fi
    if [ "${HAVE_ENTRY}" -eq 1 ] && [ "${FORCE}" -eq 0 ]; then
        OLD_NOTES=$(kp 1 show -a Notes "${DB_ARGS[@]}" "${DB}" "${ENTRY}") || OLD_NOTES=""
        if grep -qF -- "SHA-256 ${SHA}" <<<"${OLD_NOTES}"; then
            echo "${ENTRY} is up to date in ${DB##*/}."
            exit 0
        fi
    fi
    backup_db
    if ! grep -qxF -- "${GROUP}/" <<<"${LISTING}"; then
        kp 1 mkdir "${DB_ARGS[@]}" "${DB}" "${GROUP}" >/dev/null \
            || die "cannot create the group ${GROUP}"
    fi
    if [ "${HAVE_ENTRY}" -eq 1 ]; then
        kp 1 rm "${DB_ARGS[@]}" "${DB}" "${ENTRY}" >/dev/null \
            || die "cannot replace ${ENTRY}"
        # leave no copy of the old profile in the recycle bin
        kp 1 rm "${DB_ARGS[@]}" "${DB}" "Recycle Bin/${TITLE}" >/dev/null 2>&1 || true
    fi
    NOTES=$(printf '%s\n' \
        "Signed MDM profile '${PROFILE}' (PKI keychain). The attachment" \
        "holds account passwords in PLAIN TEXT." \
        "SHA-256 ${SHA}" \
        "Added $(date -u '+%Y-%m-%dT%H:%M:%SZ').")
    kp 1 add "${DB_ARGS[@]}" --notes "${NOTES}" "${DB}" "${ENTRY}" >/dev/null \
        || die "cannot add ${ENTRY}"
    if ! kp 1 attachment-import "${DB_ARGS[@]}" "${DB}" "${ENTRY}" \
            "${PROFILE}.mobileconfig" "${PROFILE_FILE}" >/dev/null; then
        kp 1 rm "${DB_ARGS[@]}" "${DB}" "${ENTRY}" >/dev/null 2>&1 || true
        die "cannot attach ${PROFILE}.mobileconfig"
    fi
    echo "Added '${ENTRY}' with the attachment ${PROFILE}.mobileconfig."
    echo "It holds account passwords in PLAIN TEXT: protect ${DB##*/}."
    exit 0
fi

STAGE="${TMPD}/staging.kdbx"
XML="${TMPD}/entry.xml"

emit_xml > "${XML}"
kp "${IMP_LINES}" import "${IMPORT_ARGS[@]}" "${XML}" "${STAGE}" >/dev/null \
    || die "keepassxc-cli import failed"
rm -f "${XML}"      # the plain-text XML is gone as soon as it is imported
rm -rf "${WORK}"    # and so is the decrypted payload

echo "Preview of the merge into ${DB##*/}:"
kp 1 merge --dry-run -s "${DB_ARGS[@]}" "${DB}" "${STAGE}" | sed 's/^/  /' \
    || die "merge preview failed"
if ! confirm "Apply it?"; then die "Aborted; ${DB##*/} is unchanged."; fi

backup_db
kp 1 merge -s "${DB_ARGS[@]}" "${DB}" "${STAGE}" || die "merge failed"

echo "Merged. Entry found by:"
kp 1 search "${DB_ARGS[@]}" "${DB}" "${TITLE}" | sed 's/^/  /' \
    || warn "could not confirm the entry; open the database and check"
echo "A copy of the database was written before the merge; delete old"
echo "${DB##*/}.bak-* files you no longer need."

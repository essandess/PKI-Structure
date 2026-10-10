#!/usr/bin/env bash

# create_keepass_entry.sh -- store S/MIME .p12 passwords in KeePassXC.
#
# Usage: create_keepass_entry.sh --db FILE [--key-file FILE | --no-password]
#            [--title TITLE] [--group PATH] [--extra-pki-dir DIR]...
#            [--allow-line1] [--force-update] [--no-backup] [--kp-prompt]
#            [-n|--dry-run] 'NAME_GLOB' ...
#        create_keepass_entry.sh --xml-out FILE [--title TITLE]
#            [--group PATH] [--extra-pki-dir DIR]... 'NAME_GLOB' ...
#
# Selects .p12 files as create_credentials.sh does: single-quote each
# 'NAME_GLOB'. It is a bash glob with brace expansion, for example
# 'persona_*' or 'personb_{gmail,comcast}_2026', matched against <name> in
# smime/private/<name>-{signature,encryption}[.<sha1>].p12. --extra-pki-dir
# DIR (repeatable) also searches DIR/smime, a tree with the same layout.
#
# Each password is checked against its .p12 before it is stored. It is
#   <p12>.pass      one per issuance, shared by that issuance's signature
#                   and encryption .p12 (written by create_smime.sh), or,
#                   for an older .p12 that has no .pass file,
#   passphrase.txt  line 2 of the tree's smime/private/passphrase.txt.
# Line 1 is the private-key passphrase and stays in the PKI tree. It is
# stored only with --allow-line1, for a .p12 that opens with nothing else.
#
# Result: ONE entry in an existing KeePassXC database, with one protected
# custom attribute per issuance, labeled '<name> [<issued>]'. Its Notes list
# the .p12 files each one opens, never a password. Title: --title, default
# 'S/MIME .p12 passwords: NAME_GLOB ...'. Copy one password with
#   keepassxc-cli clip -a 'ATTRIBUTE' DB 'TITLE'
#
# How it gets there: keepassxc-cli can only import XML into a NEW database,
# so the entry is written as KeePass 2 XML, imported into a staging database
# with the same credentials, and merged into --db. The merge is shown with
# --dry-run first, and --db is copied to DB.bak-<time> unless --no-backup.
# Entry and group UUIDs are derived from title and group path, and the
# entry's modification time from its source files, so a re-run updates the
# entry in place and changes nothing when the sources did not change.
# --force-update stamps it with the current time instead.
#
# Secrets: never in argv or the environment; the master password is read
# once from the terminal and piped to keepassxc-cli (--kp-prompt lets
# keepassxc-cli ask itself). The plain-text XML exists only in a private
# temporary directory, removed on exit. --xml-out FILE writes that XML to
# FILE (mode 0600, never overwritten) and stops: delete it after use.
#
# -n lists what would be stored and stops. PKI_ASSUME_YES=1 skips the
# prompts and makes any .p12 that cannot be opened an error.
# Needs bash 4.4+, openssl (bin/define_openssl.sh), keepassxc-cli.

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

# Same helpers as pki_structure.sh, when present
if [ -f "${SCRIPT_DIR}/pki_common.sh" ]; then
    . "${SCRIPT_DIR}/pki_common.sh"
fi
if [ -f "${SCRIPT_DIR}/define_openssl.sh" ]; then
    . "${SCRIPT_DIR}/define_openssl.sh"
fi
OPENSSL=${OPENSSL:-openssl}

die()  { echo "Error: $*" >&2; exit 1; }
warn() { echo "Warning: $*" >&2; }

usage() {
    sed -n '3,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    echo "See the comments at the top of ${0##*/} for details."
}

# ---------------------------------------------------------------- options

DB="" KEYFILE="" NOPASS=0 TITLE="" GROUP="" XML_OUT=""
ALLOW_LINE1=0 FORCE=0 BACKUP=1 KP_PROMPT=0 DRYRUN=0
EXTRA=()
GLOBS=()

need_arg() { if [ "$1" -lt 2 ]; then die "$2 needs an argument"; fi; }

while [ $# -gt 0 ]; do
    case $1 in
        --db)            need_arg $# "$1"; DB=$2; shift 2 ;;
        --key-file)      need_arg $# "$1"; KEYFILE=$2; shift 2 ;;
        --no-password)   NOPASS=1; shift ;;
        --title)         need_arg $# "$1"; TITLE=$2; shift 2 ;;
        --group)         need_arg $# "$1"; GROUP=$2; shift 2 ;;
        --extra-pki-dir) need_arg $# "$1"; EXTRA+=("$2"); shift 2 ;;
        --xml-out)       need_arg $# "$1"; XML_OUT=$2; shift 2 ;;
        --allow-line1)   ALLOW_LINE1=1; shift ;;
        --force-update)  FORCE=1; shift ;;
        --no-backup)     BACKUP=0; shift ;;
        --kp-prompt)     KP_PROMPT=1; shift ;;
        -n|--dry-run)    DRYRUN=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        --)              shift; GLOBS+=("$@"); break ;;
        -*)              usage >&2; die "unknown option: $1" ;;
        *)               GLOBS+=("$1"); shift ;;
    esac
done

if [ "${#GLOBS[@]}" -eq 0 ]; then usage >&2; die "no NAME_GLOB given"; fi
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

GLOB_OK='^[][A-Za-z0-9_.*?,{}-]+$'
for g in "${GLOBS[@]}"; do
    if ! [[ ${g} =~ ${GLOB_OK} ]]; then
        die "bad NAME_GLOB '${g}': letters, digits and _ . - * ? [] {} , only"
    fi
done

TREES=("${PKI_ROOT}")
for d in "${EXTRA[@]}"; do
    if [ ! -d "${d}" ]; then die "--extra-pki-dir: not a directory: ${d}"; fi
    TREES+=("$(cd "${d}" && pwd)")
done

if [ -z "${TITLE}" ]; then TITLE="S/MIME .p12 passwords: ${GLOBS[*]}"; fi

# ---------------------------------------------------------------- helpers

# Brace expansion only (no pathname expansion) of a validated glob
expand_braces() { ( set -f; eval "printf '%s\n' $1" ); }

GLOB_EXP=()
GLOB_HITS=()
for g in "${GLOBS[@]}"; do
    GLOB_EXP+=("$(expand_braces "${g}")")
    GLOB_HITS+=(0)
done

# match_glob NAME INDEX: does NAME match the INDEXth glob?
match_glob() {
    local pat
    while IFS= read -r pat; do
        # shellcheck disable=SC2053  # unquoted on purpose: a glob
        if [[ $1 == ${pat} ]]; then return 0; fi
    done <<<"${GLOB_EXP[$2]}"
    return 1
}

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

# PROBE_ERR, P_SERIAL, P_START, P_END, P_EXPIRED describe the last .p12
# opened by probe
PROBE_ERR="" P_SERIAL="" P_START="" P_END="" P_EXPIRED=0

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
    if ! info=$("${OPENSSL}" x509 -noout -serial -startdate -enddate \
                    <<<"${pem}" 2>/dev/null); then
        PROBE_ERR="unreadable certificate"; return 1
    fi
    while IFS='=' read -r key val; do
        case ${key} in
            serial)    P_SERIAL=${val^^} ;;
            notBefore) P_START=${val} ;;
            notAfter)  P_END=${val} ;;
        esac
    done <<<"${info}"
    P_EXPIRED=0
    if ! "${OPENSSL}" x509 -noout -checkend 0 <<<"${pem}" >/dev/null 2>&1; then
        P_EXPIRED=1
    fi
    return 0
}

# read_pw FILE LINE: that line of FILE, without its newline
read_pw() {
    local v
    v=$(sed -n "${2}p" "$1")
    printf '%s' "${v%$'\r'}"
}

# index_status TREE SERIAL: status of the serial in the CA's index.txt
index_status() {
    local idx="$1/${ISSUERCADIR:-intermediate}/index.txt"
    if [ ! -f "${idx}" ]; then
        idx="${PKI_ROOT}/${ISSUERCADIR:-intermediate}/index.txt"
    fi
    if [ ! -f "${idx}" ]; then echo "not checked"; return 0; fi
    awk -F'\t' -v s="$2" '
        BEGIN { sub(/^0+/, "", s) }
        { a = toupper($4); sub(/^0+/, "", a) }
        a == s {
            if ($1 == "V") out = "valid"
            else if ($1 == "R") {
                out = "revoked"
                c = index($3, ",")
                if (c) out = out " (" substr($3, c + 1) ")"
            } else if ($1 == "E") out = "expired"
            else out = $1
            print out; found = 1; exit
        }
        END { if (!found) print "not in index" }' "${idx}"
}

# resolve_password P12 TREE: find the password that opens P12. On success
# SRC_FILE and SRC_LINE say where it is; on failure FAIL says why.
SRC_FILE="" SRC_LINE="" FAIL=""
resolve_password() {
    local p12=$1 tree=$2 pw f
    SRC_FILE="" SRC_LINE="" FAIL=""
    if [ -f "${p12}.pass" ]; then
        pw=$(read_pw "${p12}.pass" 1)
        if [ -z "${pw}" ]; then FAIL="${p12##*/}.pass is empty"; return 1; fi
        if probe "${p12}" "${pw}"; then
            SRC_FILE="${p12}.pass"; SRC_LINE=1; return 0
        fi
        FAIL="its .pass file does not open it (${PROBE_ERR})"
        return 1
    fi
    f="${tree}/smime/private/passphrase.txt"
    if [ ! -f "${f}" ]; then
        FAIL="no .pass file, and no ${f#"${PKI_ROOT}"/}"
        return 1
    fi
    pw=$(read_pw "${f}" 2)
    if [ -n "${pw}" ] && probe "${p12}" "${pw}"; then
        SRC_FILE=${f}; SRC_LINE=2; return 0
    fi
    pw=$(read_pw "${f}" 1)
    if [ -n "${pw}" ] && probe "${p12}" "${pw}"; then
        if [ "${ALLOW_LINE1}" -eq 1 ]; then
            SRC_FILE=${f}; SRC_LINE=1; return 0
        fi
        FAIL="opens only with passphrase.txt line 1, the key passphrase:"
        FAIL="${FAIL} not stored (--allow-line1)"
        return 1
    fi
    FAIL="no .pass file; passphrase.txt line 2 does not open it (${PROBE_ERR})"
    return 1
}

# tree_name TREE: short name for display
tree_name() {
    if [ "$1" = "${PKI_ROOT}" ]; then echo "PKI_ROOT"; else echo "${1##*/}"; fi
}

# abbr FILENAME: shorten the 40-hex SHA1 in a name, for display
abbr() {
    local s=$1
    if [[ $s =~ ^(.*\.)([0-9a-f]{8})[0-9a-f]{32}(\.p12)$ ]]; then
        s="${BASH_REMATCH[1]}${BASH_REMATCH[2]}~${BASH_REMATCH[3]}"
    fi
    printf '%s' "${s}"
}

# ------------------------------------------------- find and open the .p12

C_TREE=() C_FILE=() C_NAME=()
IGNORED=0
NAME_RE='^(.+)-(signature|encryption)(\.[0-9a-f]{40})?\.p12$'
for tree in "${TREES[@]}"; do
    if [ ! -d "${tree}/smime/private" ]; then
        warn "no ${tree}/smime/private"
        continue
    fi
    for p12 in "${tree}"/smime/private/*.p12; do
        if [[ ${p12##*/} =~ ${NAME_RE} ]]; then
            C_TREE+=("${tree}")
            C_FILE+=("${p12}")
            C_NAME+=("${BASH_REMATCH[1]}")
        else
            IGNORED=$((IGNORED + 1))
        fi
    done
done
if [ "${IGNORED}" -gt 0 ]; then
    warn "${IGNORED} .p12 not named" \
         "<name>-{signature,encryption}[.<sha1>].p12 were ignored"
fi

R_TREE=() R_FILE=() R_NAME=() R_SRC=() R_LINE=() R_START=() R_END=()
R_STATUS=() R_HASH=()
SKIPPED=()
for ((c = 0; c < ${#C_FILE[@]}; c++)); do
    matched=0
    for ((gi = 0; gi < ${#GLOBS[@]}; gi++)); do
        if match_glob "${C_NAME[c]}" "${gi}"; then
            matched=1
            GLOB_HITS[gi]=$((GLOB_HITS[gi] + 1))
        fi
    done
    if [ "${matched}" -eq 0 ]; then continue; fi
    if resolve_password "${C_FILE[c]}" "${C_TREE[c]}"; then
        pw=$(read_pw "${SRC_FILE}" "${SRC_LINE}")
        h=$(printf '%s' "${pw}" | "${OPENSSL}" dgst -sha256 | sed 's/^.* //')
        pw=""
        st=$(index_status "${C_TREE[c]}" "${P_SERIAL}")
        if [ "${P_EXPIRED}" -eq 1 ]; then
            if [ "${st}" = valid ]; then st=expired
            else st="expired, ${st}"; fi
        fi
        R_TREE+=("${C_TREE[c]}"); R_FILE+=("${C_FILE[c]}")
        R_NAME+=("${C_NAME[c]}"); R_SRC+=("${SRC_FILE}")
        R_LINE+=("${SRC_LINE}"); R_START+=("${P_START}"); R_END+=("${P_END}")
        R_STATUS+=("${st}"); R_HASH+=("${h}")
    else
        SKIPPED+=("${C_FILE[c]}|${FAIL}")
    fi
done

for ((gi = 0; gi < ${#GLOBS[@]}; gi++)); do
    if [ "${GLOB_HITS[gi]}" -eq 0 ]; then
        warn "'${GLOBS[gi]}' matches no .p12"
    fi
done
if [ "${#R_FILE[@]}" -eq 0 ] && [ "${#SKIPPED[@]}" -eq 0 ]; then
    echo "Names found:" >&2
    printf '  %s\n' "${C_NAME[@]}" | sort -u | sed -n '1,30p' >&2
    die "no .p12 matches ${GLOBS[*]}"
fi

# ------------------------------------- group by password (= by issuance)

declare -A GIDX=()
G_TREE=() G_MEM=() G_KIND=() G_LINE=() G_SRC=() G_LABEL=()
for ((i = 0; i < ${#R_FILE[@]}; i++)); do
    key="${R_TREE[i]}|${R_HASH[i]}"
    if [ -z "${GIDX[${key}]+x}" ]; then
        GIDX[${key}]=${#G_TREE[@]}
        G_TREE+=("${R_TREE[i]}"); G_MEM+=(""); G_SRC+=("${R_SRC[i]}")
        G_LINE+=("${R_LINE[i]}")
        if [[ ${R_SRC[i]} == *.pass ]]; then
            G_KIND+=(pass)
        else
            G_KIND+=("line${R_LINE[i]}")
        fi
        G_LABEL+=("")
    fi
    g=${GIDX[${key}]}
    G_MEM[g]="${G_MEM[g]} ${i}"
done

declare -A LABEL_TAKEN=()
for ((g = 0; g < ${#G_TREE[@]}; g++)); do
    names=() dates=()
    for i in ${G_MEM[g]}; do
        names+=("${R_NAME[i]}")
        dates+=("$(iso_date "${R_START[i]}")")
    done
    mapfile -t uniq < <(printf '%s\n' "${names[@]}" | sort -u)
    mapfile -t dsort < <(printf '%s\n' "${dates[@]}" | sort)
    if [ "${G_KIND[g]}" = pass ]; then
        label="${uniq[0]}"
        if [ "${#uniq[@]}" -gt 1 ]; then label+=" +$((${#uniq[@]} - 1))"; fi
        label+=" [${dsort[0]}]"
    else
        label="older .p12, passphrase.txt line ${G_LINE[g]}"
        label+=" [$(tree_name "${G_TREE[g]}")]"
    fi
    case ${label} in Title|UserName|Password|URL|Notes) label+=" (pw)" ;; esac
    base=${label}; n=2
    while [ -n "${LABEL_TAKEN[${label}]+x}" ]; do
        label="${base} #${n}"
        n=$((n + 1))
    done
    LABEL_TAKEN[${label}]=1
    G_LABEL[g]=${label}
done

mapfile -t ORDER < <(
    for ((g = 0; g < ${#G_LABEL[@]}; g++)); do
        printf '%s\t%s\n' "${G_LABEL[g]}" "${g}"
    done | sort -t$'\t' -k1,1 | cut -f2)

# Entry time: the newest source file, so unchanged sources mean no update
if [ "${FORCE}" -eq 1 ]; then
    MOD=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
else
    newest=""
    for ((i = 0; i < ${#R_FILE[@]}; i++)); do
        for f in "${R_FILE[i]}" "${R_SRC[i]}"; do
            if [ -z "${newest}" ] || [ "${f}" -nt "${newest}" ]; then
                newest=${f}
            fi
        done
    done
    for tree in "${TREES[@]}"; do
        f="${tree}/${ISSUERCADIR:-intermediate}/index.txt"
        if [ -f "${f}" ] && [ "${f}" -nt "${newest}" ]; then newest=${f}; fi
    done
    MOD=$(file_mtime_iso "${newest}")
fi

# ------------------------------------------------------------------- plan

print_plan() {
    local g i k s base
    echo "S/MIME .p12 passwords for: ${GLOBS[*]}"
    echo "Entry title: ${TITLE}${GROUP:+  (group ${GROUP})}"
    if [ -n "${DB}" ]; then echo "Database:    ${DB}"; fi
    echo
    k=0
    for g in "${ORDER[@]}"; do
        k=$((k + 1))
        echo "${k}) ${G_LABEL[g]}"
        for i in ${G_MEM[g]}; do
            base=${R_FILE[i]##*/}
            echo "   $(abbr "${base}")"
            echo "       ${R_STATUS[i]}; expires ${R_END[i]}"
        done
        case ${G_KIND[g]} in
            pass)  echo "   password: each .p12.pass file (same in all)" ;;
            line2) echo "   password: smime/private/passphrase.txt line 2" ;;
            line1) echo "   password: passphrase.txt line 1 (KEY pass)" ;;
        esac
    done
    if [ "${#SKIPPED[@]}" -gt 0 ]; then
        echo
        echo "NOT stored (cannot be opened):"
        for s in "${SKIPPED[@]}"; do
            base=${s%%|*}
            echo "  $(abbr "${base##*/}")"
            echo "      ${s#*|}"
        done
    fi
    echo
    echo "${#G_TREE[@]} password(s) for ${#R_FILE[@]} .p12 file(s)."
}

print_plan

if [ "${DRYRUN}" -eq 1 ]; then exit 0; fi
if [ "${#SKIPPED[@]}" -gt 0 ] && [ "${PKI_ASSUME_YES:-0}" != "0" ]; then
    die "${#SKIPPED[@]} .p12 cannot be opened (see above)"
fi
if [ "${#G_TREE[@]}" -eq 0 ]; then die "nothing to store"; fi

confirm() {
    local ans
    if [ "${PKI_ASSUME_YES:-0}" != "0" ]; then return 0; fi
    read -r -p "$1 [y/N] " ans </dev/tty || return 1
    [[ ${ans} =~ ^[yY]([eE][sS])?$ ]]
}
if [ "${PKI_ASSUME_YES:-0}" = "0" ]; then
    echo "(Set PKI_ASSUME_YES=1 to skip the prompts.)" >&2
fi

# -------------------------------------------------------------------- XML

TS_OLD="2000-01-01T00:00:00Z"   # never newer than what the database has

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
    local g i
    echo "S/MIME .p12 passwords. This Notes text holds no passwords."
    echo "Each custom attribute is the password of one issuance."
    echo "Data as of ${MOD} (newest source file)."
    echo "Copy one: keepassxc-cli clip -a 'ATTRIBUTE' DB 'TITLE'"
    for g in "${ORDER[@]}"; do
        echo
        echo "${G_LABEL[g]}"
        for i in ${G_MEM[g]}; do
            echo "  ${R_FILE[i]##*/}: ${R_STATUS[i]}; expires ${R_END[i]}"
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
    emit_string Password "" protect
    emit_string URL ""
    printf '\t\t\t<String><Key>Notes</Key><Value>%s</Value></String>\n' \
        "$(xml_esc "${notes}" 1)"
    for g in "${ORDER[@]}"; do
        pw=$(read_pw "${G_SRC[g]}" "${G_LINE[g]}")
        emit_string "${G_LABEL[g]}" "${pw}" protect
    done
    pw=""
    printf '\t\t</Entry>\n'
}

emit_xml() {
    local parts=() p path=""
    printf '<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n'
    printf '<KeePassFile>\n\t<Meta>\n'
    printf '\t\t<Generator>%s</Generator>\n' "${0##*/}"
    printf '\t</Meta>\n\t<Root>\n'
    emit_group_open Root ""
    if [ -n "${GROUP}" ]; then IFS=/ read -r -a parts <<<"${GROUP}"; fi
    for p in "${parts[@]}"; do
        path="${path}/${p}"
        emit_group_open "${p}" "${path}"
    done
    emit_entry
    for p in "${parts[@]}"; do printf '\t\t</Group>\n'; done
    printf '\t\t</Group>\n\t</Root>\n</KeePassFile>\n'
}

if [ -n "${XML_OUT}" ]; then
    if [ -e "${XML_OUT}" ]; then die "${XML_OUT} exists; not overwriting"; fi
    warn "${XML_OUT} will hold the passwords in PLAIN TEXT;" \
         "delete it after use"
    if ! confirm "Write it?"; then die "Aborted."; fi
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

TMPD=""
KP_PASS=""
cleanup() {
    KP_PASS=""
    if [ -n "${TMPD}" ]; then rm -rf "${TMPD}"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/kpentry.XXXXXX")
STAGE="${TMPD}/staging.kdbx"
XML="${TMPD}/entry.xml"

emit_xml > "${XML}"
kp "${IMP_LINES}" import "${IMPORT_ARGS[@]}" "${XML}" "${STAGE}" >/dev/null \
    || die "keepassxc-cli import failed"
rm -f "${XML}"      # the plain-text XML is gone as soon as it is imported

echo "Preview of the merge into ${DB##*/}:"
kp 1 merge --dry-run -s "${DB_ARGS[@]}" "${DB}" "${STAGE}" | sed 's/^/  /' \
    || die "merge preview failed"
if ! confirm "Apply it?"; then die "Aborted; ${DB##*/} is unchanged."; fi

if [ "${BACKUP}" -eq 1 ]; then
    BAK="${DB}.bak-$(date -u '+%Y%m%dT%H%M%SZ')"
    cp -p "${DB}" "${BAK}"
    chmod 0600 "${BAK}"
    echo "Backup: ${BAK}"
fi
kp 1 merge -s "${DB_ARGS[@]}" "${DB}" "${STAGE}" || die "merge failed"

echo "Merged. Entry found by:"
kp 1 search "${DB_ARGS[@]}" "${DB}" "${TITLE}" | sed 's/^/  /' \
    || warn "could not confirm the entry; open the database and check"
echo "A copy of the database was written before the merge; delete old"
echo "${DB##*/}.bak-* files you no longer need."

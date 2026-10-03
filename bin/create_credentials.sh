#!/usr/bin/env bash

# create_credentials.sh -- build a macOS credential installer from the PKI tree.
#
# Usage: create_credentials.sh [--include-private-keys] ['NAME_GLOB' ...]
#        create_credentials.sh --ca-only
#
# Writes ONE installer, credentials/install_credentials[_<globs>].sh, after
# listing its payload and asking for confirmation (PKI_ASSUME_YES=1 skips
# the prompt). Always single-quote each 'NAME_GLOB': the shell must not
# expand it. The script itself matches it, as a bash glob with brace
# expansion, against the S/MIME certificate names in smime/certs, for
# example 'persona_*' or 'personb_{gmail,comcast}_2026'. The installer holds
# the certificates matching any 'NAME_GLOB'; with none, no S/MIME
# certificates are included.
#
# Installer contents:
#   System keychain  root CA (trusted), valid intermediate CA, privoxy CA,
#                    unexpired and unrevoked server and adblock2privoxy
#                    certificates
#   Login keychain   matching S/MIME .p12 files, including expired ones
# Items that do not exist are reported and left out of the payload.
# The installer confirms each item and stores no passwords; .p12 passwords
# are prompted for or read from PKI_P12_PASSWORD_<DIRECTORY>.
#
# Private keys: the root, intermediate and privoxy CA keys are never
# bundled. --include-private-keys adds the server .p12 files.
#
# Intermediate validity: openssl verify -crl_check -CRLfile <root CRL>
# -CAfile root.cert.pem (CRL from root/crl/root.crl[.pem] or PKI_ROOT_CRL).
#
# --ca-only: install the root and valid intermediate (.p12 and .cer) into
# this Mac's System keychain; passwords are read from passphrase.txt.
#
# Environment: PKI_ASSUME_YES, PKI_ROOT_CRL, PKI_PRIVOXY_DIRS (default
# privoxy), PKI_SERVER_DIRS (default "server adblock2privoxy").

# exit when any command fails
set -e

set -E   # make the ERR trap fire inside functions and subshells
set -o pipefail
shopt -s inherit_errexit
trap 'rc=$?; echo "Error: $(basename "$0") failed (exit ${rc}) at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

shopt -s nullglob

umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

. "${SCRIPT_DIR}/pki_common.sh"
. "${PKI_ROOT}/bin/define_openssl.sh"

OUTDIR=credentials
SYSTEM_KEYCHAIN=/Library/Keychains/System.keychain
ROOT_CERT=root/certs/root.cert.pem
ROOT_P12=root/private/root.p12
PRIVOXY_DIRS=${PKI_PRIVOXY_DIRS:-privoxy}
SERVER_DIRS=${PKI_SERVER_DIRS:-server adblock2privoxy}
SMIME_RE='^(.+)-(signature|encryption)(\.[0-9a-fA-F]{40})?\.cert\.pem$'
# Characters allowed in a NAME_GLOB. Nothing that is shell syntax, because
# brace expansion is done with eval (see expand_name_glob).
NAME_GLOB_RE='^[][A-Za-z0-9_.,*?{}!^-]+$'

CA_ONLY=0
INCLUDE_PRIVATE_KEYS=0
HELP=0
NAMES=()

die() {
    echo "Error: $*" >&2
    exit 1
}

warn() {
    echo "Warning: $*" >&2
}

while [[ $# -gt 0 ]]; do
    case $1 in
	--ca-only)
	    CA_ONLY=1
	    shift
	    ;;
	--include-private-keys)
	    INCLUDE_PRIVATE_KEYS=1
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

$(basename "$0") [--include-private-keys] ['NAME_GLOB' ...]
$(basename "$0") --ca-only

Creates ONE installer, ./${OUTDIR}/install_credentials[_<globs>].sh, with the
root, intermediate, privoxy CA and server certificates (those that exist)
and the S/MIME certificates matching any 'NAME_GLOB'.

Single-quote every 'NAME_GLOB' so the shell does not expand it against the
current directory. The script matches it, as a bash glob with brace
expansion, against the S/MIME certificate names in smime/certs
(persona_gmail_2026), for example:
  'persona_*'  'personb_{gmail,comcast}_2026'
Without 'NAME_GLOB' no S/MIME certificates are included.
The payload is listed and confirmed (y/N) before the installer is written;
PKI_ASSUME_YES=1 skips the prompt.

  --include-private-keys  also bundle the .p12 of the server certificates
                          (never root, intermediate or privoxy CA)
  --ca-only               install the root and valid intermediate CA
                          (.p12 and .cer) into this Mac's System keychain
USEAGE
    exit 0
fi

if [ "${CA_ONLY}" = "1" ] && [ "${#NAMES[@]}" -gt 0 ]; then
    die "--ca-only does not take 'NAME_GLOB' arguments"
fi

: "${OPENSSL:?OPENSSL is not set by bin/define_openssl.sh}"

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/pki-credentials.XXXXXX")
trap 'rm -rf "${STAGE}"' EXIT

# ---------------------------------------------------------------------
# Functions copied verbatim into the installers (see write_installer).
# They must stay compatible with the bash 3.2 that ships with macOS.
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
    local use_sudo="$1" keychain="$2" file="$3" password="$4" out rc=0
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
	echo "${out}" | sed 's/^/    /' >&2
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

# ---------------------------------------------------------------------
# Generator-only functions
# ---------------------------------------------------------------------

cert_serial() {
    "${OPENSSL}" x509 -noout -serial -in "$1" | sed 's|^serial=||' | tr '[:lower:]' '[:upper:]'
}

cert_is_current() {
    "${OPENSSL}" x509 -checkend 0 -noout -in "$1" >/dev/null 2>&1
}

cert_enddate() {
    "${OPENSSL}" x509 -noout -enddate -in "$1" | sed 's|^notAfter=||'
}

cert_enddate_epoch() {
    local s
    s=$(cert_enddate "$1")
    date -u -d "${s}" +%s 2>/dev/null || date -u -j -f '%b %e %T %Y %Z' "${s}" +%s
}

# Status letter (V, R or E) of a serial in a CA's index.txt; prints nothing
# if the serial is not listed.
ca_index_status() {
    local ca_dir="$1" want="$2" fields n
    [ -f "${ca_dir}/index.txt" ] || return 0
    while IFS=$'\t' read -r -a fields; do
	n=${#fields[@]}
	[ "${n}" -ge 4 ] || continue
	# The serial is third from last (the revocation field is empty for
	# valid entries and tab is collapsed by read), as in pki_common.sh.
	if [ "${fields[$((n-3))]}" = "${want}" ]; then
	    echo "${fields[0]}"
	    return 0
	fi
    done < "${ca_dir}/index.txt"
}

# local_p12_password P12 PASSPHRASE_FILE
# Prints whichever line of the passphrase file opens the .p12 (line 2 per
# the create_*.sh scripts; line 1 as written in root/README.md).
local_p12_password() {
    local p12="$1" pf="$2" n pw
    [ -f "${p12}" ] || return 1
    for n in 2 1; do
	pw=$(sed -n "${n}p" "${pf}")
	[ -n "${pw}" ] || continue
	if PKI_TMP_PW="${pw}" "${OPENSSL}" pkcs12 -legacy -noout -in "${p12}" \
		-passin env:PKI_TMP_PW >/dev/null 2>&1; then
	    printf '%s' "${pw}"
	    return 0
	fi
    done
    return 1
}

verify_root() {
    [ -f "${ROOT_CERT}" ] || die "root certificate '${ROOT_CERT}' not found."
    "${OPENSSL}" verify -CAfile "${ROOT_CERT}" "${ROOT_CERT}" >/dev/null 2>&1 \
	|| die "root certificate '${ROOT_CERT}' does not verify (expired?)."
}

# Sets ROOT_CRL_PEM to a PEM copy of the root CA's CRL.
find_root_crl() {
    local f="" c
    ROOT_CRL_PEM=""
    if [ -n "${PKI_ROOT_CRL:-}" ]; then
	f="${PKI_ROOT_CRL}"
	[ -f "${f}" ] || die "PKI_ROOT_CRL '${f}' does not exist."
    else
	for c in root/crl/root.crl.pem root/crl/root.crl root/root.crl.pem root/root.crl; do
	    if [ -f "${c}" ]; then
		f="${c}"
		break
	    fi
	done
    fi
    [ -n "${f}" ] || die "root CRL not found (looked for root/crl/root.crl[.pem]); create it with bin/create_crl.sh root, or set PKI_ROOT_CRL."
    if grep -aq -- '-----BEGIN X509 CRL-----' "${f}"; then
	ROOT_CRL_PEM="${f}"
    else
	ROOT_CRL_PEM="${STAGE}/root.crl.pem"
	"${OPENSSL}" crl -inform der -in "${f}" -out "${ROOT_CRL_PEM}" \
	    || die "cannot read '${f}' as a PEM or DER CRL."
    fi
}

# Sets INTERMEDIATE_PEM to the valid intermediate expiring last. Valid means
# the root accepts it:
#   openssl verify -crl_check -CRLfile root.crl -CAfile root.cert.pem
# which also rejects an expired intermediate, a revoked one, and a missing
# or expired CRL. (Without -crl_check, openssl verify ignores the CRL.)
pick_valid_intermediate() {
    local f sha1 epoch out reason best_epoch=0 seen=" "
    INTERMEDIATE_PEM=""
    find_root_crl
    for f in intermediate/certs/intermediate.cert.pem intermediate/certs/intermediate.*.cert.pem; do
	[ -f "${f}" ] || continue
	sha1=$(cert_sha1 "${f}")
	case "${seen}" in
	    *" ${sha1} "*) continue ;;
	esac
	seen="${seen}${sha1} "
	if ! cert_is_current "${f}"; then
	    warn "skipping expired intermediate ${f}"
	    continue
	fi
	if ! out=$("${OPENSSL}" verify -crl_check -CRLfile "${ROOT_CRL_PEM}" \
		       -CAfile "${ROOT_CERT}" "${f}" 2>&1); then
	    reason=$(printf '%s\n' "${out}" | sed -n 's/^error [0-9]* at [0-9]* depth lookup: //p' | head -n 1)
	    warn "skipping intermediate ${f}: ${reason:-does not verify against the root and its CRL}"
	    continue
	fi
	epoch=$(cert_enddate_epoch "${f}")
	if [ -z "${INTERMEDIATE_PEM}" ] || [ "${epoch}" -gt "${best_epoch}" ]; then
	    INTERMEDIATE_PEM="${f}"
	    best_epoch="${epoch}"
	fi
    done
    [ -n "${INTERMEDIATE_PEM}" ] || die "no valid intermediate certificate found in intermediate/certs."
}

# ---------------------------------------------------------------------
# --ca-only
# ---------------------------------------------------------------------

install_ca_only() {
    local pw sha1 base p12 der
    [ "$(uname -s)" = "Darwin" ] || die "--ca-only uses the macOS security tool; run it on a Mac."
    verify_root
    pick_valid_intermediate

    echo "Installing the root and intermediate CAs into ${SYSTEM_KEYCHAIN} (sudo required)." >&2
    sudo -v

    # Root: import the identity, then trust the certificate
    echo "- Root CA (${ROOT_CERT})"
    sha1=$(cert_sha1 "${ROOT_CERT}")
    if kc_has_identity "${SYSTEM_KEYCHAIN}" "${sha1}"; then
	echo "    already present"
    else
	pw=$(local_p12_password "${ROOT_P12}" root/private/passphrase.txt) \
	    || die "cannot open ${ROOT_P12} with either line of root/private/passphrase.txt."
	import_into_keychain 1 "${SYSTEM_KEYCHAIN}" "${ROOT_P12}" "${pw}" -A \
	    || die "importing ${ROOT_P12} failed."
    fi
    der="${STAGE}/root.cer"
    "${OPENSSL}" x509 -outform der -in "${ROOT_CERT}" -out "${der}"
    sudo security add-trusted-cert -d -r trustRoot -k "${SYSTEM_KEYCHAIN}" "${der}"
    echo "    trusted as root"

    # Intermediate
    base=${INTERMEDIATE_PEM##*/}
    base=${base%.cert.pem}
    p12="intermediate/private/${base}.p12"
    echo "- Intermediate CA (${INTERMEDIATE_PEM})"
    sha1=$(cert_sha1 "${INTERMEDIATE_PEM}")
    if kc_has_identity "${SYSTEM_KEYCHAIN}" "${sha1}"; then
	echo "    already present"
    else
	pw=$(local_p12_password "${p12}" intermediate/private/passphrase.txt) \
	    || die "cannot open ${p12} with either line of intermediate/private/passphrase.txt."
	import_into_keychain 1 "${SYSTEM_KEYCHAIN}" "${p12}" "${pw}" -A \
	    || die "importing ${p12} failed."
    fi
    pw=""
    if ! kc_has_cert "${SYSTEM_KEYCHAIN}" "${sha1}"; then
	der="${STAGE}/intermediate.cer"
	"${OPENSSL}" x509 -outform der -in "${INTERMEDIATE_PEM}" -out "${der}"
	import_into_keychain 1 "${SYSTEM_KEYCHAIN}" "${der}" ""
    fi
    echo "Done."
}

if [ "${CA_ONLY}" = "1" ]; then
    install_ca_only
    exit 0
fi

# ---------------------------------------------------------------------
# Staging the installer payloads
# ---------------------------------------------------------------------

MANIFEST="${STAGE}/common/manifest"

# stage_system_cert TYPE GROUP PEM LABEL HASKEY P12
# TYPE is trust-root, ca or server. The DER certificate is always staged
# (it is used to verify servers); the .p12 only when HASKEY is 1.
stage_system_cert() {
    local type="$1" group="$2" pem="$3" label="$4" haskey="$5" p12="$6" sha1
    sha1=$(cert_sha1 "${pem}")
    "${OPENSSL}" x509 -outform der -in "${pem}" -out "${STAGE}/common/system/${sha1}.cer"
    if [ "${haskey}" = 1 ]; then
	cp "${p12}" "${STAGE}/common/system/${sha1}.p12"
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "${type}" "${group}" "${sha1}" "${haskey}" "${label}" >> "${MANIFEST}"
}

# stage_dir_certs TYPE DIR ISSUER_DIR ALLOW_KEYS
# Stages every unexpired, unrevoked certificate in DIR/certs. The .p12 is
# bundled only when ALLOW_KEYS is 1 and --include-private-keys was given;
# directories listed in PRIVOXY_DIRS never get their keys bundled.
stage_dir_certs() {
    local type="$1" d="$2" issuer="$3" allow_keys="$4" f b sha1 serial status p12 haskey seen=" " found=0 pd
    local files=("${d}"/certs/*.cert.pem)
    for pd in ${PRIVOXY_DIRS}; do
	if [ "${pd}" = "${d}" ]; then
	    allow_keys=0
	fi
    done
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
	if ! cert_is_current "${f}"; then
	    warn "skipping expired certificate ${f}"
	    continue
	fi
	if [ -n "${issuer}" ]; then
	    serial=$(cert_serial "${f}")
	    status=$(ca_index_status "${issuer}" "${serial}")
	    if [ "${status}" = "R" ]; then
		warn "skipping revoked certificate ${f}"
		continue
	    fi
	fi
	haskey=0
	p12="${d}/private/${b}.p12"
	if [ "${INCLUDE_PRIVATE_KEYS}" = 1 ] && [ "${allow_keys}" = 1 ]; then
	    if [ -f "${p12}" ]; then
		haskey=1
	    else
		warn "no ${p12}; installing only the public certificate"
	    fi
	fi
	stage_system_cert "${type}" "${d}" "${f}" "${d}/${b}" "${haskey}" "${p12}"
	found=1
    done
    if [ "${found}" = 0 ]; then
	warn "no usable certificates found in ${d}/certs"
    fi
}

build_common() {
    local d f have_root=0 have_int=0
    mkdir -p "${STAGE}/common/system"
    : > "${MANIFEST}"
    if [ -f "${ROOT_CERT}" ]; then
	verify_root
	stage_system_cert trust-root root "${ROOT_CERT}" "root (trusted)" 0 ""
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
	pick_valid_intermediate
	echo "Using intermediate: ${INTERMEDIATE_PEM}" >&2
	stage_system_cert ca intermediate "${INTERMEDIATE_PEM}" "${INTERMEDIATE_PEM%.cert.pem}" 0 ""
    fi
    for d in ${PRIVOXY_DIRS}; do
	stage_dir_certs ca "${d}" "" 0
    done
    for d in ${SERVER_DIRS}; do
	stage_dir_certs server "${d}" intermediate 1
    done
}

list_smime_certnames() {
    local f b
    for f in smime/certs/*.cert.pem; do
	b=${f##*/}
	if [[ "${b}" =~ ${SMIME_RE} ]]; then
	    echo "${BASH_REMATCH[1]}"
	fi
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

# installer_name GLOB -> file name stem for the installer
installer_name() {
    local stem
    stem=$(printf '%s' "$1" | sed -e 's/[^A-Za-z0-9.-][^A-Za-z0-9.-]*/_/g' -e 's/^_//' -e 's/_$//')
    printf '%s' "${stem:-all}"
}

# build_payload_dir -> ${STAGE}/payload: the staged system items plus the
# S/MIME .p12 files of SEL_CERTNAMES; sets SMIME_COUNT
build_payload_dir() {
    local dir="${STAGE}/payload" f b certname ext sha1 p12 state seen=" " count=0
    rm -rf "${dir}"
    mkdir -p "${dir}/smime"
    cp -R "${STAGE}/common/." "${dir}/"
    for f in smime/certs/*.cert.pem; do
	b=${f##*/}
	[[ "${b}" =~ ${SMIME_RE} ]] || continue
	certname="${BASH_REMATCH[1]}"
	ext="${BASH_REMATCH[2]}"
	case " ${SEL_CERTNAMES[*]} " in
	    *" ${certname} "*) ;;
	    *) continue ;;
	esac
	p12="smime/private/${b%.cert.pem}.p12"
	if [ ! -f "${p12}" ]; then
	    warn "${f} has no ${p12}; skipping"
	    continue
	fi
	sha1=$(cert_sha1 "${f}")
	case "${seen}" in
	    *" ${sha1} "*) continue ;;
	esac
	seen="${seen}${sha1} "
	if cert_is_current "${f}"; then
	    state="valid"
	else
	    state="expired"
	fi
	cp "${p12}" "${dir}/smime/${sha1}.p12"
	printf 'user-p12\tsmime\t%s\t1\t%s\n' "${sha1}" \
	       "${certname} ${ext}, ${state}, until $(cert_enddate "${f}")" >> "${dir}/manifest"
	count=$((count + 1))
    done
    SMIME_COUNT="${count}"
    echo "${count} S/MIME certificate(s) selected" >&2
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

# write_installer USER DIR OUT
write_installer() {
    local user="$1" dir="$2" out="$3"
    export COPYFILE_DISABLE=1   # no AppleDouble files in the tar on macOS
    {
	printf '#!/bin/bash\n'
	printf '# Credentials installer: %s\n' "${user}"
	printf '# Generated %s. Contains encrypted private keys; no passwords.\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	printf 'INSTALL_FOR=%q\n' "${user}"
	printf 'SYSTEM_KEYCHAIN=%q\n' "${SYSTEM_KEYCHAIN}"
	declare -f confirm kc_has_cert kc_has_identity import_into_keychain get_password
	cat <<'INSTALLER'

set -eo pipefail
umask 077

usage() {
    cat <<USAGE
Usage: $(basename "$0") [--system-only | --user-only] [--list]

Installs the credentials bundled in this script (${INSTALL_FOR}).
Run it as yourself (not with sudo); sudo is requested for the System keychain.

  --system-only  only the System keychain items
  --user-only    only the S/MIME identities in your login keychain
  --list         show what is included and exit

You are asked (y/N) before each certificate is added; set PKI_ASSUME_YES=1
to answer yes to everything. Each .p12 password is asked for when needed;
to avoid the prompt set PKI_P12_PASSWORD_SMIME (and
PKI_P12_PASSWORD_<DIRECTORY> for others).
USAGE
}

DO_SYSTEM=1
DO_USER=1
LIST=0
while [ $# -gt 0 ]; do
    case "$1" in
	--system-only) DO_USER=0 ;;
	--user-only) DO_SYSTEM=0 ;;
	--list) LIST=1 ;;
	-h|--help) usage; exit 0 ;;
	*) usage >&2; exit 1 ;;
    esac
    shift
done

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
sed '1,/^__PAYLOAD_BELOW__$/d' "$0" | uudecode -p | tar -xJf - -C "${WORK}"
MANIFEST="${WORK}/manifest"
grep -Eq '^(trust-root|ca|server)' "${MANIFEST}" || DO_SYSTEM=0
grep -q '^user-p12' "${MANIFEST}" || DO_USER=0

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

install_system() {
    local type group sha1 haskey label present msg
    echo "== System keychain =="
    while IFS=$'\t' read -r -u 3 type group sha1 haskey label; do
	case "${type}" in
	    trust-root|ca|server) ;;
	    *) continue ;;
	esac
	echo "- ${type}: ${label}"
	present=0
	if [ "${haskey}" = 1 ]; then
	    if kc_has_identity "${SYSTEM_KEYCHAIN}" "${sha1}"; then present=1; fi
	elif kc_has_cert "${SYSTEM_KEYCHAIN}" "${sha1}"; then
	    present=1
	fi
	if [ "${present}" = 1 ] && [ "${type}" != "trust-root" ]; then
	    echo "    already present"
	    continue
	fi
	case "${type}" in
	    trust-root) msg="Add the ROOT CA '${label}' to the System keychain and trust it for all users?" ;;
	    *)
		msg="Add ${type} certificate '${label}' to the System keychain?"
		if [ "${haskey}" = 1 ]; then
		    msg="Add ${type} certificate '${label}' AND ITS PRIVATE KEY to the System keychain?"
		fi
		;;
	esac
	if ! confirm "    ${msg}"; then
	    echo "    skipped"
	    continue
	fi
	ensure_sudo
	if [ "${present}" = 1 ]; then
	    echo "    already present"
	elif [ "${haskey}" = 1 ]; then
	    if get_password "${group}"; then
		import_into_keychain 1 "${SYSTEM_KEYCHAIN}" "${WORK}/system/${sha1}.p12" "${PASSWORD}" -A \
		    || { fail "${label}"; continue; }
	    else
		fail "no password available for '${group}'"
		continue
	    fi
	else
	    import_into_keychain 1 "${SYSTEM_KEYCHAIN}" "${WORK}/system/${sha1}.cer" "" \
		|| { fail "${label}"; continue; }
	fi
	if [ "${type}" = "trust-root" ]; then
	    if sudo security add-trusted-cert -d -r trustRoot -k "${SYSTEM_KEYCHAIN}" "${WORK}/system/${sha1}.cer"; then
		echo "    trusted as root"
	    else
		fail "trusting ${label}"
	    fi
	fi
	if [ "${type}" = "server" ]; then
	    if security verify-cert -c "${WORK}/system/${sha1}.cer" >/dev/null 2>&1; then
		echo "    verified"
	    else
		echo "    warning: verify-cert did not validate this certificate" >&2
	    fi
	fi
    done 3< "${MANIFEST}"
}

install_user() {
    local type group sha1 haskey label keychain imported=0
    local acl=()
    echo "== Login keychain =="
    keychain="${HOME}/Library/Keychains/login.keychain-db"
    if [ ! -f "${keychain}" ]; then
	keychain="${HOME}/Library/Keychains/login.keychain"
    fi
    if [ ! -f "${keychain}" ]; then
	fail "login keychain not found"
	return 0
    fi
    if [ -d /System/Applications/Mail.app ]; then
	acl=(-T /System/Applications/Mail.app)
    fi
    while IFS=$'\t' read -r -u 3 type group sha1 haskey label; do
	[ "${type}" = "user-p12" ] || continue
	echo "- S/MIME ${label}"
	if kc_has_identity "${keychain}" "${sha1}"; then
	    echo "    already present"
	    continue
	fi
	if ! confirm "    Add this S/MIME certificate and its private key to your login keychain?"; then
	    echo "    skipped"
	    continue
	fi
	if get_password "${group}"; then
	    if import_into_keychain 0 "${keychain}" "${WORK}/smime/${sha1}.p12" "${PASSWORD}" ${acl[@]+"${acl[@]}"}; then
		imported=$((imported + 1))
	    else
		fail "${label}"
	    fi
	else
	    fail "no password available for '${group}'"
	fi
    done 3< "${MANIFEST}"
    if [ "${imported}" -gt 0 ]; then
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
    install_system
fi
if [ "${DO_USER}" = 1 ]; then
    install_user
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
	tar -cJf - -C "${dir}" . | uuencode "${user}.tar.xz"
    } > "${out}"
    chmod 0700 "${out}"
}

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

mkdir -p "${OUTDIR}"
chmod 0700 "${OUTDIR}"

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
	    || die "'NAME_GLOB' '${n}' matches no S/MIME certificate name in smime/certs (is it single-quoted?)."
	for c in "${SEL_CERTNAMES[@]}"; do
	    case " ${UNION[*]} " in
		*" ${c} "*) ;;
		*) UNION+=("${c}") ;;
	    esac
	done
    done
fi
SEL_CERTNAMES=("${UNION[@]}")

build_payload_dir
if [ "${#NAMES[@]}" -gt 0 ] && [ "${SMIME_COUNT}" -eq 0 ]; then
    die "none of the matching S/MIME certificates has a .p12 file."
fi
if [ ! -s "${STAGE}/payload/manifest" ]; then
    warn "nothing to include in the payload; no installer created."
    exit 0
fi

stem=""
for n in "${NAMES[@]}"; do
    stem="${stem}_$(installer_name "${n}")"
done
out="${OUTDIR}/install_credentials${stem}.sh"
if [ "${#NAMES[@]}" -gt 0 ]; then
    label="${NAMES[*]}"
else
    label="CA and server certificates"
fi

show_payload "${out}" "${STAGE}/payload"
if confirm "Create ${out}?"; then
    write_installer "${label}" "${STAGE}/payload" "${out}"
    echo "Created ${out}" >&2
    echo "Send the .p12 passwords separately; the installer contains none." >&2
else
    echo "Skipped ${out} (answer y at the prompt, or set PKI_ASSUME_YES=1)." >&2
fi

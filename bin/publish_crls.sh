#!/usr/bin/env bash

# publish_crls.sh
#
# Usage: publish_crls.sh [--if-configured] [--no-regenerate] [-h|--help] [root|intermediate ...]
#
# Regenerates each named CA's CRL (bin/create_crl.sh) and publishes the CRL
# and the CA certificate, both DER, to the web directory the CRL
# distribution points point at (http://PKI_FQDN/<ca>.crl and <ca>.cer).
# Default CAs: root intermediate. Safe to run at any time; called by the
# periodic CRL job and by revoke_certificate.sh, so that a revocation is
# published immediately rather than at the next scheduled run.
#
#   --no-regenerate  publish the CRL files as they are (already fresh)
#   --if-configured  exit quietly (0) if no web directory is configured
#
# Web directory: PKI_SITE_DIR, else <prefix>/var/www/PKI_FQDN when this PKI
# lives in <prefix>/etc/<name> (a MacPorts layout) and <prefix>/var/www
# exists. Group of the published files: PKI_SITE_GROUP, else _www if that
# group exists, else nobody.

set -e
set -E
set -o pipefail
trap 'rc=$?; echo "Error: $(basename "$0") failed (exit ${rc}) at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

IF_CONFIGURED=0
REGENERATE=1
HELP=0
CAS=()

while [[ $# -gt 0 ]]; do
    case $1 in
	--if-configured)
	    IF_CONFIGURED=1
	    shift
	    ;;
	--no-regenerate)
	    REGENERATE=0
	    shift
	    ;;
	-h|--help)
	    HELP=1
	    shift
	    ;;
	root|intermediate)
	    CAS+=("$1")
	    shift
	    ;;
	*)
	    echo "Error: unknown argument '$1' (expected root or intermediate)." >&2
	    exit 2
	    ;;
    esac
done

if [ "${HELP}" != "0" ]; then
    cat <<USEAGE
Useage:

$(basename "$0") [--if-configured] [--no-regenerate] [-h|--help] [root|intermediate ...]
USEAGE
    exit 0
fi

if [ "${#CAS[@]}" -eq 0 ]; then
    CAS=(root intermediate)
fi

. "${PKI_ROOT}/pki_identity.env"

if [ -z "${PKI_SITE_DIR:-}" ]; then
    PREFIX_WWW="$(cd "${PKI_ROOT}/../.." 2>/dev/null && pwd)/var/www"
    if [ -d "${PREFIX_WWW}" ]; then
	PKI_SITE_DIR="${PREFIX_WWW}/${PKI_FQDN}"
    elif [ "${IF_CONFIGURED}" = "1" ]; then
	echo "CRLs not published: set PKI_SITE_DIR to the web directory (see $(basename "$0") -h)." >&2
	exit 0
    else
	echo "Error: set PKI_SITE_DIR to the web directory that serves http://${PKI_FQDN}/." >&2
	exit 1
    fi
fi

if [ -z "${PKI_SITE_GROUP:-}" ]; then
    if id -g _www >/dev/null 2>&1; then
	PKI_SITE_GROUP=_www
    else
	PKI_SITE_GROUP=nobody
    fi
fi

mkdir -p "${PKI_SITE_DIR}"

# publish_file SRC DST: replace DST atomically, world-readable
publish_file() {
    local src="$1" dst="$2"
    /bin/cp -p "${src}" "${dst}.tmp"
    /bin/mv -f "${dst}.tmp" "${dst}"
    touch "${dst}"
    chmod 0644 "${dst}"
    chgrp "${PKI_SITE_GROUP}" "${dst}" 2>/dev/null \
	|| echo "Warning: could not set group ${PKI_SITE_GROUP} on ${dst}." >&2
}

for ca in "${CAS[@]}"; do
    if [ "${REGENERATE}" = "1" ]; then
	SHOW_CRL_TEXT=0 "${PKI_ROOT}/bin/create_crl.sh" "${ca}" > /dev/null
    fi

    SRC="${ca}/certs/${ca}.cer"
    DST="${PKI_SITE_DIR}/${ca}.cer"
    if [ -f "${SRC}" ] && { [ ! -f "${DST}" ] || [ "${SRC}" -nt "${DST}" ]; }; then
	publish_file "${SRC}" "${DST}"
    fi

    publish_file "${ca}/crl/${ca}.crl" "${PKI_SITE_DIR}/${ca}.crl"
    echo "Published ${ca}.crl to ${PKI_SITE_DIR}" >&2
done

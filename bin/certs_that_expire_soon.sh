#!/usr/bin/env bash

# Usage: certs_that_expire_soon.sh [-h|--help] [MONTHS]
#
# Lists certificates in */certs/ that expire within MONTHS (default 6) or
# already have. Each certificate is listed once.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

EXPMONTHS_DEFAULT=${EXPMONTHS_DEFAULT:-6}
EXPMONTHS=${EXPMONTHS:-${EXPMONTHS_DEFAULT}}

POSITIONAL_ARGS_USAGE=${POSITIONAL_ARGS_USAGE:-[MONTHS, default ${EXPMONTHS_DEFAULT}]}
POSITIONAL_ARGS=()
HELP=0

while [[ $# -gt 0 ]]; do
    case $1 in
	-h|--help)
	    HELP=1
	    shift
	    ;;
	*)
	    POSITIONAL_ARGS+=("$1")
	    shift
	    ;;
    esac
done

if [ "${HELP}" != "0" ]; then
    cat <<USAGE
Usage:

$(basename "$0") [-h|--help] ${POSITIONAL_ARGS_USAGE}
USAGE
    exit 0
fi

if [ "${#POSITIONAL_ARGS[@]}" -gt 1 ]; then
    echo "Error: at most one argument (MONTHS), got ${#POSITIONAL_ARGS[@]}." >&2
    exit 1
fi
if [ "${#POSITIONAL_ARGS[@]}" -eq 1 ]; then
    EXPMONTHS="${POSITIONAL_ARGS[0]}"
fi
if [[ ! "${EXPMONTHS}" =~ ^[0-9]+$ ]]; then
    echo "Error: MONTHS '${EXPMONTHS}' is not an integer." >&2
    exit 1
fi

# Defines and exports OPENSSL.
. "${PKI_ROOT}/bin/define_openssl.sh"

EXPSECS=$((EXPMONTHS * (30 * 24 + 12) * 3600))
declare -A SEEN=()
# unsuffixed and <sha1> copies are one certificate: list by fingerprint
while IFS= read -r -d '' f; do
    if ! fp=$("${OPENSSL}" x509 -noout -fingerprint -sha256 -in "${f}" 2>/dev/null); then
        echo "${f}: cannot read certificate" >&2
        continue
    fi
    fp=${fp#*=}
    [ -z "${SEEN[${fp}]:-}" ] || continue
    SEEN[${fp}]=1
    if ! "${OPENSSL}" x509 -checkend "${EXPSECS}" -noout -in "${f}" >/dev/null 2>&1; then
        echo "${f} expires on $("${OPENSSL}" x509 -enddate -noout -in "${f}" | sed 's|notAfter=||')"
    fi
done < <(find . -type f -path '*/certs/*.cert.pem' -print0)

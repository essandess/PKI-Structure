#!/usr/bin/env bash

# Usage: updatedb_and_delete_expired_certs.sh [-n|--dry-run]
#
# Marks expired entries in each CA database (openssl ca -updatedb), then
# deletes the files of expired server, codesign and adblock2privoxy
# certificates (certificate, chain, .cer, key, decrypted key, .p12).
# -n/--dry-run only lists what would be deleted. S/MIME and CA certificates
# are never deleted.

set -e
set -E
trap 'rc=$?; echo "Error: $(basename "$0") failed (exit ${rc}) at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit


DEBUG=${DEBUG:-0}
[ "${DEBUG}" != "0" ] && set -x

CERTDIR=${CERTDIR:-root}

POSITIONAL_ARGS_USAGE=${POSITIONAL_ARGS_USAGE:-[-n|--dry-run]}
POSITIONAL_ARGS=()

HELP=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case $1 in
	-h|--help)
	    HELP=1
	    shift
	    ;;
	-n|--dry-run)
	    DRY_RUN=1
	    shift
	    ;;
	*)
	    POSITIONAL_ARGS+=("$1")
	    shift
	    ;;
    esac
done

if [ "${#POSITIONAL_ARGS[@]}" -gt 0 ]; then
    echo "This script takes no positional arguments (got ${#POSITIONAL_ARGS[@]})." >&2
    exit 1
fi

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

if [ "${HELP}" != "0" ]; then
    cat <<USEAGE
Useage:

$(basename "$0") [-h|--help] ${POSITIONAL_ARGS_USAGE}
USEAGE
    exit 0
fi

. "${PKI_ROOT}/pki_identity.env"
# Defines and exports OPENSSL, which delete_expired_certs (run by find -exec
# in a child shell) needs. Without it every certificate would look expired.
. "${PKI_ROOT}/bin/define_openssl.sh"

: "${OPENSSL:?OPENSSL is not set by bin/define_openssl.sh}"

# Delete the files of a certificate only if it can be read AND has expired.
# An unreadable certificate, or any openssl failure, deletes nothing.
delete_expired_certs() {
    local PEM="$1"
    local PEMBASE PEMDIR
    PEMBASE="$(basename "${PEM}" .cert.pem)"
    PEMDIR="$(dirname "${PEM}")"
    if ! "${OPENSSL}" x509 -noout -in "${PEM}" 1> /dev/null 2>&1; then
        echo "Warning: cannot read ${PEM}; not deleting anything." >&2
        return 0
    fi
    if ! "${OPENSSL}" x509 -checkend "0" -noout -in "${PEM}" 1> /dev/null 2>&1
    then \
        for p in "${PEMDIR}/${PEMBASE}"{.cert.pem,.chain.pem,.cer} \
            "${PEMDIR}/../private/${PEMBASE}"{.key.pem,.key.pem.decrypted,.p12}
        do
            if [ -f "${p}" ]; then
                if [ "${DRY_RUN}" != "0" ]; then
                    echo "Would delete ${p}"
                else
                    echo "Deleting ${p}"
                    rm "${p}"
                fi
            fi
        done
    fi
}

export -f delete_expired_certs
export DRY_RUN


# update databases
if [ -f "${CERTDIR}/private/passphrase.txt" ] && [ -f "${CERTDIR}/index.txt" ]; then
    "${OPENSSL}" ca -config openssl.cnf -passin "file:${CERTDIR}/private/passphrase.txt" -updatedb
fi
if [ -f "intermediate/private/passphrase.txt" ] && [ -f "intermediate/index.txt" ]; then
    "${OPENSSL}" ca -config intermediate/openssl_intermediate.cnf -passin "file:intermediate/private/passphrase.txt" -updatedb
fi
if [ -f "privoxy/private/passphrase.txt" ] && [ -f "privoxy/index.txt" ]; then
    "${OPENSSL}" ca -config privoxy/openssl_privoxy.cnf -passin "file:privoxy/private/passphrase.txt" -updatedb
fi

# do NOT delete S/MIME and intermediate CA's

# codesign and server certs issued by intermediate. (find compares -path with
# the names it prints, which start with "./"; a pattern without it matches
# nothing.)
for d in codesign server; do
    find . -type f -path "./${d}/certs/*.cert.pem" -exec bash -c \
        'delete_expired_certs "$1"' bash {} ';'
done

# adblock2privoxy server certs issued by privoxy
find . -type f -path "./privoxy/adblock2privoxy/certs/*.cert.pem" -exec bash -c \
    'delete_expired_certs "$1"' bash {} ';'

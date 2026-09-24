#!/usr/bin/env bash

# Usage: updatedb_and_delete_expired_certs.sh

set -e
set -E
trap 'rc=$?; echo "Error: $(basename "$0") failed (exit ${rc}) at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

DEBUG=${DEBUG:-0}
[ "${DEBUG}" != "0" ] && set -x

CERTDIR=${CERTDIR:-root}

POSITIONAL_ARGS_USAGE=${POSITIONAL_ARGS_USAGE:-}
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

delete_expired_certs() {
    local PEM="$1"
    local PEMBASE="$(basename "${PEM}" .cert.pem)"
    local PEMDIR="$(dirname "${PEM}")"
    if ! openssl x509 -checkend "0" -noout -in "${PEM}" 1> /dev/null 2>&1
    then \
        for p in "${PEMDIR}/${PEMBASE}"{.cert.pem,.chain.pem,.cer} \
            "${PEMDIR}/../private/${PEMBASE}"{.key.pem,.key.pem.decrypted,.p12}
        do
            if [ -f "${p}" ]; then
                rm "${p}"
            fi
        done
    fi
}

export -f delete_expired_certs


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}"
# update databases
if [ -f "./${CERTDIR}/private/passphrase.txt" -a -f "./${CERTDIR}/index.txt" ]; then
    openssl ca -config ./openssl.cnf -passin "file:./${CERTDIR}/private/passphrase.txt" -updatedb
fi
if [ -f "./intermediate/private/passphrase.txt" -a -f "./intermediate/index.txt" ]; then
    openssl ca -config ./intermediate/openssl_intermediate.cnf -passin "file:./intermediate/private/passphrase.txt" -updatedb
fi
if [ -f "./privoxy/private/passphrase.txt" -a -f "./privoxy/index.txt" ]; then
    openssl ca -config ./privoxy/openssl_privoxy.cnf -passin "file:./privoxy/private/passphrase.txt" -updatedb
fi

# do NOT delete S/MIME and intermediate CA's

# codesign and server certs issued by intermediate
for d in ./codesign ./server; do
    find . -type f -path "${d}/certs/*.cert.pem" -exec bash -c \
        'delete_expired_certs "$1"' bash {} ';'
done

# adblock2privoxy server certs issued by privoxy
find . -type f -path "./privoxy/adblock2privoxy/certs/*.cert.pem" -exec bash -c \
    'delete_expired_certs "$1"' bash {} ';'

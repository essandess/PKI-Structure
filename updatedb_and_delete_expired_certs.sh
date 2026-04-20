#!/usr/bin/env bash -x

# Usage: updatedb_and_delete_expired_certs.sh

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
	if [ "${#POSITIONAL_ARGS[@]}" -gt 0 ]; then
	    echo "Number of arguments '${#POSITIONAL_ARGS[@]}' more than 1."
	    exit 1
	fi
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
    local PEMBASE="$(basename ${PEM} .cert.pem)"
    local PEMDIR="$(dirname ${PEM})"
    if ! openssl x509 -checkend "0" -noout -in "${PEM}" 1> /dev/null 2>&1
    then \
        for p in "${PEMDIR}/${PEMBASE}"{.cert.pem,.chain.pem,.cer} \
            "${PEMDIR}/../private/${PEMBASE}"{.key.pem,.key.pem.decrypted,.p12}
        do
            if [ -f "${p}" ]; then
                rm ${p}
            fi
        done
    fi
}

export -f delete_expired_certs


# update databases
if [ -f "./ca/private/passphrase.txt" -a -f "./ca/index.txt" ]; then
    openssl ca -config ./openssl.cnf -passin "file:./ca/private/passphrase.txt" -updatedb
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

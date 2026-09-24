#!/usr/bin/env bash

# Usage: certs_that_expire_soon.sh [#months]

EXPMONTHS_DEFAULT=${EXPMONTHS_DEFAULT:-6}
EXPMONTHS=${EXPMONTHS:-${EXPMONTHS_DEFAULT}}

POSITIONAL_ARGS_USAGE=${POSITIONAL_ARGS_USAGE:-[# months, default ${EXPMONTHS_DEFAULT}]}
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
	if [ "${#POSITIONAL_ARGS[@]}" -gt 1 ]; then
	    echo "Number of arguments '${#POSITIONAL_ARGS[@]}' more than 1."
	    exit 1
	fi
	EXPMONTHS="${POSITIONAL_ARGS[0]}"
fi
if [[ ! "${EXPMONTHS}" =~ ^[0-9]+$ ]]; then
    echo "Expiry in months '${EXPMONTHS}' not an integer."
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

EXPSECS=$(("${EXPMONTHS}" * (30 * 24 + 12) * 3600)); find . -type f -path '*/certs/*.cert.pem' -exec bash -c 'if ! openssl x509 -checkend '"${EXPSECS}"' -noout -in {} 1> /dev/null 2>&1; then echo "{} expires on $(openssl x509 -enddate -noout -in {})" | sed "s|notAfter=||"; fi' ';'

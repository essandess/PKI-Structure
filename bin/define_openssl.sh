#!/usr/bin/env bash

# define_openssl.sh

# Resolve the openssl binary: honor a preset $OPENSSL, else use the first one on PATH.
OPENSSL="${OPENSSL:-$(command -v openssl || true)}"

if [ -z "${OPENSSL}" ] || [ ! -x "${OPENSSL}" ]; then
    echo "Error: no usable openssl found (PATH=${PATH})." >&2
    echo "       Install OpenSSL or set OPENSSL=/path/to/openssl." >&2
    exit 1
fi

# Apple's LibreSSL /usr/bin/openssl doesn't support the '.include' directive
OPENSSL_VERSION="$("${OPENSSL}" version 2>&1 || true)"
case "${OPENSSL_VERSION}" in
    LibreSSL*)
        echo "Error: ${OPENSSL} is ${OPENSSL_VERSION}." >&2
        echo "       openssl.cnf uses '.include', which LibreSSL does not support." >&2
        echo "       Put a real OpenSSL ahead of it on PATH (e.g. \${prefix}/bin for MacPorts)," >&2
        echo "       or set OPENSSL=/path/to/openssl. Current PATH: ${PATH}" >&2
        exit 1
        ;;
esac
export OPENSSL

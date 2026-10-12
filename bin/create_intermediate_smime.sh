#!/usr/bin/env bash

# create_intermediate_smime.sh
#
# Usage: create_intermediate_smime.sh [-a EC|RSA] [--new-key] [-c|--clean|-vc|--veryclean] [-h|--help]
#
# Creates, or renews, the S/MIME intermediate CA in intermediate_smime/. It is
# create_intermediate.sh run with CERTDIR=intermediate_smime: the same
# archiving, renewal and --new-key behavior, configured by
# intermediate_smime/openssl_intermediate_smime.cnf.
#
# This CA is limited by extendedKeyUsage to emailProtection, so that a
# compromise of its key cannot be used for TLS or code signing. It has no
# nameConstraints: S/MIME addresses span unrelated domains (gmail.com,
# icloud.com). create_smime.sh issues from it. Its CRL is
# http://PKI_FQDN/intermediate_smime.crl (bin/publish_crls.sh).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export CERTDIR=intermediate_smime
export CERTNAME=intermediate_smime

exec "${SCRIPT_DIR}/create_intermediate.sh" "$@"

#!/usr/bin/env bash

: <<'PKI_STRUCTURE'
# PKI Structure

This set of shell scripts and `openssl` configuration files creates
a PKI structure for common applications that include a certificate
authority, intermediate certificate authority, server certificates,
S/MIME certificates, code signing certificates, and `https` inspection
certificates for `privoxy` and `adblock2privoxy`.

The products of the scripts are X509 certificates and keys in both
CER, PEM, and PKCS12 formats. All keys are passphrase protected.

The branding must be modified for specific PKI deployments using
the file `identity.env`.

To create the entire PKI structure:
```sh
sh README.md
```
PKI_STRUCTURE

# PKI Structure

# Set the variable CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY
export CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY=1

# Clear everything
./create_ca.sh -vc ; ./create_intermediate.sh -vc ; ./create_server.sh -vc ; ./create_codesign.sh -vc ; ./create_smime.sh -vc
./create_privoxy.sh -vc ; ./create_adblock2privoxy.sh -vc

# Create PKI chain of trust all at once
./create_privoxy.sh && ./create_adblock2privoxy.sh
./create_ca.sh && ./create_intermediate.sh && ./create_server.sh && ./create_codesign.sh && ./create_organization_smime_pki.sh

# Single S/MIME certificate creation
./create_smime.sh userc@organization.org userc_organization

# Unset the variable CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY
unset CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY

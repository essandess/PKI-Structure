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

## Deploying to a new directory

To set up a new PKI deployment from this repository — copying the
generic scripts and OpenSSL configs, but never touching an existing
`identity.env` at the destination — run:

    bin/replicate_pki_structure.sh [SRC] [DEST]

`SRC` defaults to this repository's own location; `DEST` defaults to
the current directory. Only `.sh`, `.cnf`, `.md`, and `LICENSE` files
are copied — `.git/`, any `.env` file, and `create_organization_smime_pki.sh`
(which contains this deployment's actual cert-issuance list) are never
copied to a new deployment.

If `DEST` has no `identity.env` yet, one is seeded from
`identity.env.sample` (or from this repo's own `identity.env` if no
sample exists) — edit it with the new deployment's organization,
domain, and PKI hostname before running any of the `create_*.sh`
scripts.

To create the entire PKI structure:
```sh
sh README.md
```
PKI_STRUCTURE

# PKI Structure

# Set the variable CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY
export CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY=1

# Clear everything
bin/create_root.sh -vc ; bin/create_intermediate.sh -vc ; bin/create_server.sh -vc ; bin/create_codesign.sh -vc ; bin/create_smime.sh -vc
bin/create_privoxy.sh -vc ; bin/create_adblock2privoxy.sh -vc

# Create PKI chain of trust all at once
bin/create_privoxy.sh && bin/create_adblock2privoxy.sh
bin/create_root.sh && bin/create_intermediate.sh && bin/create_server.sh && bin/create_codesign.sh && bin/create_organization_smime_pki.sh

# Single S/MIME certificate creation
bin/create_smime.sh userc@organization.org userc_organization

# Unset the variable CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY
unset CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY

#!/usr/bin/env sh

: <<'PKI_STRUCTURE'
# PKI Structure

This set of shell scripts and `openssl` configuration files creates
a PKI structure for common applications that include a certificate
authority, intermediate certificate authority, server certificates,
S/MIME certificates, code signing certificates, and `https` inspection
certificates for `privoxy` and `adblock2privoxy`.

The products of the scripts are X509 certificates and keys in both
CER, PEM, and PKCS12 formats. All keys are passphrase protected.

The files must of course be modified for specific PKI deployments. An example
workflow to accomplish this is:
```sh
find . -type f \( -name '*.sh' -o -name '*.cnf' \) -exec egrep -E -l -i -e 'myorganization' {} ';'
find . -type f \( -name '*.sh' -o -name '*.cnf' \) -exec egrep -E -l -i -e 'myorganization' {} ';' | xargs sed -E -i '' 's|myorganization(\.org)?|NewOrganization|ig'
```

To create the entire PKI structure:
```sh
sh README.md
```
PKI_STRUCTURE

# PKI Structure

printf "These files must be modified to a specific MyOrganization,\nhostname.myorganization.org, etc."
find . -type f \( -name '*.sh' -o -name '*.cnf' \) -exec egrep -E -l -i -e 'myorganization' {} ';'

# Replacement command:
# find . -type f \( -name '*.sh' -o -name '*.cnf' \) -exec egrep -E -l -i -e 'myorganization' {} ';' | xargs sed -E -i -e 's|myorganization(\.org)?|NewOrganization|ig'


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

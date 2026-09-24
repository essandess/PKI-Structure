#!/usr/bin/env bash

# clean_everything_and_create_pki.sh
#
# ############################################################################
# #  WARNING - DESTRUCTIVE                                                  #
# #                                                                         #
# #  This script UNCONDITIONALLY DELETES every existing key, certificate,   #
# #  and CA database in this PKI deployment (root, intermediate, server,    #
# #  codesign, S/MIME, privoxy, adblock2privoxy) and then regenerates the   #
# #  entire chain of trust from scratch.                                    #
# #                                                                         #
# #  Anyone already holding a certificate or key from this PKI - issued     #
# #  S/MIME certs, deployed server certs, trust-anchored root/intermediate  #
# #  certs on other machines - will need to be reissued and redeployed      #
# #  after this runs, since the regenerated root/intermediate will have     #
# #  entirely new keys and will not chain to anything issued previously.    #
# #                                                                         #
# #  Do not run this against a live/production PKI unless you intend       #
# #  exactly this. There is no undo once the -vc clean step completes.     #
# ############################################################################

set -e
set -E
trap 'rc=$?; echo "Error: $(basename "$0") failed (exit ${rc}) at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

echo "This will PERMANENTLY DELETE and regenerate the ENTIRE PKI in this directory:"
echo "  $(pwd)"
echo
echo "This includes the root CA, intermediate CA, server, codesign, S/MIME,"
echo "privoxy, and adblock2privoxy keys and certificates. Anything issued by"
echo "the current root/intermediate will no longer be valid once this completes."
echo
read -p "Type 'yes' (in full) to proceed, anything else to abort: " -r
echo
if [ "${REPLY}" != "yes" ]; then
    echo "Aborted. Nothing was changed." >&2
    exit 1
fi

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

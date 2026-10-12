#!/usr/bin/env bash

# pki_test.sh

set -e
set -E
set -o pipefail
trap 'rc=$?; echo "Error: $(basename "$0") failed (exit ${rc}) at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
if [ "$#" -gt 0 ]; then
    echo "Error: $(basename "$0") takes no arguments (got $#)." >&2
    echo "Usage: $(basename "$0")" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

# tests

# initial PKI
bin/clean_everything_and_create_pki.sh --create-pki

# supersede some certs
bin/create_intermediate.sh
bin/create_organization_smime.sh

# credentials and MDM creation
for yml in myorganization-trust.yaml \
    myorganization-settings.yaml \
    persona-settings.yaml; do
    cp -p "mdm-private/yaml/${yml}.sample" "mdm-private/yaml/${yml}"
done

bin/create_organization_credentials.sh
bin/create_organization_mdm.sh

# test overwriting and included revoked/supercede encryption certs
bin/create_credentials.sh 'persona_{gmail,comcast}_*' 'personb_*_2026' \
    --allow-expired-encryption --allow-superseded-encryption

# test installer scripts
mdm-private/credentials/install_credentials_cacerts.sh --check-signature-integrity

# KeePass item

DB="mdm-private/credentials/passwords.kdbx"
DB_PASS="squeamishossifrage"
printf "%s\n%s\n" "$DB_PASS" "$DB_PASS" | keepassxc-cli db-create -p "${DB}"

printf "%s\n" "$DB_PASS" bin/create_keepass_entry.sh \
    --db "${DB}" \
    mdm-private/credentials/install_credentials_persona_LBgmailCcomcastRB_S_personb_S_2026.sh

printf "%s\n" "$DB_PASS" bin/create_keepass_entry.sh \
    --db "${DB}" --individual-smime-passwords \
    mdm-private/credentials/install_credentials_persona_LBgmailCcomcastRB_S_personb_S_2026.sh

bin/create_keepass_entry.sh \
    --xml-out mdm-private/credentials/install_credentials_persona_LBgmailCcomcastRB_S_personb_S_2026.xml \
    mdm-private/credentials/install_credentials_persona_LBgmailCcomcastRB_S_personb_S_2026.sh

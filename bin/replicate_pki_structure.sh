#!/usr/bin/env bash
# replicate_pki_structure.sh
#
# Copies PKI-Structure's scripts and openssl configs to a new deployment
# directory. Never overwrites an existing identity.env or
# create_organization_smime_pki.sh, seeds them from the baseline template.
#
# Usage: replicate_pki_structure.sh [DEST]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_STRUCTURE_SRC="${PKI_STRUCTURE_SRC:-$(cd "${SCRIPT_DIR}/.." && pwd)/}"
SRC="${PKI_STRUCTURE_SRC}"
DEST="${1:-.}"

mkdir -p "${DEST}"

rsync -am \
    --exclude='.git/' \
    --exclude='*.env' \
    --exclude='create_organization_smime_pki.sh' \
    --include='*/' \
    --include='*.sh' \
    --include='*.cnf' \
    --include='*.md' \
    --include='LICENSE' \
    --exclude='*' \
    "${SRC}" "${DEST}/"

# Seed personalized files only if DEST doesn't already have them.
for PERSONALIZED in identity.env bin/create_organization_smime_pki.sh; do
    BASELINE="${SRC}${PERSONALIZED}.sample"
    [ -f "${BASELINE}" ] || BASELINE="${SRC}${PERSONALIZED}"

    if [ -f "${DEST}/${PERSONALIZED}" ]; then
        echo "Existing ${DEST}/${PERSONALIZED} left untouched."
    elif [ -f "${BASELINE}" ]; then
        cp -p "${BASELINE}" "${DEST}/${PERSONALIZED}"
        echo "Seeded ${DEST}/${PERSONALIZED} from $(basename "${BASELINE}") - edit it for this deployment."
    else
        echo "Warning: no baseline ${PERSONALIZED} found in '${SRC}'; none created in '${DEST}'." >&2
    fi
done

#!/usr/bin/env bash
# replicate_pki_structure.sh
#
# Copies PKI-Structure's scripts and openssl configs to a new deployment
# directory. Never overwrites an existing identity.env there; if the
# destination has none yet, seeds it from the baseline template.
#
# Usage: replicate_pki_structure.sh [SRC] [DEST]

set -euo pipefail

SRC="${1:-$HOME/Documents/Source/github/essandess/PKI-Structure}/"
DEST="${2:-.}"

mkdir -p "${DEST}"

rsync -av \
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

# Seed identity.env only if DEST doesn't already have one.
BASELINE_IDENTITY="${SRC}identity.env.sample"
[ -f "${BASELINE_IDENTITY}" ] || BASELINE_IDENTITY="${SRC}identity.env"

if [ -f "${DEST}/identity.env" ]; then
    echo "Existing ${DEST}/identity.env left untouched."
elif [ -f "${BASELINE_IDENTITY}" ]; then
    cp -p "${BASELINE_IDENTITY}" "${DEST}/identity.env"
    echo "Seeded ${DEST}/identity.env from $(basename "${BASELINE_IDENTITY}") - edit it for this deployment."
else
    echo "Warning: no baseline identity.env found in ${SRC}; none created in ${DEST}." >&2
fi

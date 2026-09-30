#!/usr/bin/env bash
# replicate_pki_structure.sh
#
# Copies PKI-Structure's scripts and openssl configs to a new deployment
# directory. Never overwrites an existing pki_identity.env,
# create_organization_smime_pki.sh or mdm-private/yaml/myorganization-trust.yaml;
# seeds them from the baseline template.
#
# mdm-private/ holds YAML and .mobileconfig files that contain secrets. It is never
# copied from the source tree (only the .sample seeds the YAML). What this script creates
# there is 0700 for directories and 0600 for files (ownership is left as the invoking user).
# Anything already in mdm-private/ is only audited: loose permissions produce a warning and
# a prompt to fix. The source tree's mdm-private/ is audited the same way.
#
# Usage: replicate_pki_structure.sh [DEST]

set -euo pipefail

MDM_PRIVATE="mdm-private"
MDM_PRIVATE_YAML="${MDM_PRIVATE}/yaml"

# Warn about paths under $1 that are not 0700 (dirs) / 0600 (files), and
# offer to fix them. $2 is a label for the messages. Nothing is changed unless the answer is y.
audit_private() {
    local dir="$1" label="$2" loose symlinks answer
    [ -d "${dir}" ] || return 0

    loose="$(find "${dir}" \( -type d ! -perm 0700 \) -o \( -type f ! -perm 0600 \) \
                           2>/dev/null | { xargs -I{} ls -ld {} 2>/dev/null || true; })"
    [ -n "${loose}" ] || return 0

    echo >&2
    echo "WARNING: these ${label} private paths under ${dir} may hold secrets but are not restricted" >&2
    echo "         (want 0700 directories / 0600 files):" >&2
    echo "${loose}" | sed 's/^/  /' >&2

    if [ ! -t 0 ]; then
        echo "Not changed (no terminal to prompt on)." >&2
        return 0
    fi
    read -r -p "Change them now? [y/N] " answer || answer=""
    case "${answer}" in
        [yY]|[yY][eE][sS])
            symlinks="$(find "${dir}" -type l)"
            if [ -n "${symlinks}" ]; then
                echo "Error: symlink(s) under '${dir}', refusing to chmod:" >&2
                echo "${symlinks}" >&2
                exit 1
            fi
            find "${dir}" -type d -exec chmod 0700 {} +
            find "${dir}" -type f -exec chmod 0600 {} +
            echo "Set 0700 on directories and 0600 on files under ${dir}."
            ;;
        *)
            echo "WARNING: continuing with loose permissions on ${dir}." >&2
            ;;
    esac
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_STRUCTURE_SRC="${PKI_STRUCTURE_SRC:-$(cd "${SCRIPT_DIR}/.." && pwd)/}"
SRC="${PKI_STRUCTURE_SRC}"
DEST="${1:-.}"

mkdir -p "${DEST}"

# The source's private directory supplies the seed YAML, so check it first.
audit_private "${SRC}${MDM_PRIVATE}" "SOURCE"

rsync -am \
    --exclude='.git/' \
    --exclude='*.env' \
    --exclude='create_organization_smime_pki.sh' \
    --exclude="${MDM_PRIVATE}/" \
    --include='*/' \
    --include='*.sh' --include='*.py' \
    --include='*.cnf' \
    --include='*.md' \
    --include='LICENSE' \
    --exclude='*' \
    "${SRC}" "${DEST}/"

# A new private directory is created closed (0700) before anything goes in it.
if [ ! -e "${DEST}/${MDM_PRIVATE}" ]; then
    ( umask 077; mkdir -p "${DEST}/${MDM_PRIVATE}" )
fi

# Seed personalized files only if DEST doesn't already have them.
for PERSONALIZED in \
    pki_identity.env \
    bin/create_organization_smime_pki.sh \
    bin/create_organization_mdm.sh \
    "${MDM_PRIVATE_YAML}/ios-restrictions-baseline.yaml" \
    "${MDM_PRIVATE_YAML}/myorganization-settings.yaml" \
    "${MDM_PRIVATE_YAML}/myorganization-trust.yaml" \
    "${MDM_PRIVATE_YAML}/persona-settings.yaml" \
    ; do
    BASELINE="${SRC}${PERSONALIZED}.sample"
    [ -f "${BASELINE}" ] || BASELINE="${SRC}${PERSONALIZED}"

    if [ -f "${DEST}/${PERSONALIZED}" ]; then
        echo "Existing ${DEST}/${PERSONALIZED} left untouched."
    elif [ -f "${BASELINE}" ]; then
        if [[ "${PERSONALIZED}" == "${MDM_PRIVATE}/"* ]]; then
            # private file: created closed, 0600
            PRIVATE_SUBDIR="$(dirname "${DEST}/${PERSONALIZED}")"
            [ -d "${PRIVATE_SUBDIR}" ] || ( umask 077; mkdir -p "${PRIVATE_SUBDIR}" )
            ( umask 077; cp "${BASELINE}" "${DEST}/${PERSONALIZED}" )
            chmod 0600 "${DEST}/${PERSONALIZED}"
        else
            mkdir -p "$(dirname "${DEST}/${PERSONALIZED}")"; cp -p "${BASELINE}" "${DEST}/${PERSONALIZED}"
        fi
        echo "Seeded ${DEST}/${PERSONALIZED} from $(basename "${BASELINE}") - edit it for this deployment."
    else
        echo "Warning: no baseline ${PERSONALIZED} found in '${SRC}'; none created in '${DEST}'." >&2
    fi
done

# Audit everything under the destination's mdm-private/ (new and pre-existing), unless it is
# the same directory as the source (already audited above).
if [ "$(cd "${SRC}" && pwd -P)" != "$(cd "${DEST}" && pwd -P)" ]; then
    audit_private "${DEST}/${MDM_PRIVATE}" "DESTINATION"
fi

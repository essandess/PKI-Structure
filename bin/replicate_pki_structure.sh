#!/usr/bin/env bash
# replicate_pki_structure.sh
#
# Copies PKI-Structure's scripts and openssl configs to a new deployment
# directory. Never overwrites an existing pki_identity.env,
# create_organization_smime.sh or mdm-private/yaml/myorganization-trust.yaml;
# seeds them from the baseline template.
#
# By default, nothing already present in DEST is ever overwritten by the
# generic .sh/.py/.cnf/.md copy step (rsync --ignore-existing), so re-running
# this script against a deployment you've since edited is safe. Pass
# -ow/--overwrite to allow overwriting; you will be asked to confirm first
# (set PKI_ASSUME_YES=1 to skip that prompt).
#
# Permissions on DEST follow pki_lockdown:
#   - directories named *private* (and everything under them): dirs 0700
#   - other directories: 0755
#   - *.sh / *.py files: 0750
#   - other files: 0600 under a private directory, 0640 elsewhere
# Files and directories this script creates or replaces are set to these modes.
# Anything already in DEST/mdm-private/ is only audited: deviations produce a
# warning and a prompt to fix. The source tree's permissions are not examined.
#
# Usage: replicate_pki_structure.sh [-ow|--overwrite] [-h|--help] [DEST]

set -euo pipefail

MDM_PRIVATE="mdm-private"
MDM_PRIVATE_YAML="${MDM_PRIVATE}/yaml"

# Print the octal mode pki_lockdown would give $1 (a path relative to DEST).
# The path must exist (it is tested to see whether it is a directory).
pki_mode() {
    local rel="${1%/}" dirpart c
    local private=0 parts=()

    if [ -d "${DEST}/${rel}" ]; then
        dirpart="${rel}"
    else
        dirpart="$(dirname "${rel}")"
    fi
    IFS=/ read -r -a parts <<< "${dirpart}"
    for c in "${parts[@]}"; do
        [[ "${c}" == *private* ]] && private=1
    done

    if [ -d "${DEST}/${rel}" ]; then
        if [ "${private}" == "1" ]; then echo 700; else echo 755; fi
    else
        case "${rel}" in
            *.sh|*.py) echo 750 ;;
            *) if [ "${private}" == "1" ]; then echo 600; else echo 640; fi ;;
        esac
    fi
}

# Warn about paths under $1 whose mode differs from pki_mode, and offer to
# fix them. Nothing is changed unless the answer is y.
audit_private() {
    local dir="$1" p want have loose="" symlinks answer

    [ -d "${dir}" ] || return 0

    while IFS= read -r -d '' p; do
        [ -L "${p}" ] && continue
        [[ "${p}" == *.sample || "${p##*/}" == .turd_* ]] && continue
        want="$(pki_mode "${p#"${DEST}"/}")"
        have="$(stat -c %a "${p}" 2>/dev/null || stat -f %Lp "${p}")"
        if [ "${have}" != "${want}" ]; then
            loose+="${p} (is ${have}, want ${want})"$'\n'
        fi
    done < <(find "${dir}" -print0)

    [ -n "${loose}" ] || return 0

    echo >&2
    echo "WARNING: these paths under ${dir} do not match the expected permissions:" >&2
    printf '%s' "${loose}" | sed 's/^/  /' >&2

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
            while IFS= read -r -d '' p; do
                [[ "${p}" == *.sample || "${p##*/}" == .turd_* ]] && continue
                chmod "$(pki_mode "${p#"${DEST}"/}")" "${p}"
            done < <(find "${dir}" -print0)
            echo "Set expected permissions under ${dir}."
            ;;
        *)
            echo "WARNING: continuing with unexpected permissions on ${dir}." >&2
            ;;
    esac
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_STRUCTURE_SRC="${PKI_STRUCTURE_SRC:-$(cd "${SCRIPT_DIR}/.." && pwd)/}"
SRC="${PKI_STRUCTURE_SRC}"

# -- argument parsing, same style as pki_structure.sh -----------------------
OVERWRITE=0
HELP=0
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
	-ow|--overwrite)
	    OVERWRITE=1
	    shift
	    ;;
	-h|--help)
	    HELP=1
	    shift
	    ;;
	*)
	    POSITIONAL_ARGS+=("$1")
	    shift
	    ;;
    esac
done
set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

if [ "${HELP}" != "0" ]; then
    cat <<USEAGE
Useage:

$(basename "$0") [-ow|--overwrite] [-h|--help] [DEST]

DEST defaults to the current directory. Without -ow/--overwrite, files
already present in DEST are never replaced (rsync --ignore-existing).
With -ow/--overwrite, you will be asked to confirm before anything is
replaced; set PKI_ASSUME_YES=1 to skip that prompt.
USEAGE
    exit 0
fi

DEST="${1:-.}"

mkdir -p "${DEST}"
DEST="$(cd "${DEST}" && pwd)"

RSYNC_EXCLUDE_INCLUDE=(
    --exclude='.git/'
    --exclude='*.env'
    --exclude='*.conf'
    --exclude='*.yaml'
    --exclude='create_organization_smime.sh'
    --exclude='create_organization_mdm.sh'
    --include='*/'
    --include='*.sh'
    --include='*.py'
    --include='*.cnf'
    --include='*.md'
    --include="etc/*.sample"
    --include="${MDM_PRIVATE_YAML}/*.sample"
    --include='LICENSE'
    --exclude='*'
)

RSYNC_OVERWRITE_FLAGS=(--ignore-existing)

if [ "${OVERWRITE}" == "1" ]; then
    # Show what -ow would actually replace before asking.
    CHANGES="$(rsync -am --dry-run --itemize-changes \
        "${RSYNC_EXCLUDE_INCLUDE[@]}" \
        "${SRC}" "${DEST}/")"
    if [ -n "${CHANGES}" ]; then
        echo >&2
        echo "WARNING: --overwrite will replace these existing files under '${DEST}' with the source's versions:" >&2
        echo "${CHANGES}" | sed 's/^/  /' >&2
    else
        echo "Nothing under '${DEST}' would actually be changed by --overwrite." >&2
    fi

    if [ "${PKI_ASSUME_YES:-0}" == "0" ]; then
        echo "(Set PKI_ASSUME_YES=1 to skip this prompt in future/scripted runs.)" >&2
        read -p "Overwrite existing files in '${DEST}' with the source's versions? [y/N] " -r < /dev/tty
        echo    # (optional) move to a new line
        if [[ ! "${REPLY}" =~ ^[y]$ ]]; then
            echo "Aborted." >&2
            exit 1
        fi
    fi
    RSYNC_OVERWRITE_FLAGS=()
fi

# exclude/include to avoid any hint of overwriting exisiting personalized files
TRANSFERRED="$(rsync -am --out-format='%n' "${RSYNC_OVERWRITE_FLAGS[@]}" \
    "${RSYNC_EXCLUDE_INCLUDE[@]}" \
    "${SRC}" "${DEST}/")"

# rsync -a carries over the source's modes; set what was created/replaced to
# the pki_lockdown modes instead.
while IFS= read -r REL; do
    REL="${REL%/}"
    case "${REL}" in ""|"."|*.sample) continue ;; esac
    [ -L "${DEST}/${REL}" ] && continue
    chmod "$(pki_mode "${REL}")" "${DEST}/${REL}"
done <<< "${TRANSFERRED}"

# A new private directory is created closed (0700) before anything goes in it.
if [ ! -e "${DEST}/${MDM_PRIVATE}" ]; then
    ( umask 077; mkdir -p "${DEST}/${MDM_PRIVATE}" )
fi

# Seed personalized files only if DEST doesn't already have them.
# Only seed necessary dependencies ; user expected to personalize the rest
for PERSONALIZED in \
    pki_identity.env \
    bin/create_organization_mdm.sh \
    bin/create_organization_smime.sh \
    "${MDM_PRIVATE_YAML}/ios-restrictions-baseline.yaml" \
    ; do
    BASELINE="${SRC}${PERSONALIZED}.sample"
    [ -f "${BASELINE}" ] || BASELINE="${SRC}${PERSONALIZED}"

    if [ -f "${DEST}/${PERSONALIZED}" ]; then
        echo "Existing ${DEST}/${PERSONALIZED} left untouched."
    elif [ -f "${BASELINE}" ]; then
        if [[ "${PERSONALIZED}" == "${MDM_PRIVATE}/"* ]]; then
            # private subdirectory: created closed (0700)
            PRIVATE_SUBDIR="$(dirname "${DEST}/${PERSONALIZED}")"
            [ -d "${PRIVATE_SUBDIR}" ] || ( umask 077; mkdir -p "${PRIVATE_SUBDIR}" )
            ( umask 077; cp "${BASELINE}" "${DEST}/${PERSONALIZED}" )
        else
            mkdir -p "$(dirname "${DEST}/${PERSONALIZED}")"
            cp "${BASELINE}" "${DEST}/${PERSONALIZED}"
        fi
        chmod "$(pki_mode "${PERSONALIZED}")" "${DEST}/${PERSONALIZED}"
        echo "Seeded ${DEST}/${PERSONALIZED} from $(basename "${BASELINE}") - edit it for this deployment."
    else
        echo "Warning: no baseline ${PERSONALIZED} found in '${SRC}'; none created in '${DEST}'." >&2
    fi
done

# Audit everything under the destination's mdm-private/ (new and pre-existing),
# unless DEST is the source itself (whose permissions are not our business).
if [ "$(cd "${SRC}" && pwd -P)" != "${DEST}" ] && [ "$(cd "${SRC}" && pwd -P)" != "$(cd "${DEST}" && pwd -P)" ]; then
    audit_private "${DEST}/${MDM_PRIVATE}"
fi

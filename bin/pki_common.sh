#!/usr/bin/env bash

# pki_common.sh
#
# Shared functions for reissuing a cert without colliding with the
# previous run's files (pki_archive_existing_cert /
# pki_restore_archived_cert), and for correctly revoking any other
# still-valid certificate the issuing CA has on record under the same
# CommonName (pki_revoke_matching_cn) - looked up authoritatively in
# the issuer's own index.txt, not guessed from a filename.

pki_confirm() {
    local msg="$1"
    if [ "${PKI_ASSUME_YES:-0}" != "0" ]; then
	return 0
    fi
    echo "${msg}" >&2
    echo "(Set PKI_ASSUME_YES=1 to skip this prompt in future/scripted runs.)" >&2
    read -p "Proceed? [y/N] " -r < /dev/tty
    echo
    if [[ ! "${REPLY}" =~ ^[Yy]$ ]]; then
	echo "Aborted: declined to revoke/supersede the existing certificate." >&2
	echo "Re-run and answer 'y', or set PKI_ASSUME_YES=1, to proceed automatically." >&2
	exit 1
    fi
}

cert_sha1() {
    "${OPENSSL}" x509 -noout -fingerprint -sha1 -inform pem -in "$1" \
        | sed -e 's|^.*Fingerprint=||' -e 's|:||g' \
        | tr '[:upper:]' '[:lower:]'
}

pki_archive_existing_cert() {
    local certdir="$1" certname="$2" files="$3"
    local old_cert="${certdir}/certs/${certname}.cert.pem"
    PKI_ARCHIVED_SHA1=""
    [ -f "${old_cert}" ] || return 0

    local sha1
    sha1=$(cert_sha1 "${old_cert}")
    if [ -z "${sha1}" ]; then
        echo "Error: could not compute the SHA1 fingerprint of '${old_cert}'." >&2
        exit 1
    fi
    PKI_ARCHIVED_SHA1="${sha1}"

    echo "Archiving existing ${certname} as ${certname}.${PKI_ARCHIVED_SHA1}.*" >&2
    local item dir ext
    for item in ${files}; do
        dir=${item%%/*}
        ext=${item#*/}
        if [ -f "${certdir}/${dir}/${certname}.${ext}" ]; then
            mv -f "${certdir}/${dir}/${certname}.${ext}" \
               "${certdir}/${dir}/${certname}.${PKI_ARCHIVED_SHA1}.${ext}"
        fi
    done
}

pki_restore_archived_cert() {
    local certdir="$1" certname="$2" files="$3"
    if [ -z "${PKI_ARCHIVED_SHA1}" ] || [ -n "${REISSUED}" ]; then
        return 0
    fi
    echo "Reissuing '${certname}' failed; restoring the previous one." >&2
    local item dir ext
    for item in ${files}; do
        dir=${item%%/*}
        ext=${item#*/}
        if [ -f "${certdir}/${dir}/${certname}.${PKI_ARCHIVED_SHA1}.${ext}" ]; then
            cp -p "${certdir}/${dir}/${certname}.${PKI_ARCHIVED_SHA1}.${ext}" \
               "${certdir}/${dir}/${certname}.${ext}"
        fi
    done
}

# issuer_dir, issuer_config, target_cn, exclude_serial, crl_caname
pki_revoke_matching_cn() {
    local issuer_dir="$1" issuer_config="$2" target_cn="$3" \
          exclude_serial="$4" crl_caname="$5"
    [ -f "${issuer_dir}/index.txt" ] || return 0

    local status serial subject cn newcert
    local revoked_any=0
    while IFS=$'\t' read -r -a fields; do
        status="${fields[0]}"
        [ "${status}" = "V" ] || continue

        local n=${#fields[@]}
        serial="${fields[$((n-3))]}"
        subject="${fields[$((n-1))]}"

        [ "${serial}" = "${exclude_serial}" ] && continue

        cn="${subject#*/CN=}"
        cn="${cn%%/*}"
        [ "${cn}" = "${target_cn}" ] || continue

        newcert="${issuer_dir}/newcerts/${serial}.pem"
        if [ ! -f "${newcert}" ]; then
            echo "Warning: ${issuer_dir}/index.txt references serial ${serial} (CN=${target_cn}) but ${newcert} is missing; skipping." >&2
            continue
        fi

        pki_confirm "An existing valid certificate with CommonName '${target_cn}' (serial ${serial}, in ${issuer_dir}) will be superseded and revoked."
        echo "Revoking superseded certificate: serial ${serial}, CN=${target_cn}, in ${issuer_dir}" >&2
        "${OPENSSL}" ca -config "${issuer_config}" \
            -revoke "${newcert}" \
            -crl_reason superseded \
            -passin file:"${issuer_dir}"/private/passphrase.txt
        revoked_any=1
    done < "${issuer_dir}/index.txt"

    if [ "${revoked_any}" = "1" ]; then
        "${PKI_ROOT}"/bin/create_crl.sh "${crl_caname}"
    fi
}

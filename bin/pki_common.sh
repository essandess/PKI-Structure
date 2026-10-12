#!/usr/bin/env bash

# pki_common.sh
#
# Shared functions for reissuing a cert without colliding with the
# previous run's files (pki_archive_existing_cert /
# pki_restore_archived_cert), and for correctly revoking any other
# still-valid certificate the issuing CA has on record under the same
# CommonName (pki_revoke_matching_cn) - looked up authoritatively in
# the issuer's own index.txt, not guessed from a filename.
#
# Also: renewal of a CA certificate with its existing key (pki_ca_prepare),
# validity capped at the issuer's remaining life (pki_cap_days), random
# per-identity .p12 passwords (pki_random_password), and cert_is_ca.

# How close to expiry a self-signed CA certificate must be before a new one
# is issued in its place (see pki_ca_prepare).
PKI_RENEW_WINDOW_DAYS=${PKI_RENEW_WINDOW_DAYS:-30}

# pki_confirm MESSAGE [ABORT_MESSAGE]
pki_confirm() {
    local msg="$1"
    local abort="${2:-Aborted: declined to revoke/supersede the existing certificate.}"
    if [ "${PKI_ASSUME_YES:-0}" != "0" ]; then
	return 0
    fi
    echo "${msg}" >&2
    echo "(Set PKI_ASSUME_YES=1 to skip this prompt in future/scripted runs.)" >&2
    read -p "Proceed? [y/N] " -r < /dev/tty
    echo
    if [[ ! "${REPLY}" =~ ^[Yy]$ ]]; then
	echo "${abort}" >&2
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

# ---------------------------------------------------------------------
# Dates and validity
# ---------------------------------------------------------------------

# pki_date_epoch "Oct  3 08:32:07 2026 GMT": seconds since the epoch (GNU or BSD date)
pki_date_epoch() {
    date -u -d "$1" +%s 2>/dev/null || date -u -j -f '%b %e %T %Y %Z' "$1" +%s
}

# pki_cert_end_epoch CERT: notAfter of a PEM certificate, in epoch seconds
pki_cert_end_epoch() {
    local s
    s=$("${OPENSSL}" x509 -noout -enddate -in "$1" | sed 's|^notAfter=||')
    pki_date_epoch "${s}"
}

# pki_cap_days ISSUER_CERT DAYS: print DAYS, or fewer so that a certificate
# issued now ends a day before its issuer does. Fails if the issuer is about
# to expire.
pki_cap_days() {
    local issuer="$1" days="$2" end now left
    end=$(pki_cert_end_epoch "${issuer}")
    now=$(date +%s)
    left=$(( (end - now) / 86400 - 1 ))
    if [ "${left}" -lt 1 ]; then
        echo "Error: issuer certificate '${issuer}' expires in less than two days; renew it first." >&2
        return 1
    fi
    if [ "${left}" -lt "${days}" ]; then
        echo "Note: validity shortened from ${days} to ${left} days because issuer '${issuer}' ends sooner." >&2
        days="${left}"
    fi
    printf '%s' "${days}"
}

# pki_expires_within CERT [DAYS]: true if CERT expires within DAYS (default
# PKI_RENEW_WINDOW_DAYS) or has already expired.
pki_expires_within() {
    local days="${2:-${PKI_RENEW_WINDOW_DAYS}}"
    ! "${OPENSSL}" x509 -checkend $(( days * 86400 )) -noout -in "$1" >/dev/null 2>&1
}

# ---------------------------------------------------------------------
# CA certificate renewal
# ---------------------------------------------------------------------

# pki_ca_prepare CERTDIR CERTNAME FILES NEW_KEY WINDOW_ONLY
#
# Call BEFORE sourcing pki_structure.sh, with OPENSSL defined. If the CA
# certificate already exists it is archived (as <name>.<sha1>.*) so that a
# new one can be issued, and the EXIT trap restores it if issuing fails
# (the caller sets REISSUED=1 once the new certificate exists).
#
#   WINDOW_ONLY=1  (self-signed CAs: root, privoxy) a new certificate is
#                  issued only within PKI_RENEW_WINDOW_DAYS of expiry, or
#                  after it; earlier than that is an error.
#   WINDOW_ONLY=0  (intermediate) renewal is allowed at any time, after a
#                  confirmation.
#
# Unless NEW_KEY is 1 the existing key is reused: PKI_RENEW is set to 1 and
# the caller must run pki_ca_restore_key after sourcing pki_structure.sh
# and skip generating a key. With NEW_KEY=1 everything the old key signed
# has to be reissued.
pki_ca_prepare() {
    local certdir="$1" certname="$2" files="$3" new_key="$4" window_only="$5"
    local cert="${certdir}/certs/${certname}.cert.pem"
    local key="${certdir}/private/${certname}.key.pem"
    local enddate what

    PKI_RENEW=0
    PKI_CA_DIR="${certdir}"
    PKI_CA_NAME="${certname}"
    PKI_CA_FILES="${files}"

    # Nothing issued yet (or a key without a certificate, which
    # pki_structure.sh reports).
    [ -f "${cert}" ] || return 0

    if ! "${OPENSSL}" x509 -noout -in "${cert}" >/dev/null 2>&1; then
        echo "Error: cannot read '${cert}'." >&2
        exit 1
    fi
    enddate=$("${OPENSSL}" x509 -noout -enddate -in "${cert}" | sed 's|^notAfter=||')

    if [ "${window_only}" = "1" ] && ! pki_expires_within "${cert}"; then
        echo "Error: '${cert}' is valid until ${enddate}, more than ${PKI_RENEW_WINDOW_DAYS} days away." >&2
        echo "A new ${certname} is issued only within ${PKI_RENEW_WINDOW_DAYS} days of expiry (change with PKI_RENEW_WINDOW_DAYS)," >&2
        echo "or after cleaning with -c/-vc, which deletes the CA and everything it issued." >&2
        exit 1
    fi

    if [ "${new_key}" != "1" ]; then
        if [ ! -f "${key}" ]; then
            echo "Error: '${key}' is missing, so '${cert}' cannot be renewed with its key; use --new-key." >&2
            exit 1
        fi
        PKI_RENEW=1
        what="renew ${certname} (valid until ${enddate}) with its existing key"
    else
        what="replace ${certname} (valid until ${enddate}) with a NEW KEY"
    fi
    pki_confirm "About to ${what}; the current files are archived as ${certname}.<sha1>.*." \
        "Aborted: declined to renew ${certname}."

    trap 'pki_restore_archived_cert "${PKI_CA_DIR}" "${PKI_CA_NAME}" "${PKI_CA_FILES}"' EXIT
    pki_archive_existing_cert "${certdir}" "${certname}" "${files}"
}

# pki_ca_restore_key CERTDIR CERTNAME: put the archived key back (renewal
# with the same key). Call after sourcing pki_structure.sh.
pki_ca_restore_key() {
    local certdir="$1" certname="$2"
    cp -p "${certdir}/private/${certname}.${PKI_ARCHIVED_SHA1}.key.pem" \
       "${certdir}/private/${certname}.key.pem"
}

# ---------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------

# pki_random_password: 24 random letters and digits
pki_random_password() {
    local pw=""
    while [ "${#pw}" -lt 24 ]; do
        pw="${pw}$("${OPENSSL}" rand -base64 48 | tr -dc 'A-Za-z0-9')"
    done
    printf '%s' "${pw:0:24}"
}

# ---------------------------------------------------------------------
# Certificate properties. Needs OpenSSL >= 1.1.1 for `x509 -ext`.
# ---------------------------------------------------------------------

# cert_is_ca CERT: true if basicConstraints says CA:TRUE.
cert_is_ca() {
    "${OPENSSL}" x509 -noout -ext basicConstraints -in "$1" 2>/dev/null | grep -q 'CA:TRUE'
}

# ---------------------------------------------------------------------
# Intermediate CA scope
# ---------------------------------------------------------------------

# pki_assert_ca_scope CERT KIND: succeed only if the intermediate certificate
# CERT is restricted the way its KIND requires; otherwise say why on stderr.
#   intermediate        TLS/code signing: serverAuth in the extendedKeyUsage,
#                       no emailProtection, and a critical nameConstraints
#                       with permitted DNS names
#   intermediate_smime  S/MIME: the extendedKeyUsage is emailProtection only
# Needs OpenSSL >= 1.1.1 for `x509 -ext`.
pki_assert_ca_scope() {
    local cert="$1" kind="$2" text eku nc

    text=$("${OPENSSL}" x509 -noout -ext extendedKeyUsage,nameConstraints -in "${cert}" 2>/dev/null) || true
    eku=$(printf '%s\n' "${text}" | awk '/^X509v3 Extended Key Usage:/ {m=1; next} /^X509v3 Name Constraints:/ {m=0} m {print}')
    nc=$(printf '%s\n' "${text}" | awk '/^X509v3 Name Constraints:/ {m=1; print; next} /^X509v3 Extended Key Usage:/ {m=0} m {print}')

    case "${kind}" in
        intermediate_smime)
            if ! grep -qi 'E-mail Protection' <<<"${eku}" \
                   || grep -Eqi 'TLS Web|Code Signing|Any Extended' <<<"${eku}"; then
                echo "${cert}: extendedKeyUsage must be emailProtection only." >&2
                return 1
            fi
            ;;
        *)
            if ! grep -qi 'TLS Web Server' <<<"${eku}" \
                   || grep -Eqi 'E-mail Protection|Any Extended' <<<"${eku}"; then
                echo "${cert}: extendedKeyUsage must be serverAuth/codeSigning, without emailProtection." >&2
                return 1
            fi
            if ! grep -q '^X509v3 Name Constraints: critical' <<<"${nc}" \
                   || ! grep -q 'Permitted:' <<<"${nc}" \
                   || ! grep -q 'DNS:' <<<"${nc}"; then
                echo "${cert}: it needs a critical nameConstraints extension with permitted DNS names." >&2
                return 1
            fi
            ;;
    esac
}

# ---------------------------------------------------------------------
# Finishing a certificate
# ---------------------------------------------------------------------

# pki_finish_cert CERTDIR CERTNAME ISSUERDIR ISSUERNAME [P12_PASS_FILE]
# Chain, verify, DER and .p12 of CERTDIR/certs/CERTNAME.cert.pem. Self-signed
# (issuer is the certificate itself): no chain file. P12_PASS_FILE holds the
# .p12 password; default is line 2 of CERTDIR/private/passphrase.txt.
pki_finish_cert() {
    local certdir="$1" certname="$2" issuerdir="$3" issuername="$4" p12pass="${5:-}"
    local cert="${certdir}/certs/${certname}.cert.pem"
    local chain="${certdir}/certs/${certname}.chain.pem"
    local cafile="${issuerdir}/certs/${issuername}.cert.pem"
    local keypass="${certdir}/private/passphrase.txt"
    local p12="${certdir}/private/${certname}.p12" passout p12in

    if [ "${issuerdir}/${issuername}" != "${certdir}/${certname}" ]; then
        if [ -f "${issuerdir}/certs/${issuername}.chain.pem" ]; then
            cafile="${issuerdir}/certs/${issuername}.chain.pem"
        fi
        cat "${cert}" "${cafile}" > "${chain}"
        "${OPENSSL}" verify -CAfile "${cafile}" "${chain}"
    fi
    "${OPENSSL}" verify -CAfile "${cafile}" "${cert}"

    "${OPENSSL}" x509 -outform der -in "${cert}" -out "${certdir}/certs/${certname}.cer"

    # Same file for -passin and -passout: line 1 opens the key, line 2 is
    # the .p12 password (man openssl-passphrase-options).
    if [ -n "${p12pass}" ]; then
        passout="file:${p12pass}"
        p12in="file:${p12pass}"
    else
        passout="file:${keypass}"
        p12in="pass:$(sed -n 2p "${keypass}")"
    fi
    "${OPENSSL}" pkcs12 -legacy -export -out "${p12}" \
        -inkey "${certdir}/private/${certname}.key.pem" -in "${cert}" \
        -passin "file:${keypass}" -passout "${passout}"
    "${OPENSSL}" pkcs12 -legacy -noout -in "${p12}" -passin "${p12in}"
}

# pki_sha1_files MODE CERTDIR CERTNAME NEWNAME "SUBDIR/SUFFIX ..."
# mv or cp CERTNAME.<suffix> to NEWNAME.<sha1>.<suffix>; sets PKI_LEAF_SHA1.
pki_sha1_files() {
    local mode="$1" certdir="$2" certname="$3" newname="$4" files="$5"
    local item dir suffix src dst

    PKI_LEAF_SHA1=$(cert_sha1 "${certdir}/certs/${certname}.cert.pem")
    for item in ${files}; do
        dir=${item%%/*}
        suffix=${item#*/}
        src="${certdir}/${dir}/${certname}.${suffix}"
        dst="${certdir}/${dir}/${newname}.${PKI_LEAF_SHA1}.${suffix}"
        [ -f "${src}" ] || { echo "Error: '${src}' is missing." >&2; return 1; }
        case "${mode}" in
            mv) mv -f "${src}" "${dst}" ;;
            cp) cp -p "${src}" "${dst}" ;;
            *) echo "Error: pki_sha1_files mode must be mv or cp." >&2; return 1 ;;
        esac
    done
}

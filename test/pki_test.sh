#!/usr/bin/env bash

# pki_test.sh -- end-to-end and negative tests for the PKI toolkit.
# DESTRUCTIVE: rebuilds the PKI in this tree. Runs only in a disposable tree
# (marker .pki_test_tree) or with PKI_TEST_DESTROY_PKI=1.
# PKI_TEST_VERIFY_FLAGS overrides the openssl-verify strictness flags
# (default -x509_strict); PKI_TEST_SMIME_NAME selects the S/MIME identity.
# PKI_TEST_PATCH_V1

# Re-exec under bash >= 4.4 (the Portfile starts this with sh).
if [ -z "${BASH_VERSION:-}" ] || [ "${BASH_VERSINFO:-0}" -lt 4 ] \
       || { [ "${BASH_VERSINFO:-0}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
    if [ -n "${PKI_TEST_REEXEC:-}" ]; then
        echo "Error: bash >= 4.4 required." >&2
        exit 1
    fi
    exec env PKI_TEST_REEXEC=1 bash "$0" "$@"
fi

set -Eeuo pipefail
shopt -s inherit_errexit
umask 077
trap 'rc=$?; echo "Error: $(basename "$0") failed (exit ${rc}) at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
if [ "$#" -gt 0 ]; then
    echo "Error: $(basename "$0") takes no arguments (got $#)." >&2
    echo "Usage: $(basename "$0")" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

die()  { echo "Error: $*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

# Keep caller overrides from redirecting the tools at another tree or site.
unset CERTDIR CERTNAME ISSUERCADIR ISSUERCANAME SMIME_ISSUERCADIR SMIME_ISSUERCANAME \
      LEGACY_ISSUERCADIR UNSIGNED_DIR SIGNED_DIR PKI_STRUCTURE_SRC PKI_SITE_DIR \
      PKI_SITE_GROUP PKI_ROOT_SHA256 PKI_ROOT_CRL PKI_INTERMEDIATE_CRL \
      PKI_CODESIGN_DIR PKI_CODESIGN_NAME PKI_CODESIGN_SHA1 CERTSHA1
export CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY=1 PKI_ASSUME_YES=1 SHOW_CERT_TEXT=0 SHOW_CRL_TEXT=0

# ---------------------------------------------------------------- guard
MARKER_FILE=.pki_test_tree
if [ ! -e "${MARKER_FILE}" ]; then
    LIVE=$(find root intermediate intermediate_smime server codesign smime privoxy \
                -maxdepth 2 \( -name '*.key.pem' -o -name index.txt \) 2>/dev/null \
               | sed -n 1p || true)
    if [ -n "${LIVE}" ] && [ "${PKI_TEST_DESTROY_PKI:-0}" != 1 ]; then
        die "existing PKI material (${LIVE}); this test deletes it. Use a scratch tree or PKI_TEST_DESTROY_PKI=1."
    fi
    : > "${MARKER_FILE}"
fi

# ---------------------------------------------------------------- tools
. bin/define_openssl.sh
. bin/define_python.sh
case "$("${OPENSSL}" version)" in
    "OpenSSL 3."*) ;;
    *) die "OpenSSL 3 required, found: $("${OPENSSL}" version)" ;;
esac
"${PYTHON}" -c 'import cryptography, yaml' 2>/dev/null \
    || die "${PYTHON} needs the cryptography and PyYAML packages."
for t in tar xz; do command -v "${t}" >/dev/null 2>&1 || die "${t} not found."; done
KPCLI=""
for c in "${KEEPASSXC_CLI:-}" keepassxc-cli /Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli; do
    if [ -n "${c}" ] && command -v "${c}" >/dev/null 2>&1; then
        KPCLI=$(command -v "${c}")
        break
    fi
done
[ -n "${KPCLI}" ] || die "keepassxc-cli not found (set KEEPASSXC_CLI)."
export KEEPASSXC_CLI="${KPCLI}"

[ -f pki_identity.env ] || die "pki_identity.env missing; seed it with bin/replicate_pki_structure.sh."
set -a
. ./pki_identity.env
set +a

TMPD="$(mktemp -d "${TMPDIR:-/tmp}/pki_test.XXXXXX")"
trap 'rm -rf "${TMPD}"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

VERIFY_FLAGS="${PKI_TEST_VERIFY_FLAGS--x509_strict}"
SM="${PKI_TEST_SMIME_NAME:-persona_gmail_2026}"

# ---------------------------------------------------------------- seed deployment files
mkdir -p mdm-private/yaml
for f in smime mdm credentials; do
    [ -f "bin/create_organization_${f}.sh" ] \
        || cp -p "bin/create_organization_${f}.sh.sample" "bin/create_organization_${f}.sh"
    chmod 0750 "bin/create_organization_${f}.sh"
done
for yml in myorganization-trust myorganization-settings persona-settings ios-restrictions-baseline; do
    if [ ! -e "mdm-private/yaml/${yml}.yaml" ]; then
        cp "mdm-private/yaml/${yml}.yaml.sample" "mdm-private/yaml/${yml}.yaml"
    fi
    chmod 0600 "mdm-private/yaml/${yml}.yaml"
done

# ---------------------------------------------------------------- test helpers
PASSED=0
FAILED=0
ok()       { PASSED=$((PASSED + 1)); printf '  ok    %s\n' "$1"; }
bad()      { FAILED=$((FAILED + 1)); printf '  FAIL  %s\n' "$1" >&2; }
show_out() { sed 's/^/        /' "${TMPD}/out" >&2; }

# check DESC CMD...: exit 0 required.
check() {
    local d=$1
    shift
    if "$@" >"${TMPD}/out" 2>&1 </dev/null; then ok "${d}"; else bad "${d}"; show_out; fi
}
# fails DESC CMD...: non-zero exit required.
fails() {
    local d=$1
    shift
    if "$@" >"${TMPD}/out" 2>&1 </dev/null; then bad "${d}: accepted"; show_out; else ok "${d}"; fi
}
# refuse DESC REGEX CMD...: non-zero exit and REGEX (ERE, case-insensitive) in the output.
refuse() {
    local d=$1 re=$2
    shift 2
    if "$@" >"${TMPD}/out" 2>&1 </dev/null; then
        bad "${d}: accepted"; show_out
    elif grep -Eqi -- "${re}" "${TMPD}/out"; then
        ok "${d}"
    else
        bad "${d}: rejected for another reason"; show_out
    fi
}
# run DESC CMD...: setup command; abort the test on failure.
run() {
    local d=$1
    shift
    "$@" >"${TMPD}/run.log" 2>&1 </dev/null || { tail -n 40 "${TMPD}/run.log" >&2; die "${d} failed"; }
}
run_yes() {
    local d=$1
    shift
    printf 'yes\n' | "$@" >"${TMPD}/run.log" 2>&1 || { tail -n 40 "${TMPD}/run.log" >&2; die "${d} failed"; }
}

mode()    { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
mode_is() { [ "$(mode "$1")" = "$2" ]; }
latest()  { { ls -1t "$@" 2>/dev/null || true; } | sed -n 1p; }
cert_fp() { "${OPENSSL}" x509 -noout -fingerprint -sha256 -in "$1"; }

bundle_crls() {
    cat root/crl/root.crl.pem intermediate/crl/intermediate.crl.pem \
        intermediate_smime/crl/intermediate_smime.crl.pem > "${TMPD}/crls.pem" || return 1
    cat intermediate/certs/intermediate.cert.pem \
        intermediate_smime/certs/intermediate_smime.cert.pem > "${TMPD}/ints.pem" || return 1
    cat root/certs/root.cert.pem "${TMPD}/ints.pem" > "${TMPD}/ca_bundle.pem"
}

# vfy PURPOSE CERT [openssl-verify-args]: chain, purpose and CRL check against the root.
vfy() {
    local purpose=$1 cert=$2
    shift 2
    bundle_crls || return 1
    # shellcheck disable=SC2086
    "${OPENSSL}" verify ${VERIFY_FLAGS} -purpose "${purpose}" -crl_check_all \
        -CRLfile "${TMPD}/crls.pem" -CAfile root/certs/root.cert.pem \
        -untrusted "${TMPD}/ints.pem" "$@" "${cert}"
}

# pkival ROLE CERT [flags]: bin/pki_validate.py against the current trust set.
pkival() {
    local role=$1 cert=$2
    shift 2
    bundle_crls || return 1
    "${PYTHON}" bin/pki_validate.py "${role}" "${cert}" \
        --ca-bundle "${TMPD}/ca_bundle.pem" --crl-bundle "${TMPD}/crls.pem" \
        --index intermediate/index.txt --index intermediate_smime/index.txt "$@"
}

# archived_cert NAME ROLE: an S/MIME certificate that is not the current one.
archived_cert() {
    local name=$1 role=$2 cur f
    cur=$(cert_fp "smime/certs/${name}-${role}.cert.pem")
    for f in smime/certs/"${name}-${role}".*.cert.pem; do
        [ -f "${f}" ] || continue
        if [ "$(cert_fp "${f}")" != "${cur}" ]; then
            printf '%s' "${f}"
            return 0
        fi
    done
    return 1
}

crl_ok() {   # crl -verify exits 0 on failure; read its verdict
    local out
    out=$("${OPENSSL}" crl -verify -noout -CAfile "$2" -in "$1" 2>&1) || true
    grep -q '^verify OK' <<<"${out}"
}

revoke() { printf 'yes\n' | bin/revoke_certificate.sh "$@"; }
ptyrun() { "${PYTHON}" "${TMPD}/ptyrun.py" "$@"; }

tamper_header() {   # change a signed header line; signature must break
    sed 's/^INSTALL_FOR=.*/INSTALL_FOR="tampered"/' "$1" > "$2" || return 1
    chmod 0700 "$2"
    ! cmp -s "$1" "$2"
}
tamper_payload() {  # corrupt the first payload line
    awk 'f == 1 && !d { $0 = (substr($0, 1, 1) == "A" ? "B" : "A") substr($0, 2); d = 1 }
         /^__PAYLOAD_BELOW__$/ { f = 1 }
         { print }' "$1" > "$2" || return 1
    chmod 0700 "$2"
    ! cmp -s "$1" "$2"
}
tamper_profile() {  # flip one byte of signed content
    "${PYTHON}" - "$1" "$2" <<'PY'
import sys
d = open(sys.argv[1], "rb").read()
m = b"PayloadVersion"
i = d.find(m)
assert i >= 0, "marker not found in signed profile"
open(sys.argv[2], "wb").write(d[:i] + b"PayloadVersioN" + d[i + len(m):])
PY
}
verify_profile() {  # CMS signature chains to the root and carries the unsigned bytes
    "${OPENSSL}" smime -verify -binary -inform der -in "$1" -CAfile root/certs/root.cert.pem \
        -purpose any -out "${TMPD}/profile.out" || return 1
    cmp -s "${TMPD}/profile.out" "$2"
}

# ---------------------------------------------------------------- embedded helpers
cat > "${TMPD}/ptyrun.py" <<'PY'
import os
import pty
import select
import sys

pwfile, *cmd = sys.argv[1:]
with open(pwfile) as fh:
    pw = fh.readline().rstrip("\n")
pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)
buf = b""
log = b""
while True:
    ready, _, _ = select.select([fd], [], [], 120)
    if not ready:
        os.kill(pid, 9)
        sys.exit(124)
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    log += data
    buf += data
    while b"Installer password" in buf:
        buf = buf.split(b"Installer password", 1)[1]
        os.write(fd, (pw + "\n").encode())
_, status = os.waitpid(pid, 0)
sys.stdout.write(log.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(status))
PY

cat > "${TMPD}/props.py" <<'PY'
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID as EKU

domain, fqdn = sys.argv[1].lower(), sys.argv[2].lower()
C = {k: x509.load_pem_x509_certificate(open(v, "rb").read())
     for k, v in (a.split("=", 1) for a in sys.argv[3:])}
errs = []


def req(ok, msg):
    if not ok:
        errs.append(msg)


def ext(c, cls):
    try:
        return c.extensions.get_extension_for_class(cls)
    except x509.ExtensionNotFound:
        return None


def span(c):
    nb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before
    na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after
    return nb, na


def eku(name):
    e = ext(C[name], x509.ExtendedKeyUsage)
    return set(e.value) if e else None


def ca(name, plen):
    c = C[name]
    bc, ku = ext(c, x509.BasicConstraints), ext(c, x509.KeyUsage)
    req(bc and bc.critical and bc.value.ca and bc.value.path_length == plen,
        f"{name}: basicConstraints must be critical CA:TRUE, pathlen:{plen}")
    req(ku and ku.critical and ku.value.key_cert_sign and ku.value.crl_sign
        and not ku.value.digital_signature,
        f"{name}: keyUsage must be critical keyCertSign,cRLSign only")
    req(ext(c, x509.SubjectKeyIdentifier) and ext(c, x509.AuthorityKeyIdentifier),
        f"{name}: SKI/AKI missing")
    h = c.signature_hash_algorithm
    req(h is not None and h.name in ("sha384", "sha512"),
        f"{name}: signature digest {h.name if h else None}, want sha384+")


def leaf(name, issuer, want_eku):
    c = C[name]
    nb, na = span(c)
    bc = ext(c, x509.BasicConstraints)
    req(bc and not bc.value.ca, f"{name}: must be CA:FALSE")
    req(eku(name) == want_eku, f"{name}: extendedKeyUsage is {eku(name)}")
    req((na - nb).days <= 825, f"{name}: validity exceeds 825 days")
    req(na < span(C[issuer])[1], f"{name}: outlives its issuer")
    for cls in (x509.SubjectKeyIdentifier, x509.AuthorityKeyIdentifier,
                x509.CRLDistributionPoints, x509.AuthorityInformationAccess):
        req(ext(c, cls), f"{name}: missing {cls.__name__}")


def key_ok(name, rsa_min, curves):
    pk = C[name].public_key()
    good = (isinstance(pk, rsa.RSAPublicKey) and pk.key_size >= rsa_min) or \
           (isinstance(pk, ec.EllipticCurvePublicKey) and pk.curve.name in curves)
    req(good, f"{name}: weak or unexpected public key")


ca("root", 1)
ca("inter", 0)
ca("smime_inter", 0)
req(eku("inter") == {EKU.SERVER_AUTH, EKU.CODE_SIGNING}, "inter: EKU must be serverAuth,codeSigning")
req(eku("smime_inter") == {EKU.EMAIL_PROTECTION}, "smime_inter: EKU must be emailProtection only")
nc = ext(C["inter"], x509.NameConstraints)
req(nc and nc.critical, "inter: nameConstraints must be critical")
if nc:
    perm = [g.value.lower() for g in (nc.value.permitted_subtrees or []) if isinstance(g, x509.DNSName)]
    excl = {str(g.value) for g in (nc.value.excluded_subtrees or []) if isinstance(g, x509.IPAddress)}
    req(perm == [domain], f"inter: permitted DNS {perm}, want [{domain}]")
    req(excl == {"0.0.0.0/0", "::/0"}, f"inter: excluded IP {sorted(excl)}")

leaf("server", "inter", {EKU.SERVER_AUTH})
san = ext(C["server"], x509.SubjectAlternativeName)
req(san and [n.lower() for n in san.value.get_values_for_type(x509.DNSName)] == [fqdn]
    and not san.value.get_values_for_type(x509.IPAddress), "server: SAN must be exactly the FQDN")
ku = ext(C["server"], x509.KeyUsage)
req(ku and ku.critical and ku.value.digital_signature and not ku.value.key_cert_sign,
    "server: keyUsage must be critical digitalSignature")
key_ok("server", 2048, ("secp256r1", "secp384r1"))

leaf("codesign", "inter", {EKU.CODE_SIGNING})
e = ext(C["codesign"], x509.ExtendedKeyUsage)
b = ext(C["codesign"], x509.BasicConstraints)
req(e and e.critical and b and b.critical, "codesign: EKU and basicConstraints must be critical")
key_ok("codesign", 2048, ("secp256r1", "secp384r1"))

for role in ("sig", "enc"):
    leaf(role, "smime_inter", {EKU.EMAIL_PROTECTION})
    s = ext(C[role], x509.SubjectAlternativeName)
    req(s and s.value.get_values_for_type(x509.RFC822Name), f"{role}: SAN rfc822Name missing")
k = ext(C["sig"], x509.KeyUsage).value
req(k.digital_signature and not k.key_encipherment, "sig: keyUsage must be signing only")
k = ext(C["enc"], x509.KeyUsage).value
req(k.key_encipherment and not k.digital_signature, "enc: keyUsage must be keyEncipherment only")
key_ok("sig", 2048, ("secp256r1", "secp384r1"))
key_ok("enc", 3072, ())

for e in errs:
    print(e)
sys.exit(1 if errs else 0)
PY

# ================================================================ build
step "build the PKI"
run_yes "PKI build" bin/clean_everything_and_create_pki.sh --create-pki

step "supersede: intermediate renewal, S/MIME reissue"
run "intermediate renewal" bin/create_intermediate.sh
run "S/MIME reissue" bin/create_organization_smime.sh
run "revocation-test server cert" bin/create_server.sh --server-fqdn "revoketest.${DOMAIN_NAME}"

SRV=$(latest server/certs/"${SERVER_FQDN}".*.cert.pem)
CS=$(latest codesign/certs/codesign.*.cert.pem)
SIG_CUR="smime/certs/${SM}-signature.cert.pem"
ENC_CUR="smime/certs/${SM}-encryption.cert.pem"
SIG_OLD=$(archived_cert "${SM}" signature) || die "no superseded ${SM} signature certificate"
ENC_OLD=$(archived_cert "${SM}" encryption) || die "no superseded ${SM} encryption certificate"
[ -f "${SRV}" ] && [ -f "${CS}" ] || die "server or codesign certificate missing"

# ================================================================ certificates
step "chain, purpose, CRL"
check "root CRL signature"              crl_ok root/crl/root.crl.pem root/certs/root.cert.pem
check "intermediate CRL signature"      crl_ok intermediate/crl/intermediate.crl.pem intermediate/certs/intermediate.cert.pem
check "intermediate_smime CRL signature" crl_ok intermediate_smime/crl/intermediate_smime.crl.pem intermediate_smime/certs/intermediate_smime.cert.pem
check "server: sslserver + hostname"    vfy sslserver "${SRV}" -verify_hostname "${SERVER_FQDN}"
check "codesign chain"                  vfy any "${CS}"
check "S/MIME signature: smimesign"     vfy smimesign "${SIG_CUR}"
check "S/MIME encryption: smimeencrypt" vfy smimeencrypt "${ENC_CUR}"
refuse "TLS chain rejected for S/MIME"  "purpose" vfy smimesign "${SRV}"
refuse "S/MIME chain rejected for TLS"  "purpose" vfy sslserver "${SIG_CUR}"
check "extensions, key sizes, lifetimes" "${PYTHON}" "${TMPD}/props.py" "${DOMAIN_NAME}" "${SERVER_FQDN}" \
    root=root/certs/root.cert.pem inter=intermediate/certs/intermediate.cert.pem \
    smime_inter=intermediate_smime/certs/intermediate_smime.cert.pem \
    server="${SRV}" codesign="${CS}" sig="${SIG_CUR}" enc="${ENC_CUR}"

step "nameConstraints enforcement (certificates forged outside the toolkit)"
forge() {   # forge OUT.pem SUBJECT_CN EXTFILE|-
    local out=$1 cn=$2 ext=$3 args=()
    "${OPENSSL}" req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "${TMPD}/forge.key" -out "${TMPD}/forge.csr" -config server/openssl_server.cnf \
        -subj "/CN=${cn}" -batch || return 1
    if [ "${ext}" = - ]; then args=(-extensions server); else args=(-extfile "${ext}" -extensions x); fi
    SERVER_FQDN="${cn}" "${OPENSSL}" ca -config server/openssl_server.cnf "${args[@]}" \
        -days 30 -notext -md sha256 -in "${TMPD}/forge.csr" -out "${out}" \
        -passin file:intermediate/private/passphrase.txt -batch
}
cat > "${TMPD}/ip.ext" <<'EXT'
[ x ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = IP:10.0.0.1
EXT
run "forge out-of-domain DNS cert" forge "${TMPD}/evil_dns.pem" evil.example.net -
run "forge IP-SAN cert" forge "${TMPD}/evil_ip.pem" ipsan.example.net "${TMPD}/ip.ext"
refuse "out-of-domain DNS SAN rejected" "(permitted|excluded) subtree violation" vfy sslserver "${TMPD}/evil_dns.pem"
refuse "IP SAN rejected"                "(permitted|excluded) subtree violation" vfy sslserver "${TMPD}/evil_ip.pem"

step "issuance guards"
refuse "create_server: FQDN outside DOMAIN_NAME" "not within DOMAIN_NAME" bin/create_server.sh --server-fqdn evil.example.net
refuse "create_smime: overlong EMAIL"            "too long" bin/create_smime.sh "$(printf 'a%.0s' $(seq 1 60))@example.org" toolong
refuse "create_root: early renewal refused"      "more than [0-9]+ days away" bin/create_root.sh

step "revocation"
RV="revoketest.${DOMAIN_NAME}"
RVC=$(latest server/certs/"${RV}".*.cert.pem)
[ -f "${RVC}" ] || die "revocation-test certificate missing"
check  "pre-revocation: verifies"        vfy sslserver "${RVC}"
check  "revoke_certificate keyCompromise" revoke "${RVC}" intermediate keyCompromise
refuse "revoked certificate rejected"    "certificate revoked" vfy sslserver "${RVC}"
check  "intermediate CRL still verifies" crl_ok intermediate/crl/intermediate.crl.pem intermediate/certs/intermediate.cert.pem

step "validator policy (bin/pki_validate.py)"
check  "current signature accepted"                      pkival signature  "${SIG_CUR}"
check  "current encryption accepted"                     pkival encryption "${ENC_CUR}"
refuse "superseded signature rejected"                   "superseded"        pkival signature  "${SIG_OLD}"
refuse "superseded encryption needs opt-in"              "allow_superseded"  pkival encryption "${ENC_OLD}"
check  "superseded encryption accepted with opt-in"      pkival encryption "${ENC_OLD}" --allow-superseded
refuse "encryption cert refused in signature role"       "keyUsage"          pkival signature  "${ENC_CUR}"
refuse "signature cert refused in encryption role"       "keyUsage"          pkival encryption "${SIG_CUR}"
refuse "S/MIME cert refused in codesign role"            "ExtendedKeyUsage"  pkival codesign   "${SIG_CUR}"

# ================================================================ installers
step "credential installers"
run "CA/S-MIME installers" bin/create_organization_credentials.sh
run "installer with old encryption certs" bin/create_credentials.sh 'persona_{gmail,comcast}_*' 'personb_*_2026' \
    --allow-expired-encryption --allow-superseded-encryption
INST_CA=mdm-private/credentials/install_credentials_cacerts.sh
INST=mdm-private/credentials/install_credentials_persona_LBgmailCcomcastRB_S_personb_S_2026.sh
[ -f "${INST_CA}" ] && [ -f "${INST}" ] && [ -f "${INST}.pass" ] || die "installer outputs missing"

refuse "create_credentials: unmatched glob"    "matches no S/MIME" bin/create_credentials.sh 'nosuch_*'
refuse "create_credentials: shell metachars"   "invalid .NAME_GLOB" bin/create_credentials.sh '$(id)'

check  "CA installer: signature"               "${INST_CA}" --check-signature-integrity
check  "S/MIME installer: signature (pty)"     ptyrun "${INST}.pass" "${INST}" --check-signature-integrity
tamper_header  "${INST_CA}" "${TMPD}/t_ca.sh"
tamper_payload "${INST_CA}" "${TMPD}/p_ca.sh"
tamper_header  "${INST}"    "${TMPD}/t_in.sh"
refuse "CA installer: tampered header rejected"   "SIGNATURE CHECK FAILED" "${TMPD}/t_ca.sh" --check-signature-integrity
fails  "CA installer: tampered payload rejected"  "${TMPD}/p_ca.sh" --check-signature-integrity
refuse "S/MIME installer: tampered header rejected" "SIGNATURE CHECK FAILED" ptyrun "${INST}.pass" "${TMPD}/t_in.sh" --check-signature-integrity
printf 'wrong-password\n' > "${TMPD}/badpw"
fails  "S/MIME installer: wrong password rejected" ptyrun "${TMPD}/badpw" "${INST}" --check-signature-integrity

payload_has_no_secrets() {
    local listing
    ( cd "${TMPD}" && rm -f credentials_cacerts.txz && "${PKI_ROOT}/${INST_CA}" --tar-only ) || return 1
    listing=$(tar -tJf "${TMPD}/credentials_cacerts.txz") || return 1
    ! grep -Eqi '\.(p12|pass|key|pem)( |$)' <<<"${listing}" && grep -q '\.cer$' <<<"${listing}"
}
check "CA installer payload: certificates only" payload_has_no_secrets
embeds_password() { grep -qFf <(sed -n 1p "${INST}.pass") "${INST}"; }
fails "installer script does not embed its password" embeds_password

# ================================================================ KeePassXC (keyfile, no password)
step "KeePassXC"
DB="${TMPD}/passwords.kdbx"
KEYFILE="${TMPD}/kdbx.key"
"${OPENSSL}" rand -hex 32 | tr -d '\n' > "${KEYFILE}"
run "keepass db-create" "${KPCLI}" db-create --set-key-file "${KEYFILE}" "${DB}"
kpentry() { bin/create_keepass_entry.sh --db "${DB}" --key-file "${KEYFILE}" --no-password --title "pki_test installer" "$@" "${INST}"; }
kp_password_matches() {
    local got want
    got=$("${KPCLI}" show -s -a Password -k "${KEYFILE}" --no-password "${DB}" "pki_test installer") || return 1
    want=$(sed -n 1p "${INST}.pass")
    [ "${got}" = "${want}" ]
}
check "keepass: installer-password entry"        kpentry
check "keepass: entry holds the installer password" kp_password_matches
check "keepass: re-run is idempotent"            kpentry
check "keepass: per-issuance .p12 passwords"     kpentry --individual-smime-passwords
check "keepass: xml export"                      bin/create_keepass_entry.sh --xml-out "${TMPD}/entry.xml" \
    --individual-smime-passwords "${INST}"
check "keepass: xml well-formed, secrets protected" grep -q 'ProtectInMemory="True"' "${TMPD}/entry.xml"
refuse "keepass: CA-only installer rejected"     "not encrypted" bin/create_keepass_entry.sh --db "${DB}" \
    --key-file "${KEYFILE}" --no-password "${INST_CA}"

# ================================================================ MDM profiles
step "MDM profiles"
run "MDM profiles" bin/create_organization_mdm.sh
for p in myorganization-trust myorganization-settings persona-settings; do
    U="mdm-private/mobfileconfigs-unsigned/${p}.mobileconfig"
    S="mdm-private/mobfileconfigs-signed/${p}.mobileconfig"
    check "${p}: written"                       test -s "${U}" -a -s "${S}"
    check "${p}: signature chains to root, content intact" verify_profile "${S}" "${U}"
    tamper_profile "${S}" "${TMPD}/${p}.tampered" || die "tamper_profile failed"
    fails "${p}: tampered profile rejected"     "${OPENSSL}" smime -verify -binary -inform der \
        -in "${TMPD}/${p}.tampered" -CAfile root/certs/root.cert.pem -purpose any -out /dev/null
done
trust_profile_ok() {
    "${PYTHON}" - mdm-private/mobfileconfigs-unsigned/myorganization-trust.mobileconfig root/certs/root.cert.pem <<'PY'
import hashlib
import plistlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

prof = plistlib.load(open(sys.argv[1], "rb"))
root = x509.load_pem_x509_certificate(open(sys.argv[2], "rb").read())
types = [p["PayloadType"] for p in prof["PayloadContent"]]
assert "com.apple.security.pkcs12" not in types, "private keys in the trust profile"
fps = {hashlib.sha256(p["PayloadContent"]).hexdigest()
       for p in prof["PayloadContent"] if p["PayloadType"] == "com.apple.security.root"}
assert root.fingerprint(hashes.SHA256()).hex() in fps, "root certificate not in the trust profile"
assert len(prof["PayloadUUID"]) == 36
PY
}
check "trust profile: root present, CA certificates only" trust_profile_ok

# ================================================================ permissions
step "permissions"
perm_audit() {
    local out
    out=$( {
        find root intermediate intermediate_smime server codesign smime privoxy -type d -name private ! -perm 700
        find root intermediate intermediate_smime server codesign smime privoxy -path '*/private/*' -type f ! -perm 600
        find mdm-private -type d ! -perm 700
        find mdm-private -type f ! -perm 600 ! -name 'install_credentials_*.sh' ! -name '*.sample'
    } 2>/dev/null ) || true
    if [ -n "${out}" ]; then printf '%s\n' "${out}"; return 1; fi
}
check "private dirs 0700, key/secret files 0600" perm_audit
check "installer 0750"        mode_is "${INST}" 750
check "installer .pass 0600"  mode_is "${INST}.pass" 600

# ================================================================ summary
printf '\n%d passed, %d failed\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]

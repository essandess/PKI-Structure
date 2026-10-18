#!/usr/bin/env bash

# pki_test.sh -- end-to-end and negative tests for the PKI toolkit.
# DESTRUCTIVE: rebuilds the PKI in this tree. Runs only in a disposable tree
# (marker .pki_test_tree) or with PKI_TEST_DESTROY_PKI=1.
# PKI_TEST_VERIFY_FLAGS overrides the openssl-verify strictness flags
# (default -x509_strict); PKI_TEST_SMIME_NAME selects the S/MIME identity.

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
      PKI_STRUCTURE_SRC PKI_SITE_DIR \
      PKI_SITE_GROUP PKI_ROOT_SHA256 PKI_ROOT_CRL PKI_INTERMEDIATE_CRL \
      PKI_CODESIGN_DIR PKI_CODESIGN_NAME PKI_CODESIGN_SHA1 CERTSHA1 \
      PKI_KEYCHAIN_DIR PKI_KEYCHAIN_ITEM PKI_KEYCHAIN_FILE PKI_KEYCHAIN_KEYFILE
export CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY=1 PKI_ASSUME_YES=1 SHOW_CERT_TEXT=0 SHOW_CRL_TEXT=0

# ---------------------------------------------------------------- guard
MARKER_FILE=.pki_test_tree
if [ ! -e "${MARKER_FILE}" ]; then
    LIVE=$(find root intermediate intermediate_smime server codesign smime privoxy keepassxc \
                -maxdepth 2 \( -name '*.key.pem' -o -name index.txt -o -name '*.kdbx' -o -name '*.keyx' -o -name '*.pass' \) 2>/dev/null \
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

# the master password goes into a throwaway keychain, never the real one
command -v security >/dev/null 2>&1 || die "macOS security(1) required."
export PKI_KEYCHAIN_FILE="${TMPD}/pki_test.keychain-db"
# the database and key file are useless once this master is gone: keep them out of the tree
export PKI_KEYCHAIN_DIR="${TMPD}/keychain" PKI_KEYCHAIN_KEYFILE="${TMPD}/keyfile/pki-structure.keyx"
security create-keychain -p pki_test "${PKI_KEYCHAIN_FILE}" >/dev/null
security set-keychain-settings "${PKI_KEYCHAIN_FILE}"
security unlock-keychain -p pki_test "${PKI_KEYCHAIN_FILE}"

VERIFY_FLAGS="${PKI_TEST_VERIFY_FLAGS--x509_strict}"
SM="${PKI_TEST_SMIME_NAME:-persona_gmail_2026}"

# ---------------------------------------------------------------- seed deployment files
mkdir -p mdm/yaml
# build with the default chain, not this deployment's
rm -f bin/create_organization_pki.sh
for f in smime mdm credentials; do
    [ -f "bin/create_organization_${f}.sh" ] \
        || cp -p "bin/create_organization_${f}.sh.sample" "bin/create_organization_${f}.sh"
    chmod 0750 "bin/create_organization_${f}.sh"
done
for yml in myorganization-trust myorganization-settings persona-settings ios-restrictions-baseline; do
    if [ ! -e "mdm/yaml/${yml}.yaml" ]; then
        cp "mdm/yaml/${yml}.yaml.sample" "mdm/yaml/${yml}.yaml"
    fi
    chmod 0600 "mdm/yaml/${yml}.yaml"
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
verify_signed() {   # CMS signature chains to the root; content to $2
    "${OPENSSL}" smime -verify -binary -inform der -in "$1" -CAfile root/certs/root.cert.pem \
        -purpose any -out "$2"
}

# ---------------------------------------------------------------- embedded helpers
cat > "${TMPD}/ptyrun.py" <<'PY'
import os
import pty
import re
import select
import sys

pwfile, *cmd = sys.argv[1:]
with open(pwfile) as fh:
    pw = fh.readline().rstrip("\n")
s1 = os.environ.get("PTY_SECRET", "")
s2 = os.environ.get("PTY_SECRET_AGAIN", s1)
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
    while True:
        m = re.search(rb"Secret [^\n]*?: ", buf)
        if not m:
            break
        buf = buf[m.end():]
        ans = s2 if b"(again)" in m.group(0) else s1
        os.write(fd, (ans + "\n").encode())
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
run "revocation-test server cert" bin/create_server.sh --decrypt-key --server-fqdn "revoketest.${DOMAIN_NAME}"

SRV=$(latest server/certs/"${SERVER_FQDN}".*.cert.pem)
CS=$(latest codesign/certs/codesign.*.cert.pem)
SIG_CUR="smime/certs/${SM}-signature.cert.pem"
ENC_CUR="smime/certs/${SM}-encryption.cert.pem"
SIG_OLD=$(archived_cert "${SM}" signature) || die "no superseded ${SM} signature certificate"
ENC_OLD=$(archived_cert "${SM}" encryption) || die "no superseded ${SM} encryption certificate"
[ -f "${SRV}" ] && [ -f "${CS}" ] || die "server or codesign certificate missing"

# ================================================================ key passphrases
step "key passphrases"
KC() { "${PYTHON}" bin/pki_keychain.py "$@"; }
no_secret_files() {
    [ -z "$(find . -path ./mdm -prune -o \( -name passphrase.txt -o -name '*.p12.pass' \) -print | sed -n 1p)" ]
}
p12_opens() { "${OPENSSL}" pkcs12 -legacy -noout -in "$1" -passin fd:3 3< <(KC get --cert "$2" --field p12); }
p12_shared() { [ "$(KC get --cert "$1" --field p12)" = "$(KC get --cert "$2" --field p12)" ]; }
check "no passphrase files in the tree"             no_secret_files
check "S/MIME .p12 opens with its keychain password" p12_opens "smime/private/${SM}-signature.p12" "smime/certs/${SM}-signature.cert.pem"
check "signature and encryption .p12 share a password" p12_shared "smime/certs/${SM}-signature.cert.pem" "smime/certs/${SM}-encryption.cert.pem"
run "stray certificate" "${OPENSSL}" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj /CN=stray -keyout "${TMPD}/stray.key" -out "${TMPD}/stray.pem"
refuse "unknown key has no entry" "no keychain entry" KC get --cert "${TMPD}/stray.pem"

SERVICE="com.github.essandess.pki-structure.keepassxc-passphrase"
master_pw()      { security find-generic-password -s "${SERVICE}" -w "${PKI_KEYCHAIN_FILE}"; }
no_keyfile()     { master_pw | "${KPCLI}" ls -q "${PKI_KEYCHAIN_DIR}/pki-structure.kdbx"; }
restore_master() { printf '%s\n' "${MASTER}" | KC import-master; }
init_keeps()     { KC init && [ "$(master_pw)" = "${MASTER}" ]; }
reap_test() {   # a failed issuance leaves no entry once init has run
    local k="${TMPD}/reap.key.pem" id
    id=$(KC genkey --alg EC --out "${k}" --label reap) || return 1
    rm -f "${k}"
    KC init
    ! KC get --id "${id}"
}
installer_roundtrip() {
    printf 'pw-%s\n' "$$" | KC installer-set --name test_installer.sh &&
    [ "$(KC installer-get --name test_installer.sh)" = "pw-$$" ] &&
    printf 'pw2\n' | KC installer-set --name test_installer.sh &&
    [ "$(KC installer-get --name test_installer.sh)" = pw2 ]
}
kdf_rounds_ok() {   # header of the KDBX4 file: Argon2 passes, memory, lanes
    "${PYTHON}" - "${PKI_KEYCHAIN_DIR}/pki-structure.kdbx" <<'PY'
import struct
import sys

d = open(sys.argv[1], "rb").read(1 << 16)
assert d[:8] == bytes.fromhex("03d9a29a67fb4bb5"), "not a KDBX file"
assert struct.unpack_from("<H", d, 10)[0] == 4, "not KDBX4"
pos = 12
while True:
    i, size = d[pos], struct.unpack_from("<I", d, pos + 1)[0]
    pos += 5
    val, pos = d[pos:pos + size], pos + size
    if i == 0:
        sys.exit("no KDF parameters")
    if i == 11:
        break
p, o = {}, 2
while val[o]:
    n = struct.unpack_from("<I", val, o + 1)[0]
    name, o = val[o + 5:o + 5 + n].decode(), o + 5 + n
    n = struct.unpack_from("<I", val, o)[0]
    p[name], o = val[o + 4:o + 4 + n], o + 4 + n
rounds = struct.unpack("<Q", p["I"])[0]
mem = struct.unpack("<Q", p["M"])[0] >> 20
lanes = struct.unpack("<I", p["P"])[0]
assert rounds >= 16 and mem >= 64 and lanes == 4, f"{rounds} rounds, {mem} MiB, {lanes} lanes"
PY
}
help_fits() { COLUMNS=80 "${PYTHON}" bin/pki_keychain.py --help | awk 'length($0) > 80 { bad = 1 } END { exit bad }'; }
MASTER=$(master_pw)
check  "database is KDBX4, Argon2, >= 64 MiB, 4 lanes" KC kdf-check
check  "database KDF: >= 16 rounds, >= 64 MiB, 4 lanes" kdf_rounds_ok
check  "pki_keychain.py --help fits 80 columns"       help_fits
check  "master item exists, is readable, opens the database" KC verify
fails  "database does not open without the key file"  no_keyfile
check  "init keeps an existing master item"           init_keeps
run    "drop master item"                             security delete-generic-password -s "${SERVICE}" "${PKI_KEYCHAIN_FILE}"
refuse "init refuses a new master next to a database" "master item" KC init
fails  "master item not recreated"                    master_pw
refuse "verify reports the missing master item"       "master item" KC verify
check  "import-master restores it"                    restore_master
check  "restored master matches"                      test "$(master_pw)" = "${MASTER}"
run    "swap in a wrong master"                       bash -c 'security delete-generic-password -s "$1" "$3" >/dev/null && security add-generic-password -s "$1" -a pki_test -w "$2" "$3"' _ "${SERVICE}" wrong-password "${PKI_KEYCHAIN_FILE}"
refuse "verify rejects a master that does not open"   "does not open" KC verify
run    "drop the wrong master"                        security delete-generic-password -s "${SERVICE}" "${PKI_KEYCHAIN_FILE}"
check  "right master restored"                        restore_master
check  "installer password: store, replace, retrieve" installer_roundtrip
refuse "installer password: unknown name"             "no installer entry" KC installer-get --name nosuch.sh
check  "init reaps a failed issuance" reap_test

# file-backed master (root's layout), own database and key file
MF="${TMPD}/mf/master/pki-structure.pass"
mf_kc() { PKI_KEYCHAIN_MASTER="${MF}" PKI_KEYCHAIN_DIR="${TMPD}/mf/keychain" \
    PKI_KEYCHAIN_KEYFILE="${TMPD}/mf/keyfile/pki-structure.keyx" \
    "${PYTHON}" bin/pki_keychain.py "$@"; }
mf_init()   { mf_kc init && mode_is "${MF}" 600 && mf_kc verify; }
mf_export() { [ "$(mf_kc export-master)" = "$(sed -n 1p "${MF}")" ]; }
mf_import() { printf 'x\n' | mf_kc import-master; }
mf_loose()  { chmod 0644 "${MF}"; mf_kc verify; }
check  "master file: init makes a 0600 file that opens the database" mf_init
check  "master file: export-master matches the file" mf_export
refuse "master file: import refuses to replace"      "already exists" mf_import
refuse "master file: loose mode refused"             "mode 0600" mf_loose

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
        -passin fd:3 3< <("${PYTHON}" bin/pki_keychain.py get --cert intermediate/certs/intermediate.cert.pem) -batch
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

run "plus-addressed S/MIME" bin/create_smime.sh "a+b@${DOMAIN_NAME}" plustest
check "plus-addressed S/MIME: signature" vfy smimesign smime/certs/plustest-signature.cert.pem
check "plus-addressed S/MIME: encryption" vfy smimeencrypt smime/certs/plustest-encryption.cert.pem

step "revocation"
RV="revoketest.${DOMAIN_NAME}"
RVC=$(latest server/certs/"${RV}".*.cert.pem)
[ -f "${RVC}" ] || die "revocation-test certificate missing"
check  "pre-revocation: verifies"        vfy sslserver "${RVC}"
decrypted_of() { local b=${1##*/}; printf 'server/private/%s.key.pem.decrypted' "${b%.cert.pem}"; }
key_matches()  { [ "$("${OPENSSL}" pkey -in "$1" -pubout)" = "$("${OPENSSL}" x509 -in "$2" -noout -pubkey)" ]; }
no_adblock_decrypted() { ! ls privoxy/adblock2privoxy/private/*.decrypted >/dev/null 2>&1; }
adblock_decrypted_ok() {
    local k c
    k=$(latest privoxy/adblock2privoxy/private/adblock2privoxy-nginx.*.key.pem.decrypted)
    c=$(latest privoxy/adblock2privoxy/certs/adblock2privoxy-nginx.*.cert.pem)
    [ -f "${k}" ] && mode_is "${k}" 600 && key_matches "${k}" "${c}"
}
check  "create_server --decrypt-key: file is 0600"              mode_is "$(decrypted_of "${RVC}")" 600
check  "create_server --decrypt-key: key matches the certificate" key_matches "$(decrypted_of "${RVC}")" "${RVC}"
fails  "create_server: no decrypted key by default"             test -e "$(decrypted_of "${SRV}")"
check  "create_adblock2privoxy: no decrypted key by default"    no_adblock_decrypted
run    "adblock2privoxy with --decrypt-key"                     bin/create_adblock2privoxy.sh --decrypt-key
check  "create_adblock2privoxy --decrypt-key: 0600, matches"    adblock_decrypted_ok
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
INST_CA=mdm/credentials/install_credentials_cacerts.sh
INST=mdm/credentials/install_credentials_persona_LBgmailCcomcastRB_S_personb_S_2026.sh
[ -f "${INST_CA}" ] && [ -f "${INST}" ] || die "installer outputs missing"
INST_PW_FILE="${TMPD}/installer.pw"
KC installer-get --name "${INST##*/}" > "${INST_PW_FILE}" || die "no installer password in the PKI keychain"

refuse "create_credentials: unmatched glob"    "matches no S/MIME" bin/create_credentials.sh 'nosuch_*'
refuse "create_credentials: shell metachars"   "invalid .NAME_GLOB" bin/create_credentials.sh '$(id)'

check  "CA installer: signature"               "${INST_CA}" --check-signature-integrity
check  "S/MIME installer: signature (pty)"     ptyrun "${INST_PW_FILE}" "${INST}" --check-signature-integrity
tamper_header  "${INST_CA}" "${TMPD}/t_ca.sh"
tamper_payload "${INST_CA}" "${TMPD}/p_ca.sh"
tamper_header  "${INST}"    "${TMPD}/t_in.sh"
refuse "CA installer: tampered header rejected"   "SIGNATURE CHECK FAILED" "${TMPD}/t_ca.sh" --check-signature-integrity
fails  "CA installer: tampered payload rejected"  "${TMPD}/p_ca.sh" --check-signature-integrity
refuse "S/MIME installer: tampered header rejected" "SIGNATURE CHECK FAILED" ptyrun "${INST_PW_FILE}" "${TMPD}/t_in.sh" --check-signature-integrity
check  "S/MIME installer: signature check needs no password" "${INST}" --check-signature-integrity

check  "verify_installer.sh: root file" bin/verify_installer.sh "${INST_CA}" --root root/certs/root.cert.pem
check  "verify_installer.sh: root pin"  bin/verify_installer.sh "${INST}" --root-sha256 "$(cert_fp root/certs/root.cert.pem)"
refuse "verify_installer.sh: tampered header" "SIGNATURE CHECK FAILED" bin/verify_installer.sh "${TMPD}/t_ca.sh" --root root/certs/root.cert.pem
payload_has_no_secrets() {
    local listing
    ( cd "${TMPD}" && rm -f credentials_cacerts.txz && "${PKI_ROOT}/${INST_CA}" --tar-only ) || return 1
    listing=$(tar -tJf "${TMPD}/credentials_cacerts.txz") || return 1
    ! grep -Eqi '\.(p12|pass|key|pem)( |$)' <<<"${listing}" && grep -q '\.cer$' <<<"${listing}"
}
check "CA installer payload: certificates only" payload_has_no_secrets
embeds_password() { grep -qFf "${INST_PW_FILE}" "${INST}"; }
fails "installer script does not embed its password" embeds_password

# ================================================================ KeePassXC (keyfile, no password)
step "KeePassXC"
DB="${TMPD}/passwords.kdbx"
KEYFILE="${TMPD}/kdbx.key"
"${PYTHON}" -c 'import sys; sys.path.insert(0, "bin"); import pki_keychain as k; k.write_keyfile(k.Path(sys.argv[1]))' "${KEYFILE}"
run "keepass db-create" "${KPCLI}" db-create --set-key-file "${KEYFILE}" "${DB}"
kpentry() { bin/create_keepass_entry.sh --db "${DB}" --key-file "${KEYFILE}" --no-password --title "pki_test installer" "$@" "${INST}"; }
kp_password_matches() {
    local got want
    got=$("${KPCLI}" show -s -a Password -k "${KEYFILE}" --no-password "${DB}" "pki_test installer") || return 1
    want=$(sed -n 1p "${INST_PW_FILE}")
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

KP_MASTER_TITLE="PKI-Structure KeePassXC Passphrase"
kpmaster() { bin/create_keepass_entry.sh --db "${DB}" --key-file "${KEYFILE}" --no-password --export-master; }
kp_master_matches() {
    local got
    got=$("${KPCLI}" show -s -a Password -k "${KEYFILE}" --no-password "${DB}" "${KP_MASTER_TITLE}") || return 1
    [ "${got}" = "$(master_pw)" ]
}
kp_master_in_passwords() {   # the entry sits in the root group, Passwords
    "${KPCLI}" ls -k "${KEYFILE}" --no-password "${DB}" | grep -qxF "${KP_MASTER_TITLE}"
}
check "keepass: --export-master without an installer"  kpmaster
check "keepass: the entry holds the master password"    kp_master_matches
check "keepass: the entry is in the group Passwords"    kp_master_in_passwords
check "keepass: --export-master re-run is idempotent"   kpmaster

# ================================================================ MDM profiles
step "MDM profiles"
export PTY_SECRET="pki-test-secret-0042"
run "MDM profiles" ptyrun "${INST_PW_FILE}" bin/create_organization_mdm.sh
no_profile_on_disk() { [ -z "$(find mdm -name '*.mobileconfig' | sed -n 1p)" ]; }
no_secret_in_tree() {
    [ -z "$(grep -rlaF --exclude-dir=.git --exclude=pki_test.sh -- "${PTY_SECRET}" . 2>/dev/null | sed -n 1p)" ]
}
for p in myorganization-trust myorganization-settings persona-settings; do
    S="${TMPD}/${p}.mobileconfig"
    run "${p}: extract from the keychain" KC profile-get --name "${p}" --out "${S}"
    run "${p}: extract unsigned" KC profile-get --name "${p}" --unsigned --out "${TMPD}/${p}.unsigned"
    check "${p}: signature chains to root" verify_signed "${S}" "${TMPD}/${p}.content"
    check "${p}: --unsigned is the signed content" cmp -s "${TMPD}/${p}.content" "${TMPD}/${p}.unsigned"
    tamper_profile "${S}" "${TMPD}/${p}.tampered" || die "tamper_profile failed"
    fails "${p}: tampered profile rejected" "${OPENSSL}" smime -verify -binary -inform der \
        -in "${TMPD}/${p}.tampered" -CAfile root/certs/root.cert.pem -purpose any -out /dev/null
done
for p in myorganization-settings persona-settings; do
    check "${p}: holds the prompted secret" grep -aqF -- "${PTY_SECRET}" "${TMPD}/${p}.unsigned"
done
check "no profile written to mdm/" no_profile_on_disk
check "no prompted secret on disk in the tree" no_secret_in_tree
refuse "profile-get refuses an existing file" "exists" KC profile-get --name persona-settings \
    --out "${TMPD}/persona-settings.mobileconfig"
refuse "mismatched secret entries rejected" "no matching entries" \
    env PTY_SECRET=one PTY_SECRET_AGAIN=two "${PYTHON}" "${TMPD}/ptyrun.py" "${INST_PW_FILE}" \
    "${PYTHON}" bin/configurate_yaml.py mdm/yaml/persona-settings.yaml
printf 'name: t\ndescription: t\npayloads:\n  - id: w\n    type: wifi\n    settings:\n      Password: literal\n' \
    > mdm/yaml/literal-test.yaml
refuse "literal secret in YAML rejected" "literal secret" \
    "${PYTHON}" bin/configurate_yaml.py mdm/yaml/literal-test.yaml
rm -f mdm/yaml/literal-test.yaml
trust_profile_ok() {
    "${PYTHON}" - "${TMPD}/myorganization-trust.unsigned" root/certs/root.cert.pem <<'PY'
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

kp_profile() { bin/create_keepass_entry.sh --db "${DB}" --key-file "${KEYFILE}" --no-password persona-settings; }
kp_trust_attached() {   # exported to a file, not --stdout
    "${KPCLI}" attachment-export -k "${KEYFILE}" --no-password "${DB}" \
        "MDM/MDM profile: persona-settings" myorganization-trust.mobileconfig \
        "${TMPD}/attached.trust" \
        && cmp -s "${TMPD}/attached.trust" "${TMPD}/myorganization-trust.mobileconfig"
}
nosign_roundtrip() {
    KC profile-get --name myorganization-trust --out "${TMPD}/nosign.out" \
        && cmp -s "${TMPD}/nosign.out" "${TMPD}/myorganization-trust.unsigned"
}
check "keepass: profile entry with its trust profile" kp_profile
check "keepass: the trust profile is attached"        kp_trust_attached
check "keepass: profile re-run is idempotent"         kp_profile
run   "trust profile built with --no-sign" "${PYTHON}" bin/configurate_yaml.py mdm/yaml/myorganization-trust.yaml --no-sign
check "--no-sign stores the unsigned plist"           nosign_roundtrip
run   "signed trust profile restored" "${PYTHON}" bin/configurate_yaml.py mdm/yaml/myorganization-trust.yaml

# ================================================================ permissions
step "permissions"
perm_audit() {
    local out
    out=$( {
        find root intermediate intermediate_smime server codesign smime privoxy -type d -name private ! -perm 700
        find root intermediate intermediate_smime server codesign smime privoxy -path '*/private/*' -type f ! -perm 600
        find "${PKI_KEYCHAIN_DIR}" -type d ! -perm 700
        find "${PKI_KEYCHAIN_DIR}" -type f ! -perm 600
        find "${PKI_KEYCHAIN_KEYFILE%/*}" -type d ! -perm 700
        find "${PKI_KEYCHAIN_KEYFILE%/*}" -type f ! -perm 600
        find mdm -type d ! -perm 700
        find mdm -type f ! -perm 600 ! -name 'install_credentials_*.sh' ! -name '*.sample'
    } 2>/dev/null ) || true
    if [ -n "${out}" ]; then printf '%s\n' "${out}"; return 1; fi
}
check "private dirs 0700, key/secret files 0600" perm_audit
check "installer 0750"        mode_is "${INST}" 750

# ================================================================ summary
printf '\n%d passed, %d failed\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]

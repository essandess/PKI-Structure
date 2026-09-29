# PKI Structure

This set of shell scripts and `openssl` configuration files creates
a PKI structure for common applications that include a certificate
authority, intermediate certificate authority, server certificates,
S/MIME certificates, code signing certificates, and `https` inspection
certificates for `privoxy` and `adblock2privoxy`. A Python tool builds
and signs iOS trust profiles (`.mobileconfig`) from the PKI's
certificates; see [MDM configuration profiles](#mdm-configuration-profiles).

The products of the scripts are X509 certificates and keys in CER, PEM,
and PKCS12 formats, and signed `.mobileconfig` profiles. All keys are
passphrase protected.

## Requirements

* `bash` 4.4 or later (`inherit_errexit`). macOS `/bin/bash` is 3.2; use a
  MacPorts or Homebrew `bash`.
* OpenSSL 3 (`pkcs12 -legacy`).
* `rsync` (deployment only).
* `sf-pwgen` (optional; passphrases fall back to `openssl rand`).
* Python 3.9 or later with `PyYAML` and `cryptography` 39 or later, as
  `python3` in `PATH` (MDM profiles only).

## Deploying to a new directory

To set up a new PKI deployment from this repository:
```sh
bin/replicate_pki_structure.sh [DEST]
```
`DEST` defaults to the current directory. `PKI_STRUCTURE_SRC` (trailing
`/` required) overrides the source, which defaults to this repository.
Copied: `.sh`, `.py`, `.cnf`, `.md`, and `LICENSE` files.
Never copied: `.git/`, `*.env`, `bin/create_organization_smime_pki.sh`
(this deployment's cert-issuance list), and `mdm-private/`.

Seeded when absent at `DEST`, from `<file>.sample` or from the source file
if no sample exists. Existing files are never modified:

- `pki_identity.env`
- `bin/create_organization_smime_pki.sh`
- `mdm-private/yaml/myorganization-trust.yaml`

Edit `pki_identity.env` with the deployment's organization, domain
(`DOMAIN_NAME`), and PKI hostname before running any `create_*.sh` script.

`mdm-private/` is permission-audited in both source and destination; see
[Permissions](#permissions).

To clean and create the entire PKI structure:
```sh
bin/clean_everything_and_create_pki.sh
```

## Layout

```
pki_identity.env                       organization and hostname settings
openssl.cnf                        root CA configuration
common_policy.cnf                  shared CA policies
bin/                               scripts
root/                              root CA
intermediate/                      intermediate CA
server/                            TLS server certificates
codesign/                          code signing certificates
smime/                             S/MIME certificates
privoxy/                           privoxy CA (separate trust anchor)
privoxy/adblock2privoxy/           adblock2privoxy server certificates
```

Each directory contains:

```
certs/      *.cert.pem  *.chain.pem  *.cer (DER)
private/    *.key.pem  *.p12  passphrase.txt   (mode 0700)
crl/        <ca>.crl.pem  <ca>.crl (DER)       (CAs only)
newcerts/   <serial>.pem                       (CAs only)
index.txt   serial  crlnumber                  (CAs only)
```

`newcerts/` and `index.txt` are the CA's record of issued certificates.
Revocation reads them. Do not delete them.

Per-directory configuration:

| Directory | Configuration | Extension section |
|---|---|---|
| `root/` | `openssl.cnf` | `v3_ca` |
| `intermediate/` | `intermediate/openssl_intermediate.cnf` | `v3_intermediate_ca` |
| `server/` | `server/openssl_server.cnf` | `server_cert` |
| `codesign/` | `codesign/openssl_codesign.cnf` | `codesign_reqext` |
| `smime/` | `smime/openssl_smime.cnf` | `smime_signature`, `smime_encryption` |
| `privoxy/` | `privoxy/openssl_privoxy.cnf` | `v3_ca` |
| `privoxy/adblock2privoxy/` | `privoxy/adblock2privoxy/openssl_adblock2privoxy.cnf` | `server_cert` |

## Configuration

### pki_identity.env

| Variable | Use |
|---|---|
| `ORG_COUNTRY`, `ORG_STATE`, `ORG_LOCALITY`, `ORG_NAME`, `ORG_EMAIL` | Subject fields |
| `DOMAIN_NAME` | Organization domain |
| `SERVER_FQDN` | Server certificate CN and SAN |
| `PKI_FQDN` | Host serving CRLs and CA certificates; embedded in issued certificates |
| `SUBJECTALTNAME_ADBLOCK2PRIVOXY` | adblock2privoxy SAN |

`PKI_FQDN` is embedded in every certificate at issuance. Changing it does not
alter certificates already issued.

### Environment variables

| Variable | Default | Use |
|---|---|---|
| `CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY` | unset | Must be `1` to run any `create_*.sh` |
| `PKI_ASSUME_YES` | `0` | `1` skips `[y/N]` confirmations (supersession and `-c`/`-vc`) |
| `ALGORITHM` | `EC` | `EC` or `RSA`; same as `-a` |
| `EC_PARAMGEN_CURVE` | per script | `P-256`, `P-384`, `P-521` |
| `RSA_KEYGEN_BITS` | per script | `2048`, `3072`, `4096` |
| `HASH_DIGEST` | matched to key size | Signature digest |
| `SHOW_CERT_TEXT` | `1` | `0` suppresses certificate text output |

## Passphrases

`<dir>/private/passphrase.txt` is created on first use, mode 0600, with two
independent passphrases:

* Line 1: protects the private key.
* Line 2: PKCS#12 (`.p12`) export password.

See `man openssl-passphrase-options`. Read line 2 for `.p12` imports:
```sh
sed -n 2p smime/private/passphrase.txt
```

## Create certificates

```sh
export CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY=1
```

Create in dependency order: root, intermediate, then leaf certificates.
Create `privoxy` before `adblock2privoxy`.

### Common options

| Option | Effect |
|---|---|
| `-a`, `--algorithm EC\|RSA` | Key algorithm |
| `-c`, `--clean` | Delete keys, certificates, and CA database in the directory (prompts) |
| `-vc`, `--veryclean` | As `-c`, and delete `passphrase.txt` (prompts) |
| `-h`, `--help` | Usage |

`-c` and `-vc` on a CA directory delete `index.txt`, `newcerts/`, and CRLs.
Certificates it issued can no longer be revoked. Not reversible.

### Summary

| Script | Issuer | Default key | Validity |
|---|---|---|---|
| `create_root.sh` | self-signed | EC P-384, SHA-384 | 4383 days |
| `create_intermediate.sh` | root | EC P-384, SHA-384 | 2191 days |
| `create_server.sh` | intermediate | EC P-256, SHA-256 | 825 days |
| `create_codesign.sh` | intermediate | EC P-256, SHA-256 | 2191 days |
| `create_smime.sh` | intermediate | signature EC P-256; encryption RSA 3072 | 1126 days |
| `create_privoxy.sh` | self-signed | EC P-256, SHA-256 | 4383 days |
| `create_adblock2privoxy.sh` | privoxy | EC P-256, SHA-256 | 825 days |

### Root CA

```sh
bin/create_root.sh [-a EC|RSA]
```

Self-signed, `pathlen:1`. Creates `root/certs/root.cert.pem`,
`root/certs/root.cer`, `root/private/root.key.pem`, `root/private/root.p12`,
and the initial CRL. Refuses to run if `root/` already holds a key or
certificate; clean first with `-c`.

### Intermediate CA

```sh
bin/create_intermediate.sh [-a EC|RSA]
```

Signed by root, `pathlen:0`. Creates
`intermediate/certs/intermediate.{cert.pem,chain.pem,cer}`,
`intermediate/private/intermediate.{key.pem,p12}`, SHA1-named copies
`intermediate.<sha1>.*`, and the initial CRL.

Requires root. Rotating the intermediate leaves existing leaf certificates
signed by the previous key; reissue them (see Reissue below).

### Server

```sh
bin/create_server.sh [-a EC|RSA]
```

CN and SAN are `SERVER_FQDN`. Output is renamed to
`<SERVER_FQDN>.<sha1>.*`: `certs/*.{cert.pem,chain.pem,cer}` and
`private/*.{key.pem,key.pem.decrypted,p12}`. `key.pem.decrypted` is the
unencrypted key, mode 0600.

### Code signing

```sh
bin/create_codesign.sh [-a EC|RSA]
```

CN is `ORG_NAME`. Output is renamed to `codesign.<sha1>.*`.

### S/MIME

```sh
bin/create_smime.sh [-a EC|RSA] EMAIL CERTNAME
```

Issues a signature and an encryption certificate for `EMAIL`:

* `CN=EMAIL - signature`: EC P-256 by default (`-a RSA` for RSA).
* `CN=EMAIL - encryption`: always RSA. Apple Mail does not support ECDH
  S/MIME encryption certificates.

Output is `smime/{certs,private}/CERTNAME-{signature,encryption}.*` plus
SHA1-named copies. Example:
```sh
bin/create_smime.sh user@example.org user_example
```

Issue the full list of identities defined for this deployment:
```sh
PKI_ASSUME_YES=1 bin/create_organization_smime_pki.sh
```

### Privoxy and adblock2privoxy

```sh
bin/create_privoxy.sh
bin/create_adblock2privoxy.sh
```

`privoxy` is a self-signed CA, independent of the root/intermediate
hierarchy. `create_adblock2privoxy.sh` issues `adblock2privoxy-nginx` from it.
Output is renamed to `adblock2privoxy-nginx.<sha1>.*` in
`privoxy/adblock2privoxy/{certs,private}`, including
`key.pem.decrypted` (mode 0600).

### Reissue and supersession

Run a `create_*.sh` script again to reissue. After the replacement is issued,
the script searches the issuing CA's `index.txt` for other valid certificates
with the same CommonName. Each match is revoked with reason `superseded`, and
the issuer's CRL is regenerated once.

* A `[y/N]` prompt precedes each revocation. Set `PKI_ASSUME_YES=1` to skip.
* Matching is by CommonName in the CA database, not by filename.
* If issuance fails, nothing is revoked. `create_intermediate.sh` and
  `create_smime.sh` restore the previous files.
* Existing files are archived as `<name>.<sha1>.*`.

After reissuing the intermediate, reissue server, code signing, and S/MIME
certificates.

## Certificate revocation lists

```sh
bin/create_crl.sh root|intermediate|privoxy
```

Writes `<ca>/crl/<ca>.crl.pem` and the DER file `<ca>/crl/<ca>.crl`.
Validity is 30 days (`default_crl_days`); regenerate more often than that.
Safe to run repeatedly.

Issued certificates reference these URLs, taken from `PKI_FQDN`:

| Certificate | CRL | Issuer certificate (DER) |
|---|---|---|
| intermediate | `http://PKI_FQDN/root.crl` | `http://PKI_FQDN/root.cer` |
| server, codesign, S/MIME | `http://PKI_FQDN/intermediate.crl` | `http://PKI_FQDN/intermediate.cer` |

Publish `root.crl`, `intermediate.crl`, `root.cer`, and `intermediate.cer` at
`http://PKI_FQDN/` under those exact names. CRLs and `.cer` files are DER.

## Revoke a certificate

```sh
bin/revoke_certificate.sh CERTFILE CA [REASON]
```

| Argument | Value |
|---|---|
| `CERTFILE` | PEM certificate to revoke (`*.cert.pem`) |
| `CA` | Issuing CA: `root`, `intermediate`, or `privoxy` |
| `REASON` | Default `keyCompromise` |

`REASON` is one of: `unspecified`, `keyCompromise`, `CACompromise`,
`affiliationChanged`, `superseded`, `cessationOfOperation`,
`certificateHold`, `removeFromCRL`. See `man ca`, `-crl_reason`.

The script revokes the certificate and regenerates the issuer's CRL.
Publish the new CRL afterward. Revocation is permanent once a CRL listing the
certificate is published.

`CA` is the issuer of `CERTFILE`:

| Certificate | `CA` |
|---|---|
| intermediate | `root` |
| server, codesign, S/MIME | `intermediate` |
| adblock2privoxy | `privoxy` |

Examples:
```sh
bin/revoke_certificate.sh server/certs/server.example.org.<sha1>.cert.pem intermediate keyCompromise
bin/revoke_certificate.sh smime/certs/user_example-signature.<sha1>.cert.pem intermediate cessationOfOperation
bin/revoke_certificate.sh intermediate/certs/intermediate.<sha1>.cert.pem root CACompromise
bin/revoke_certificate.sh privoxy/adblock2privoxy/certs/adblock2privoxy-nginx.<sha1>.cert.pem privoxy
```

Revoke both S/MIME certificates (signature and encryption) for an identity.

### Compromised key

* Leaf certificate: revoke with `keyCompromise`, then rerun the `create_*.sh`
  script.
* Intermediate: revoke with `CACompromise` against `root`, run
  `bin/create_intermediate.sh`, then reissue all leaf certificates.

### Verify

List revoked entries (`R`) and valid entries (`V`):
```sh
grep '^R' intermediate/index.txt
grep '^V' intermediate/index.txt
```

Inspect a CRL:
```sh
openssl crl -inform DER -in intermediate/crl/intermediate.crl -noout -text
```

Check a certificate against its issuer's CRL:
```sh
openssl verify -crl_check \
    -CAfile intermediate/certs/intermediate.chain.pem \
    -CRLfile intermediate/crl/intermediate.crl.pem \
    server/certs/<fqdn>.<sha1>.cert.pem
```

## Maintenance

List certificates expiring within N months (default 6):
```sh
bin/certs_that_expire_soon.sh [N]
```

Mark expired entries in each CA database (`openssl ca -updatedb`) and delete
expired server, code signing, and adblock2privoxy files. CA and S/MIME
certificates are not deleted:
```sh
bin/updatedb_and_delete_expired_certs.sh
```

## Clean and create the entire PKI

```sh
bin/clean_everything_and_create_pki.sh
```

Deletes and regenerates every CA, key, and certificate. Prompts for a typed
`yes`. `PKI_ASSUME_YES=1` skips the per-directory `[y/N]` prompts but not this
one. Previously issued certificates no longer chain to the new root.

## MDM configuration profiles

`bin/configurate_yaml.py` converts a YAML file into an unsigned iOS
`.mobileconfig` trust profile, then signs it with the deployment's code
signing certificate.
```sh
bin/configurate_yaml.py mdm-private/yaml/myorganization-trust.yaml [--no-sign]
```

Requirements: Python 3.9+, PyYAML, `cryptography` 39+, `openssl`, `bash`.
`plutil -lint` runs on the output when available (macOS).

### Layout

```
mdm-private/
    yaml/                       profile definitions
    mobfileconfigs-unsigned/    <yaml name>.mobileconfig
    mobfileconfigs-signed/      <yaml name>.mobileconfig, CMS-signed
```

All relative paths resolve against `PKI_ROOT`, the parent directory of `bin/`.
YAML files and output directories must be inside `mdm-private/`.

### YAML format

```yaml
identifier: org.example.mdm.trust        # optional
name: Trust Profile for ${ORG_NAME}
description: Installs the ${ORG_NAME} CA certificates.
organization: ${ORG_NAME}                # optional
scope: System                            # optional: System (default) | User
cert_dirs:
  - $PKI_ROOT/root/certs
  - $PKI_ROOT/intermediate/certs
certificates:
  - root.cer
  - intermediate.cer
```

| Field          | Required | Description |
|----------------|----------|-------------|
| `identifier`   | no       | Reverse-DNS profile identifier. Default: see below. |
| `name`         | yes      | Profile display name. |
| `description`  | yes      | Profile description shown at install. |
| `organization` | no       | `PayloadOrganization`. |
| `scope`        | no       | `System` (default) or `User`. |
| `cert_dirs`    | yes      | Directories searched, in order, for each certificate. Relative paths resolve against `PKI_ROOT`. `$VAR` and `~` are expanded. |
| `certificates` | yes      | Certificate filenames, DER or PEM. Order is preserved in the profile. |

Certificate lookup: exact filename in each `cert_dirs` entry; otherwise
`<stem>.*<suffix>` (matches `<name>.<sha1>.cer` files). Zero or multiple
matches are errors. An absolute path bypasses the search.

`${VAR}` placeholders in `identifier`, `name`, `description`, and
`organization` are filled from `pki_identity.env`, then the environment.
Filters: `${VAR|rdns}` (reverse domain labels), `|lower`, `|upper`.
Undefined variables are errors.

### Generated fields

| Field | Value |
|-------|-------|
| Payload type | `com.apple.security.root` for self-signed certificates, `com.apple.security.pkcs1` otherwise. |
| Display name | Certificate CN (falls back to O). |
| Profile identifier | `identifier`, or `<DOMAIN_NAME reversed>.mdm.<YAML file name>`, e.g. `org.myorganization.mdm.myorganization-trust`. |
| Payload identifier | `<profile identifier>.<root\|pkcs1>.<UUID>` |
| UUIDs | UUIDv5 of profile identifier and certificate SHA-256. Rebuilds are byte-identical. |

The identifier is checked against Apple's documented payload requirements
and against other profiles in `mobfileconfigs-unsigned/`; duplicates are
refused. Keep the identifier stable after deployment: devices match
profiles on it, and a changed identifier installs as a new profile.

### Signing

The signer is the newest `codesign/certs/<CERTNAME>.<sha1>.cert.pem` that
passes all of:

1. Within its validity period.
2. Status `V` in `intermediate/index.txt`.
3. `codeSigning` in ExtendedKeyUsage, if that extension is present.
4. `openssl verify -crl_check_all` against `intermediate/certs/intermediate.chain.pem`
   (`.cert.pem` if no chain file), using all CRLs in `*/crl/`.

Rejected candidates are reported with the reason. If none qualifies, or
`index.txt` or the CRLs are missing, signing fails and no signed file remains.

CRLs are read from `*/crl/*.crl.pem`, otherwise `*/crl/*.crl` (DER or PEM). A
current CRL is required for the issuing CA and for the root; an expired CRL
blocks signing.

The key passphrase is line 1 of `codesign/private/passphrase.txt`. Output is
a DER CMS envelope (`openssl smime -sign -binary -nodetach`) containing the
profile and the issuer chain. The signature and payload round-trip are
verified after signing.

Never edit a profile after signing. Regenerate from the YAML.

### Environment

| Variable              | Default                                | Purpose |
|-----------------------|----------------------------------------|---------|
| `CERTDIR`             | `codesign`                             | Signing identity directory. |
| `CERTNAME`            | `$CERTDIR`                             | Signing file name prefix. |
| `ISSUERCADIR`         | `intermediate`                         | Issuing CA directory (chain, `index.txt`). |
| `ISSUERCANAME`        | `$ISSUERCADIR`                         | Issuing CA file name prefix. |
| `HASH_DIGEST`         | `sha256`                               | Signature digest. |
| `CERTSHA1`            | unset                                  | Pin a signer among usable candidates. Revoked or expired certificates are never used. |
| `UNSIGNED_DIR`        | `mdm-private/mobfileconfigs-unsigned`  | Unsigned output. |
| `SIGNED_DIR`          | `mdm-private/mobfileconfigs-signed`    | Signed output. |
| `IDENTITY_DOMAIN_VAR` | `DOMAIN_NAME`                          | `pki_identity.env` variable holding the domain for default identifiers. |

### Permissions

`mdm-private/` may contain secrets. Ownership is not managed; the scripts run
as the invoking user (or under `sudo`).

- Generated profiles and their directories are set to `0600` (files) and `0700`
  (directories) before anything is written and again on exit, including on failure.
  Loose permissions are reported.
- All other content under `mdm-private/` (YAML, samples) is checked before any
  secret is read. Loose permissions produce a warning and a `[y/N]` prompt to fix.
  Nothing changes without `y`. Without a terminal, the warning includes the
  commands to run.
- `replicate_pki_structure.sh` performs the same check on the source and
  destination `mdm-private/`.
- Symlinks under `mdm-private/` are not followed; a symlink in a tree to be
  fixed aborts the fix.
- All files are created with `umask 077`.

### iOS certificate trust

A root installed by manually installing a profile (email, web, AirDrop) is
not trusted for TLS until enabled under Settings > General > About >
Certificate Trust Settings. Roots installed through Apple Configurator, MDM,
or an MDM enrollment profile are trusted automatically. The profile format
has no key to change this; trust follows the delivery method and applies to
every root in the profile. To leave a root under manual trust (e.g.
the `privoxy` interception root) while auto-trusting others, deliver it in
a separate profile installed manually.

Signed profiles show as verified only if the signer's chain is already
trusted on the device.

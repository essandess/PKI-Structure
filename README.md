# PKI Structure

Shell tooling for a private PKI: root, intermediate, and `privoxy` CAs;
server, code signing, S/MIME, and adblock2privoxy certificates; revocation and
CRL publication; signed macOS install scripts; KeePassXC storage of their
passwords; and signed MDM profiles. Private keys are passphrase protected.

| Tool | Purpose |
|---|---|
| `create_{root,intermediate,intermediate_smime,server,codesign,smime,privoxy,adblock2privoxy}.sh` | CAs and leaf certificates; reissue supersedes the predecessor |
| `revoke_certificate.sh`, `create_crl.sh`, `publish_crls.sh` | Revocation, CRL generation and publication |
| `create_credentials.sh` | Signed macOS install scripts for CA certificates and S/MIME identities |
| `create_keepass_entry.sh` | Install-script passwords into KeePassXC |
| `configurate_yaml.py` | Signed `.mobileconfig` profiles from YAML |
| `create_organization_{smime,mdm,credentials}.sh` | Per-deployment driver scripts, seeded from `.sample` |
| `certs_that_expire_soon.sh`, `updatedb_and_delete_expired_certs.sh` | Expiry reports and cleanup |
| `replicate_pki_structure.sh`, `clean_everything_and_create_pki.sh` | New deployment; full clean or rebuild |
| `pki_structure.sh`, `pki_common.sh`, `define_openssl.sh`, `pki_validate.py` | Shared libraries; `pki_validate.py` is the one certificate validator |

## Requirements

* `bash` 4.4+ (macOS `/bin/bash` is 3.2; use MacPorts or Homebrew).
* OpenSSL 3 (`pkcs12 -legacy`, `enc -pbkdf2`) as `openssl` in `PATH`, or via
  `OPENSSL=/path`. Apple's LibreSSL is rejected (`openssl.cnf` uses `.include`).
  Generated installers run on the macOS-native `openssl`, `tar` with xz, and
  `security`.
* Python 3.9+ with `cryptography` 39+ (certificate validation) and `PyYAML` (MDM profiles).
* `keepassxc-cli` (KeePassXC integration only; `KEEPASSXC_CLI` overrides lookup).
* `rsync` (deployment); `sf-pwgen` (optional; falls back to `openssl rand`).

## Deploying to a new directory

```sh
bin/replicate_pki_structure.sh [-ow|--overwrite] [DEST]      # DEST defaults to .
```

* Copies `.sh`, `.py`, `.cnf`, `.md`, `LICENSE`, `etc/*.sample`, and
  `mdm-private/yaml/*.sample`; never `.git/`, `*.env`, `*.conf`, `*.yaml`,
  `create_organization_smime.sh`, or `create_organization_mdm.sh`.
  `PKI_STRUCTURE_SRC` (trailing `/`) overrides the source.
* Existing files are kept. `-ow` lists what it would replace and asks `[y/N]`
  (`PKI_ASSUME_YES=1` skips the prompt).
* Seeds when absent, from `<file>.sample` (else the source file):
  `pki_identity.env`, `bin/create_organization_{smime,mdm,credentials}.sh`,
  `mdm-private/yaml/ios-restrictions-baseline.yaml`.
* Modes on `DEST`: directories 0755, or 0700 for `*private*` and below; scripts
  0750; other files 0640, or 0600 under a private directory. An existing
  `DEST/mdm-private/` is audited, with a `[y/N]` prompt before any change.

Edit `pki_identity.env` before running any `create_*.sh`.

## Layout

```
pki_identity.env, openssl.cnf, common_policy.cnf
bin/                scripts
root/  intermediate/  intermediate_smime/  server/  codesign/  smime/
privoxy/            separate trust anchor
privoxy/adblock2privoxy/
mdm-private/        secrets; keep out of version control
    yaml/  mobfileconfigs-unsigned/  mobfileconfigs-signed/  credentials/
```

Each PKI directory has `certs/` (`*.cert.pem`, `*.chain.pem`, `*.cer`),
`private/` (`*.key.pem`, `*.p12`, `passphrase.txt`; mode 0700), and, for CAs,
`crl/`, `newcerts/`, `index.txt`, `crlnumber`. A CA's `index.txt` and
`newcerts/` are its issuance record; revocation, supersession, and signer
checks read them. Do not delete them. Configuration is
`<dir>/openssl_<dir>.cnf` (root: `openssl.cnf`).

## Configuration

`pki_identity.env`:

| Variable | Use |
|---|---|
| `ORG_COUNTRY`, `ORG_STATE`, `ORG_LOCALITY`, `ORG_NAME`, `ORG_EMAIL` | Subject fields |
| `DOMAIN_NAME` | Organization domain |
| `SERVER_FQDN` | Server certificate CN and SAN; `create_server.sh --server-fqdn NAME` overrides it per run (must be within `DOMAIN_NAME`) |
| `PKI_FQDN` | Host serving CRLs and CA certificates; embedded in issued certificates |
| `SUBJECTALTNAME_ADBLOCK2PRIVOXY` | adblock2privoxy SAN |

Environment (tool-specific variables are listed with each tool):

| Variable | Default | Use |
|---|---|---|
| `CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY` | unset | Must be `1` to build a CA or leaf certificate |
| `PKI_ASSUME_YES` | `0` | Not `0`: answer `[y/N]` prompts yes (not typed-`yes` prompts) |
| `OPENSSL` | first `openssl` in `PATH` | OpenSSL binary |
| `ALGORITHM` | `EC` | `EC` or `RSA` (same as `-a`) |
| `EC_PARAMGEN_CURVE`, `RSA_KEYGEN_BITS`, `HASH_DIGEST` | per script | Key and digest overrides |
| `SHOW_CERT_TEXT` | `1` | `0` suppresses certificate text |
| `PKI_RENEW_WINDOW_DAYS` | `30` | How close to expiry a self-signed CA may be renewed |

`<dir>/private/passphrase.txt` (created on first use, mode 0600): line 1
protects the private key; line 2 is the `.p12` export password for CA, server,
and code signing `.p12` files. S/MIME `.p12` files use per-issuance passwords
instead (see [S/MIME](#smime)).

## Create certificates

```sh
export CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY=1
```

Order: root, intermediate, intermediate_smime, then leaf certificates; `privoxy` before
`adblock2privoxy`. Options for every script: `-a EC|RSA`, `-c`/`--clean` and
`-vc`/`--veryclean` (delete the directory's keys, certificates, and CA
database; `-vc` also `passphrase.txt`; prompts; irreversible, and issued
certificates can no longer be revoked), `-h`.

| Script | Issuer | Default key | Validity | Output |
|---|---|---|---|---|
| `create_root.sh` | self | EC P-384 | 7305 days | `root.{cert.pem,cer}`, `root.{key.pem,p12}`, CRL |
| `create_intermediate.sh` | root | EC P-384 | 3653 days | `intermediate.*` and `intermediate.<sha1>.*`, CRL; TLS/code signing only, name-constrained |
| `create_intermediate_smime.sh` | root | EC P-384 | 3653 days | `intermediate_smime.*` and `intermediate_smime.<sha1>.*`, CRL; emailProtection only |
| `create_server.sh` | intermediate | EC P-256 (RSA 2048) | 825 days | `<SERVER_FQDN>.<sha1>.*`, incl. `key.pem.decrypted` (0600) |
| `create_codesign.sh` | intermediate | EC P-256 (RSA 2048) | 825 days | `codesign.<sha1>.*` (no unsuffixed names) |
| `create_smime.sh EMAIL CERTNAME` | intermediate_smime | signature EC P-256; encryption RSA 3072 | 825 days | `CERTNAME-{signature,encryption}.*` plus `<sha1>` copies |
| `create_privoxy.sh` | self | EC P-256 | 825 days | `privoxy.*` |
| `create_adblock2privoxy.sh` | privoxy | EC P-256 | 825 days | `adblock2privoxy-nginx.<sha1>.*`, incl. `key.pem.decrypted` |

A leaf's validity is shortened to end a day before its issuer's.

**Renewal.** Re-running `create_root.sh` or `create_privoxy.sh` issues a new
certificate with the same key only within `PKI_RENEW_WINDOW_DAYS` of expiry (or
after it); `create_intermediate.sh` renews at any time after confirmation. Old
files are archived as `<name>.<sha1>.*`; the old certificate is not revoked.
`--new-key` generates a new key; after a new root or intermediate key, reissue
everything below it. Install and trust a renewed root on every device before
the old one expires. After a privoxy renewal, redeploy the certificate where
privoxy uses it.

**Reissue and supersession.** Re-running a leaf script reissues it. Once the
replacement is complete (for S/MIME, both certificates), other valid
certificates with the same CommonName in the issuer's `index.txt` are revoked as
`superseded` (`[y/N]` per revocation) and the CRL is regenerated. On failure
nothing is revoked and the previous files are restored.

### S/MIME

`EMAIL` may have at most 51 characters: the CN `EMAIL - encryption` is
capped at 64 by X.509.

`CN=EMAIL - signature` is EC P-256 (`-a RSA` for RSA); `CN=EMAIL - encryption`
is always RSA (Apple Mail does not support ECDH encryption certificates). Each
issuance has a random `.p12` password shared by its two `.p12` files and stored
beside each as `CERTNAME-{signature,encryption}.p12.pass` (0600). It opens no
other issuance's `.p12`; give it only to the recipient.
`bin/create_organization_smime.sh` runs this deployment's list of identities.

## Intermediate scoping

The root is trusted for every purpose, so one intermediate that could sign
anything would make its key a way to impersonate any site on every device that
trusts the root. There are two intermediates, each restricted:

| CA | Directory | Issues | Restriction |
|---|---|---|---|
| TLS / code signing | `intermediate/` | server, code signing | `extendedKeyUsage` serverAuth, codeSigning; **critical `nameConstraints`**: DNS only under `DOMAIN_NAME`, no IP addresses |
| S/MIME | `intermediate_smime/` | S/MIME | `extendedKeyUsage` emailProtection only |

S/MIME cannot carry `nameConstraints` (addresses include gmail.com and
icloud.com), so its limit is the EKU. `create_intermediate_smime.sh` is
`create_intermediate.sh` with `CERTDIR=intermediate_smime`; renewal, `--new-key`
and archiving behave identically. Each has its own key, `passphrase.txt`,
`index.txt` and CRL (`root`, `intermediate`, and `intermediate_smime`
`.crl`/`.cer` are all published by `publish_crls.sh`). `create_intermediate.sh`
refuses (and revokes) a certificate that does not carry its restrictions
(`pki_assert_ca_scope`), and refuses a `SERVER_FQDN` outside `DOMAIN_NAME`.

**Migrating an existing PKI.** The old intermediate certificate is
unconstrained and must not stay valid:

1. `bin/create_intermediate.sh --new-key` (a same-key renewal would leave the
   old unconstrained certificate valid for the same key), then
   `bin/create_intermediate_smime.sh`.
2. Revoke the old intermediate against the root:
   `bin/revoke_certificate.sh intermediate/certs/intermediate.<old sha1>.cert.pem root superseded`.
3. Reissue the server and code signing certificates and all S/MIME certificates
   (`create_organization_smime.sh`). `create_smime.sh` also revokes (as
   superseded) the identity's still-valid certificates in the old
   `intermediate/index.txt`.
4. `bin/publish_crls.sh`, then rebuild installers and profiles.

Certificates issued under the old intermediate no longer validate once it is
revoked, so old S/MIME encryption certificates can not be put into new
installers or profiles; keep their `.p12` files if the mail they decrypt is
still needed. If `ORG_NAME` looks like a hostname (contains a dot), OpenSSL may
apply the DNS constraint to the code signing certificate's CommonName.

## Revocation and CRLs

```sh
bin/revoke_certificate.sh CERTFILE CA [REASON]    # CA: root | intermediate | intermediate_smime | privoxy
bin/create_crl.sh [--min-days-left DAYS] [--force] root|intermediate|intermediate_smime|privoxy
bin/publish_crls.sh [--if-configured] [--no-regenerate] [root|intermediate|intermediate_smime ...]
```

* **Revoke.** `CA` is the certificate's issuer: intermediate, intermediate_smime → `root`; server, codesign → `intermediate`; S/MIME → `intermediate_smime`; adblock2privoxy → `privoxy`. Revoke both
  S/MIME certificates of an identity. Requires a typed `yes`. `REASON` (default
  `unspecified`): `keyCompromise`, `CACompromise`, `affiliationChanged`,
  `superseded`, `cessationOfOperation`, `certificateHold` (`openssl ca` cannot undo a revocation).
  Then it regenerates the CRL and, for root and intermediate, publishes it.
* **CRL.** Regenerated only if missing, expiring in fewer than 15 days
  (`--min-days-left`, `CRL_MIN_DAYS_LEFT`), not signed by the CA's current
  certificate, or out of step with the revocations in `index.txt`; `--force`
  overrides. Safe to run from cron. `SHOW_CRL_TEXT=0` suppresses the dump.
* **Publish.** Copies the CRL and CA certificate (DER) to `PKI_SITE_DIR` (or
  `<prefix>/var/www/PKI_FQDN` in a MacPorts layout; group `PKI_SITE_GROUP`,
  default `_www`, else `nobody`). If a CA key is not present (offline root), its
  existing CRL is published, with a warning when it is nearly expired. The
  `privoxy` CRL is not published.
* **Compromised key.** Revoke a leaf with `keyCompromise` and reissue it; revoke
  the intermediate with `CACompromise` against `root`, run
  `create_intermediate.sh --new-key`, and reissue all leaves.

Certificates reference `http://PKI_FQDN/{root,intermediate,intermediate_smime}.crl` and `{root,intermediate,intermediate_smime}.cer` (DER). Publish them under those names.

```sh
openssl crl -inform DER -in intermediate/crl/intermediate.crl -noout -text
grep '^R' intermediate/index.txt        # revoked; '^V' for valid
```

## Signer selection

`configurate_yaml.py` and `create_credentials.sh` sign with the newest
`codesign/certs/<name>.<sha1>.cert.pem` that:

1. is within its validity period;
2. has status `V` in `intermediate/index.txt` (revoked or superseded is never
   accepted);
3. carries `codeSigning` in ExtendedKeyUsage, if that extension is present;
4. passes `openssl verify -crl_check_all` through a valid intermediate, with
   current CRLs for the whole chain.

Rejected candidates are reported with the reason; if none qualifies the tool
fails. The key passphrase is line 1 of `codesign/private/passphrase.txt`.

| | `configurate_yaml.py` | `create_credentials.sh` |
|---|---|---|
| Directory / prefix | `CERTDIR` / `CERTNAME` | `PKI_CODESIGN_DIR` / `PKI_CODESIGN_NAME` |
| Pin a signer | `CERTSHA1` | `PKI_CODESIGN_SHA1` |

A pinned certificate that fails the checks is an error, not a fallback.

## macOS credential installers

```sh
bin/create_credentials.sh [--user-keychain] [--extra-pki-dir DIR]...
    [--exclude-expired-encryption] [--exclude-superseded-encryption] ['NAME_GLOB' ...]
bin/create_credentials.sh --ca-certs-only [--user-keychain]
```

Writes `mdm-private/credentials/install_credentials_<stem>.sh` (0750) after
listing the payload and confirming. `-h` lists all options.

| Mode | Payload | Encrypted |
|---|---|---|
| default | root, valid intermediate (both required) and privoxy CA certificates; S/MIME `.p12` files matching the globs | yes, if it has `.p12` files |
| `--ca-certs-only` | the same CA certificates only; no `.p12`, no passwords | no |

CA private keys are never included.

* **Globs.** Single-quote each `'NAME_GLOB'`: a bash glob with brace expansion
  matched against names in `smime/certs`, e.g. `'personb_{gmail,comcast}_2026'`.
  `<stem>` is the globs with glob characters spelled out (`*` S, `?` Q, `{` LB,
  `}` RB, `[` LBK, `]` RBK, `,` C, `!`/`^` N), `nosmimes` without globs, or
  `cacerts`. `--extra-pki-dir DIR` (repeatable) also searches `DIR/smime`, a
  tree with the same layout (e.g. an older one with expired certificates).
* **`.p12` passwords.** Each `.p12` must open with its `<p12>.pass`, or (older
  files) line 2, else line 1, of its tree's `passphrase.txt`. The script also
  checks that the `.p12` holds the expected certificate and matching key.
* **Validation.** Root and privoxy CA must verify against themselves; the
  intermediate against the root. S/MIME certificates must verify through a
  valid intermediate with `-crl_check_all`; an unexpired CRL is required
  (`PKI_ROOT_CRL`, `PKI_INTERMEDIATE_CRL` name CRL files explicitly).
  Policy is one table in `bin/pki_validate.py`, shared with
  `configurate_yaml.py`:

  | State | signature, codesign | encryption |
  |---|---|---|
  | valid | accept | accept |
  | expired | reject | `--allow-expired-encryption` |
  | revoked: superseded | reject | `--allow-superseded-encryption` |
  | expired and superseded | reject | both flags |
  | other revocation, not yet valid, wrong keyUsage/EKU | reject | reject |

  The file name gives the role; a keyUsage that does not fit it is rejected.
* **Encryption.** A payload with `.p12` files also holds their password files,
  so it is encrypted (`openssl enc -aes-256-cbc -pbkdf2`, 600000 iterations)
  with a random 24-character password written to `<installer>.pass` (0600).
  The installer reads it from the terminal only. Send installer and `.pass` by
  different channels.
* **Signature.** A detached PKCS#7 (DER) over the script and encrypted payload,
  stored between `__SIGNATURE_BELOW__` and `__PAYLOAD_BELOW__`, signed per
  [Signer selection](#signer-selection). The installer verifies that the file is
  unchanged, that the signer chains to the root and intermediates carried in the
  signature block (checked before the payload is decrypted or unpacked), and that the signer is a code signing, non-CA certificate. A recipient
  has no CRL for the signer, so a signer revoked after signing is not detected.
* **Root anchor.** A chain inside the file cannot show who built it. Before
  installing, the installer requires that the payload's root is already
  installed on the machine, or matches `PKI_ROOT_SHA256`, or that the user
  confirms its SHA-256 fingerprint against one received separately.
  `PKI_ASSUME_YES` never accepts an unknown root. `create_credentials.sh` prints
  the fingerprint; send it by a separate channel.

Environment: `PKI_PRIVOXY_DIRS` (default `privoxy`),
`PKI_CODESIGN_DIR`/`NAME`/`SHA1`, `PKI_ROOT_CRL`, `PKI_INTERMEDIATE_CRL`,
`PKI_ASSUME_YES`.

Running an installer (macOS, as the target user, not root):

```sh
./install_credentials_<stem>.sh [--system-only | --user-only] [--list] [--tar-only] [--check-signature-integrity]
```

Order: installer password (if encrypted), signature check, root-anchor check,
then `[y/N]` per certificate, with `sudo` only for the System keychain. CA
certificates go to the System keychain (or the login keychain with
`--user-keychain`); the root is also trusted. S/MIME `.p12` files go to the
login keychain.

| Option | Effect |
|---|---|
| `--system-only`, `--user-only` | Install only the System or only the login keychain items |
| `--list` | Verify the signature, list the payload, and exit |
| `--tar-only` | Write the payload (still encrypted, if it is) to `credentials_<stem>.txz[.enc]` in the current directory and exit |
| `--check-signature-integrity` | Run the signature check only (no password; nothing decrypted or unpacked; root not anchored) and exit 0 if valid, non-zero if not. Needs only `openssl`, not macOS or a non-root user |

Installer environment: `PKI_ASSUME_YES`, `PKI_ROOT_SHA256`, and
`PKI_P12_PASSWORD_<GROUP>` (for a `.p12` whose password the payload lacks;
`GROUP` is the name shown in the prompt, upper-cased, other characters `_`).

## KeePassXC

```sh
bin/create_keepass_entry.sh --db FILE [--key-file FILE | --no-password] [--title T] [--group PATH]
    [--individual-smime-passwords] [--force-update] [--no-backup] [--kp-prompt] [-n] INSTALLER
bin/create_keepass_entry.sh --xml-out FILE [--individual-smime-passwords] INSTALLER
```

`INSTALLER` is an encrypted installer. The script decrypts its payload with the
`.pass` file (never running the installer), so a wrong `.pass` fails before
anything is stored. `--ca-certs-only` installers are unencrypted and rejected.

* **Default:** one entry whose Password is the installer password; Notes list
  the contents, no passwords.
* **`--individual-smime-passwords`:** also one protected attribute per S/MIME
  issuance (`<certname> [<issued>]`), each checked against its `.p12`.
* Entry UUIDs derive from title and group, so re-runs update in place.
  The entry is imported into a staging database, previewed with `merge
  --dry-run`, and merged; `--db` is first copied to `DB.bak-<time>` unless
  `--no-backup`.
* Secrets never appear in argv or the environment; the decrypted payload and
  XML live in a private temp directory removed on exit. `--xml-out` writes
  plain-text XML (0600) and asks before replacing an existing file.

Copy values with `keepassxc-cli clip DB 'TITLE'` (installer password) or
`clip -a 'ATTRIBUTE' DB 'TITLE'`. Relative paths resolve against the PKI root.

## MDM profiles

```sh
bin/configurate_yaml.py mdm-private/yaml/myorganization-trust.yaml [--no-sign]
```

Builds an unsigned `.mobileconfig`, then signs it (DER CMS, signer per
[Signer selection](#signer-selection); signature and payload round-trip
verified). YAML and output directories must be under `mdm-private/`; relative
paths resolve against the PKI root. `create_organization_mdm.sh` runs this
deployment's list of profiles and takes no arguments. Never edit a profile
after signing; regenerate.

Output: `mdm-private/mobfileconfigs-{unsigned,signed}/<yaml name>.mobileconfig`.
At least one of `certificates`, `payloads`, `identities`, `accounts` is
required.

| Key | Description |
|---|---|
| `identifier` | Default `<DOMAIN_NAME reversed>.mdm.<yaml name>`. Keep stable after deployment |
| `name`, `description` | Required |
| `organization`, `scope` (`System`\|`User`), `removal_disallowed` | Optional |
| `cert_dirs`, `certificates` | CA certificates (DER or PEM) as `root`/`pkcs1` payloads; lookup tries the exact name, then `<stem>.*<suffix>` |
| `payloads` | Arbitrary Apple payloads: `id`, `type`, `name`, `description`, `settings` |
| `include` | Other files' `payloads:`, merged by `id` underneath this file's own |
| `identities` | S/MIME identities as PKCS#12 payloads |
| `accounts` | `mail`, `caldav`, `carddav` accounts |
| `short_name` | Default sender name for mail accounts |

`${VAR}` and `${VAR|rdns|lower|upper}` in text fields are filled from
`pki_identity.env`, then the environment.

* **Payloads.** `id` is stable and unique (it fixes the identifier and UUID);
  `settings` keys beginning `Payload` are reserved. `type` is a full
  PayloadType or an alias in `TYPE_ALIASES` (`passcode`, `restrictions`,
  `wifi`, `airprint`, `airplay`, `content-filter`, `fonts`, `notifications`,
  `subscribed-calendar`, `webclip`). A `settings` value `{file: PATH}` or
  `{base64: TEXT}` becomes binary data. Includes are relative to the including
  file; repeated ids deep-merge `settings`; a changed `type` or a circular
  include is an error.
* **YAML types.** Only `true`/`false` are booleans (`yes`/`no`/`on`/`off` stay
  strings); bare dates and other values a plist cannot hold are rejected.
* **Identities.** `<name>-{signature,encryption}.p12` from `identity_dirs`
  (default `smime/private`); password from `<p12>.pass`, else line 2 of
  `identity_passphrase_file`. Each embedded certificate must be `V` in the
  issuer's `index.txt`, pass the CRL check, and have a keyUsage matching its
  role. Signing certificates must be current; an expired or `superseded`
  encryption certificate needs `allow_expired_encryption` /
  `allow_superseded_encryption` on the entry (same policy as
  `create_credentials.sh`'s `--allow-*-encryption`). Other revocations
  are refused.
* **Accounts.** Translated to payloads and merged like hand-written ones (a
  payload with the same `id` overrides field by field); `smime.identity` must
  be in `identities`. A `settings:` mapping on an entry takes Apple keys.
  Passwords are plaintext in the YAML and the profile.
* **Overwrite.** If the output exists, or another profile in
  `mobfileconfigs-unsigned/` has the same `PayloadIdentifier`, the unsigned and
  signed files to be replaced are listed and `[y/N]` is asked; `PKI_ASSUME_YES=1`
  answers yes.

Environment: `CERTDIR`, `CERTNAME` (default `codesign`), `ISSUERCADIR`,
`ISSUERCANAME` (default `intermediate`), `SMIME_ISSUERCADIR`,
`SMIME_ISSUERCANAME` (default to the signing issuer), `HASH_DIGEST`
(`sha256`), `CERTSHA1`, `UNSIGNED_DIR`, `SIGNED_DIR`, `IDENTITY_DOMAIN_VAR`
(`DOMAIN_NAME`), `PKI_ASSUME_YES`. CRLs are read from `*/crl/*.crl.pem`, else
`*/crl/*.crl`.

**Permissions.** Signing does not encrypt: `mdm-private/` holds secrets
(account passwords, installers, `.pass` files). `configurate_yaml.py` sets
`umask 077` and does not check or change modes; `create_credentials.sh` sets
`mdm-private/` and `credentials/` to 0700, installers 0750, `.pass` 0600;
`replicate_pki_structure.sh` audits `mdm-private/` at the destination.

**iOS trust.** A root installed by manually opening a profile is not trusted
for TLS until enabled under Settings > General > About > Certificate Trust
Settings; Apple Configurator, MDM, and enrollment profiles trust it
automatically. The profile format has no key to change this. To leave a root
(e.g. the `privoxy` root) under manual trust, deliver it in a separate profile.
Signed profiles show as verified only if the signer's chain is already trusted.

## Maintenance

```sh
bin/certs_that_expire_soon.sh [MONTHS]            # default 6
bin/updatedb_and_delete_expired_certs.sh [-n]     # updatedb; delete expired server, codesign, adblock2privoxy files
bin/clean_everything_and_create_pki.sh [--create-pki]
```

`updatedb_and_delete_expired_certs.sh -n` lists without deleting; CA and
S/MIME certificates are never deleted. `clean_everything_and_create_pki.sh`
deletes every key, certificate, and CA database after a typed `yes`
(`PKI_ASSUME_YES=1` skips only the per-directory prompts); with `--create-pki`
it then rebuilds the PKI and the S/MIME list. Previously issued certificates no
longer chain to the new root.

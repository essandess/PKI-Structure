# PKI Structure

Shell tooling for a private PKI: root, intermediate, and privoxy CAs;
server, code signing, S/MIME, and adblock2privoxy certificates; 
CRL publication and revocation; signed macOS install scripts and configuration
profiles (.mobileconfig); KeePassXC password keychain with a root-only
master password file (login keychain item for other users) and separable
keyfile.

Profiles exported to an external KeePass database synced to mobile devices
(e.g. Syncthing) provide serverless, MDM-style distribution: the device
opens the attachment and installs it. This is manual: no push, enforcement
or remote removal, and a root needs enabling under Certificate Trust Settings
(see iOS trust).

| Tool | Purpose |
|---|---|
| `create_{root,intermediate,intermediate_smime,server,codesign,smime,privoxy,adblock2privoxy}.sh` | CAs and leaf certificates; reissue supersedes the predecessor |
| `revoke_certificate.sh`, `create_crl.sh`, `publish_crls.sh` | Revocation, CRL generation and publication |
| `create_credentials.sh` | Signed macOS install scripts for CA certificates and S/MIME identities |
| `verify_installer.sh` | Signature check of an installer without running it |
| `create_keepass_entry.sh` | Installers with their passwords, master password, and stored profiles with trust profiles, into KeePassXC |
| `configurate_yaml.py` | `.mobileconfig` profiles from YAML, stored in the keychain |
| `create_organization_{smime,mdm,credentials}.sh` | Per-deployment driver scripts, seeded from `.sample` |
| `certs_that_expire_soon.sh`, `updatedb_and_delete_expired_certs.sh` | Expiry reports and cleanup |
| `replicate_pki_structure.sh`, `clean_everything_and_create_pki.sh` | New deployment; full clean or rebuild |
| `pki_structure.sh`, `pki_common.sh`, `define_openssl.sh`, `pki_validate.py`, `pki_keychain.py`, `pki_index.py` | Shared libraries; `pki_validate.py` is the one certificate validator, `pki_keychain.py` the passphrase store, `pki_index.py` the `index.txt` queries |

## Requirements

* `bash` 4.4+ (macOS `/bin/bash` is 3.2; use MacPorts or Homebrew).
* OpenSSL 3 (`pkcs12 -legacy`, `enc -pbkdf2`) as `openssl` in `PATH`, or via
  `OPENSSL=/path`. Apple's LibreSSL is rejected (`openssl.cnf` uses `.include`).
  Generated installers run on the macOS-native `openssl`, `tar` with xz, and
  `security`.
* Python 3.9+ with `cryptography` 44+ (certificate validation, KDBX4 database
  creation) and `PyYAML` (MDM profiles).
* `keepassxc-cli` 2.7+ (key passphrases, profile attachments; `KEEPASSXC_CLI`
  overrides lookup) and macOS `security`.
* `rsync` (deployment).

## Deploying to a new directory

```sh
bin/replicate_pki_structure.sh [-ow|--overwrite] [DEST]      # DEST defaults to .
```

* Copies `.sh`, `.py`, `.cnf`, `.md`, `LICENSE`, `etc/*.sample`, and
  `mdm/yaml/*.sample`; never `.git/`, `*.env`, `*.conf`, `*.yaml`,
  or `create_organization_*.sh`.
  `PKI_STRUCTURE_SRC` (trailing `/`) overrides the source.
* Existing files are kept. `-ow` lists what it would replace and asks `[y/N]`
  (`PKI_ASSUME_YES=1` skips the prompt).
* Seeds when absent, from `<file>.sample` (else the source file):
  `pki_identity.env`, `bin/create_organization_{pki,smime,credentials,mdm}.sh`,
  `mdm/yaml/ios-restrictions-baseline.yaml`.
* Modes on `DEST`: directories 0755, or 0700 for `*private*`, `keepassxc`, `mdm` and below; scripts
  0750; other files 0640, or 0600 under a private directory. An existing
  `DEST/mdm/` is audited, with a `[y/N]` prompt before any change.

Edit `pki_identity.env` before running any `create_*.sh`.

## Layout

```
pki_identity.env, openssl.cnf, common_policy.cnf
bin/                scripts
etc/                nginx and pf samples
test/               pki_test.sh (destructive; see Testing)
root/  intermediate/  intermediate_smime/  server/  codesign/  smime/
privoxy/            separate trust anchor
privoxy/adblock2privoxy/
keepassxc/          secrets; keychain/ keyfile/ master/
mdm/                YAML sources and installers; keep out of version control
    yaml/  credentials/
```

Each PKI directory has `certs/` (`*.cert.pem`, `*.chain.pem`, `*.cer`),
`private/` (`*.key.pem`, `*.p12`; mode 0700), and, for CAs,
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
| `PYTHON` | first `python3` in `PATH` | Python binary |
| `KEEPASSXC_CLI` | `keepassxc-cli` in `PATH` | KeePassXC CLI binary |
| `PKI_KEYCHAIN_DIR`, `PKI_KEYCHAIN_KEYFILE` | `keepassxc/keychain`, `keepassxc/keyfile/pki-structure.keyx` | Database directory and key file |
| `PKI_KEYCHAIN_MASTER` | `keepassxc/master/pki-structure.pass` | Master password file; setting it selects the file backend |
| `PKI_KEYCHAIN_FILE`, `PKI_KEYCHAIN_ITEM` | login keychain, service name | Keychain file and item of the master (tests) |
| `PKI_KEYCHAIN_KDF_ROUNDS` | `4` | Argon2 rounds of a new database |
| `PKI_SITE_DIR`, `PKI_SITE_GROUP` | `<prefix>/var/www/PKI_FQDN`, `_www` else `nobody` | CRL web directory and its group |
| `CRL_MIN_DAYS_LEFT` | `15` | Regenerate a CRL that expires sooner |
| `PKI_VERIFY_STRICT` | `1` | `0` drops `-x509_strict`; honored only in a test tree (`.pki_test_tree`) |

`CERTDIR`, `CERTNAME`, `ISSUERCADIR`, `ISSUERCANAME` and `CATRUE` are read from
the environment by the create scripts and `configurate_yaml.py`; do not export
them in the shell. `test/pki_test.sh` unsets them.

## Key passphrases

Each private key has its own random passphrase in
`keepassxc/keychain/pki-structure.kdbx` (KeePassXC; KDBX4, Argon2id, 64 MiB,
4 lanes, 4 rounds; `PKI_KEYCHAIN_KDF_ROUNDS` sets the rounds of a new
database), found by SHA-256 of the key's public key, so a same-key renewal
finds it. Entry `Password/<id16> :: <CN>`: Password = key passphrase,
UserName = serial, URL = certificate SHA-256; `... :: p12` holds the `.p12`
export password. Under the root `PKI-Structure`: `Password` holds bare
secrets (key, `.p12`, installer, master), `Profile` installable artifacts
with their secrets attached (profiles, exported installers). Encrypted
files stay on disk; only plaintext artifacts live in the vault.

The database opens only with the master password (192 random bits) and the
key file `keepassxc/keyfile/pki-structure.keyx` (`PKI_KEYCHAIN_KEYFILE`; 0600;
keep a copy offline). The master is created once, never replaced or deleted,
and never next to an existing database:

| Run as | Master | Protection |
|---|---|---|
| root | `keepassxc/master/pki-structure.pass`, 0600 (`PKI_KEYCHAIN_MASTER`) | file mode: other users cannot read it |
| other user | login keychain item, service `com.github.essandess.pki-structure.keepassxc-passphrase`, name `PKI-Structure KeePassXC Passphrase` | any process of that user can read it |

Root and each user have separate masters and databases. The root file protects
against non-root users only: escrow it (`export-master`) and back up the
master, key file and database together; any one missing makes the others
useless. To keep the master off the server, escrow it offline, keep the key
file on removable media (`PKI_KEYCHAIN_KEYFILE`) and delete the `.pass` file;
restore it with `import-master` before issuing or refreshing CRLs.

```sh
bin/pki_keychain.py get --cert CERT [--field p12]     # print a secret
bin/pki_keychain.py list | prune [-n] | reap          # reap: failed issuances
bin/pki_keychain.py get --all --field key|p12         # every secret, id16<TAB>secret
bin/pki_keychain.py export-master | import-master     # escrow / restore (stdin)
bin/pki_keychain.py verify | kdf-check | selftest     # master + database; KDF; keychain
bin/pki_keychain.py installer-set | installer-get --name NAME   # installer passwords
bin/pki_keychain.py profile-get --name NAME [--unsigned] --out FILE          # stored profile
bin/pki_keychain.py profile-list | profile-rm --name NAME
```


## Create certificates

```sh
export CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY=1
```

Order: root, intermediate, intermediate_smime, then leaf certificates; `privoxy` before
`adblock2privoxy`. Options for every script: `-a EC|RSA`, `-c`/`--clean`
(delete the directory's keys, certificates, CA database and their keychain
entries; prompts; irreversible, and issued certificates can no longer be
revoked), `-h`.

| Script | Issuer | Default key | Validity | Output |
|---|---|---|---|---|
| `create_root.sh` | self | EC P-384 | 7305 days | `root.{cert.pem,cer}`, `root.{key.pem,p12}`, CRL |
| `create_intermediate.sh` | root | EC P-384 | 3653 days | `intermediate.*` and `intermediate.<sha1>.*`, CRL; TLS/code signing only, name-constrained |
| `create_intermediate_smime.sh` | root | EC P-384 | 3653 days | `intermediate_smime.*` and `intermediate_smime.<sha1>.*`, CRL; emailProtection only |
| `create_server.sh` | intermediate | EC P-256 (RSA 2048) | 825 days | `<SERVER_FQDN>.<sha1>.*`; with `--decrypt-key` also `key.pem.decrypted` (0600, unencrypted) |
| `create_codesign.sh` | intermediate | EC P-256 (RSA 2048) | 825 days | `codesign.<sha1>.*` (no unsuffixed names) |
| `create_smime.sh EMAIL CERTNAME` | intermediate_smime | signature EC P-256; encryption RSA 3072 | 825 days | `CERTNAME-{signature,encryption}.*` plus `<sha1>` copies |
| `create_privoxy.sh` | self | EC P-256 | 854 days (825 + (`PKI_RENEW_WINDOW_DAYS` - 1)) | `privoxy.*` |
| `create_adblock2privoxy.sh` | privoxy | EC P-256 | 825 days | `adblock2privoxy-nginx.<sha1>.*`; with `--decrypt-key` also `key.pem.decrypted` (unencrypted) |

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
issuance has a random `.p12` password shared by its two `.p12` files, kept in the
keychain (`bin/pki_keychain.py get --cert smime/certs/CERTNAME-signature.cert.pem
--field p12`). It opens no other issuance's `.p12`; give it only to the recipient.
`bin/create_organization_smime.sh` runs this deployment's list of identities.

## Intermediate scoping

The root is trusted for every purpose, so one intermediate that could sign
anything would make its key a way to impersonate any site on every device that
trusts the root. There are two intermediates, each restricted:

| CA | Directory | Issues | `pathlen` | Restriction |
|---|---|---|---|---|
| TLS / code signing | `intermediate/` | server, code signing | 0 | `extendedKeyUsage` serverAuth, codeSigning; **critical `nameConstraints`**: DNS only under `DOMAIN_NAME`, no IP addresses |
| S/MIME | `intermediate_smime/` | S/MIME | 0 | `extendedKeyUsage` emailProtection only |

S/MIME cannot carry `nameConstraints` (addresses include gmail.com and
icloud.com), so its limit is the EKU. `create_intermediate_smime.sh` is
`create_intermediate.sh` with `CERTDIR=intermediate_smime`; renewal, `--new-key`
and archiving behave identically. Each has its own key,
`index.txt` and CRL (`root`, `intermediate`, and `intermediate_smime`
`.crl`/`.cer` are all published by `publish_crls.sh`). `create_intermediate.sh`
refuses (and revokes) a certificate that does not carry its restrictions
(`pki_assert_ca_scope`), and refuses a `SERVER_FQDN` outside `DOMAIN_NAME`.

OpenSSL checks a leaf's CommonName against DNS nameConstraints when the leaf
has no DNS SAN and the CN parses as a hostname, e.g. an `ORG_NAME` containing
a dot. The code signing certificate has no SAN.

## Revocation and CRLs

```sh
bin/revoke_certificate.sh CERTFILE CA [REASON]    # CA: root | intermediate | intermediate_smime | privoxy
bin/create_crl.sh [--min-days-left DAYS] [--force] root|intermediate|intermediate_smime|privoxy
bin/publish_crls.sh [--if-configured] [--no-regenerate] [root|intermediate|intermediate_smime ...]
```

* **Revoke.** `CA` is the certificate's issuer: intermediate, intermediate_smime → `root`; server, codesign → `intermediate`; S/MIME → `intermediate_smime`; adblock2privoxy → `privoxy`. Revoke both
  S/MIME certificates of an identity. Requires a typed `yes`. `REASON` (default
  `unspecified`): `keyCompromise`, `CACompromise`, `affiliationChanged`,
  `superseded`, `cessationOfOperation`, `certificateHold` (a revocation cannot be undone without editing `index.txt`).
  Then it regenerates the CRL and, for every CA except privoxy, publishes it.
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

`configurate_yaml.py` and `create_credentials.sh` sign with the newest (`pki_validate.py signer`)
`codesign/certs/<name>.<sha1>.cert.pem` that:

1. is within its validity period;
2. has status `V` in `intermediate/index.txt` (revoked or superseded is never
   accepted);
3. carries `codeSigning` in ExtendedKeyUsage, if present, and its issuing CA
   allows `codeSigning`;
4. passes `openssl verify -crl_check_all` through a valid intermediate, with
   current CRLs for the whole chain.

Rejected candidates are reported with the reason; if none qualifies the tool
fails. The key passphrase comes from the keychain.

| | `configurate_yaml.py` | `create_credentials.sh` |
|---|---|---|
| Directory / prefix | `CERTDIR` / `CERTNAME` | `PKI_CODESIGN_DIR` / `PKI_CODESIGN_NAME` |
| Pin a signer | `CERTSHA1` | `PKI_CODESIGN_SHA1` |

A pinned certificate that fails the checks is an error, not a fallback.

## macOS credential installers

```sh
bin/create_credentials.sh [--user-keychain] [--extra-pki-dir DIR]...
    [--with-privoxy] [--allow-expired-encryption]
    [--allow-superseded-encryption] ['NAME_GLOB' ...]
bin/create_credentials.sh --ca-certs-only [--user-keychain]
```

Writes `mdm/credentials/install_credentials_<stem>.sh` (0750) after
listing the payload and confirming. `-h` lists all options.

| Mode | Payload | Encrypted |
|---|---|---|
| default | root, valid intermediate (both required), valid S/MIME intermediate; privoxy CA with `--with-privoxy`; S/MIME `.p12` files matching the globs | yes, if it has `.p12` files |
| `--ca-certs-only` | the same CA certificates only; no `.p12`, no passwords | no |

CA private keys are never included.

* **Globs.** Single-quote each `'NAME_GLOB'`: a bash glob with brace expansion
  matched against names in `smime/certs`, e.g. `'personb_{gmail,comcast}_2026'`.
  `<stem>` is the globs with glob characters spelled out (`*` S, `?` Q, `{` LB,
  `}` RB, `[` LBK, `]` RBK, `,` C, `!`/`^` N), `nosmimes` without globs, or
  `cacerts`. `--extra-pki-dir DIR` (repeatable) also searches `DIR/smime`, a
  tree with the same layout (e.g. an older one with expired certificates).
* **`.p12` passwords.** Each `.p12` must open with its keychain password (`--extra-pki-dir`: that
  tree's `keepassxc/keychain/`). The script also
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
  with a random 24-character password stored in the PKI keychain as the entry
  `<installer file name>` (`pki_keychain.py installer-get --name NAME`). The installer
  reads it from the terminal only. Send installer and password by different channels.
* **Signature.** A detached PKCS#7 (DER) over the script and encrypted payload,
  stored between `__SIGNATURE_BELOW__` and `__PAYLOAD_BELOW__`, signed per
  [Signer selection](#signer-selection). The installer verifies that the file is
  unchanged, that the signer chains to the root and intermediates carried in the
  signature block (checked before the payload is decrypted or unpacked), and that the signer is a non-CA code signing certificate whose issuing CA
  allows code signing. A recipient
  has no CRL for the signer, so a signer revoked after signing is not detected.
  The installer's own check runs inside the file: it detects damage, not
  an editor who removes it. Verify first, from a trusted tree, with
  `bin/verify_installer.sh INSTALLER (--root FILE | --root-sha256 HEX)`.
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
It is the one secret passed through the environment; prefer the prompt.

## KeePassXC

```sh
bin/create_keepass_entry.sh --db FILE [--key-file FILE | --no-password] [--title T] [--group PATH]
    [--individual-smime-passwords] [--force-update] [--no-backup] [--kp-prompt] [-n]
    [--trust NAME]... [--no-trust] INSTALLER|PROFILE
bin/create_keepass_entry.sh --xml-out FILE [--individual-smime-passwords] INSTALLER
```

`INSTALLER` is an encrypted installer. The script decrypts its payload with the
installer's keychain password (never running the installer), so a missing or wrong
password fails before anything is stored. `--ca-certs-only` installers are unencrypted and rejected.

* **Default:** one entry: Password = installer password, attachment = the
  installer; Notes list the contents, no passwords. The entry goes into the
  group `Profile` (`--group` overrides; created if absent).
  `--xml-out` cannot carry the attachment.
* **`--export-master`:** also (or, without `INSTALLER`, only) the PKI master
  password (`pki_keychain.py export-master`), titled `PKI-Structure KeePassXC Passphrase`
  (`--master-title`), in the group `Password`. Back up the key file and the
  `.kdbx` with it.
* **`--individual-smime-passwords`:** also one protected attribute per S/MIME
  issuance (`<certname> [<issued>]`), each checked against its `.p12`.
* **`PROFILE`:** an argument that is not a file names a profile in
  `pki_keychain.py profile-list`. Its `.mobileconfig` and the trust profiles
  (`--trust NAME`, repeatable; default: stored profiles named `*-trust`;
  `--no-trust`: none) are attached to the entry `MDM profile: NAME` in the
  group `Profile` (created if absent). Install the trust profile first. An
  attachment holds passwords in plain text if its profile has secrets. Not
  with `--xml-out` or `--export-master`; needs `keepassxc-cli` 2.7+. A re-run
  with unchanged content is skipped; `--force-update` replaces the entry.
* Entry UUIDs derive from title and group, so re-runs update in place.
  The entry is imported into a staging database, previewed with `merge
  --dry-run`, and merged; `--db` is first copied to `DB.bak-<time>` unless
  `--no-backup`. As root, `--db` keeps its owner and group.
* Secrets never appear in argv or the environment; the decrypted payload and
  XML live in a private temp directory removed on exit. `--xml-out` writes
  plain-text XML (0600) and asks before replacing an existing file.

Copy values with `keepassxc-cli clip DB 'TITLE'` (installer password) or
`clip -a 'ATTRIBUTE' DB 'TITLE'`. Relative paths resolve against the PKI root.

## Configuration profiles

```sh
bin/configurate_yaml.py mdm/yaml/myorganization-trust.yaml [--no-sign]
```

Builds a `.mobileconfig`, signs it (DER CMS, signer per
[Signer selection](#signer-selection); signature and payload round-trip
verified) and stores it as the attachment of the PKI keychain entry
`Profile/mobileconfig :: <yaml name>`; nothing is written to `mdm/`. `--no-sign`
stores it unsigned. The YAML must be under `mdm/`; relative paths resolve
against the PKI root. `create_organization_mdm.sh` runs this deployment's
list of profiles and takes no arguments. Never edit a profile after
signing; regenerate. At least one of `certificates`, `payloads`,
`identities`, `accounts` is required.

```sh
bin/pki_keychain.py profile-list
bin/pki_keychain.py profile-get --name NAME [--unsigned] --out FILE
```

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
  (default `smime/private`); password from the keychain. Each embedded certificate must be `V` in the
  issuer's `index.txt`, pass the CRL check, and have a keyUsage matching its
  role. Signing certificates must be current; an expired or `superseded`
  encryption certificate needs `allow_expired_encryption` /
  `allow_superseded_encryption` on the entry (same policy as
  `create_credentials.sh`'s `--allow-*-encryption`). Other revocations
  are refused.
* **Accounts.** Translated to payloads and merged like hand-written ones (a
  payload with the same `id` overrides field by field); `smime.identity` must
  be in `identities`. A `settings:` mapping on an entry takes Apple keys.
  Passwords are `!secret LABEL` (see Secrets).
* **Replace.** A stored profile of the same name is replaced after `[y/N]`
  (`PKI_ASSUME_YES=1` answers yes); one with the same `PayloadIdentifier`
  under another name is an error.

Environment: `CERTDIR`, `CERTNAME` (default `codesign`), `ISSUERCADIR`,
`ISSUERCANAME` (default `intermediate`), `SMIME_ISSUERCADIR`,
`SMIME_ISSUERCANAME` (default `intermediate_smime`), `HASH_DIGEST`
(`sha256`), `CERTSHA1`, `IDENTITY_DOMAIN_VAR`
(`DOMAIN_NAME`), `PKI_ASSUME_YES`. CRLs are read from `*/crl/*.crl.pem`, else
`*/crl/*.crl`.

**Secrets.** No YAML holds a secret. Write `!secret LABEL` for a password: it
is prompted for twice at build time. A literal under a password-like key is an
error. A profile with a `!secret` or with `identities` (the `.p12` passwords
are embedded) holds them in plain text; signing does not encrypt. Extract it,
use it at once, then delete it. `configurate_yaml.py` sets `umask 077`;
`create_credentials.sh` sets `mdm/` and `credentials/` to 0700, installers
0750; `replicate_pki_structure.sh` audits `mdm/` at the destination.

**iOS trust.** A root installed by manually opening a profile is not trusted
for TLS until enabled under Settings > General > About > Certificate Trust
Settings; Apple Configurator, MDM, and enrollment profiles trust it
automatically. The profile format has no key to change this. To leave a root
(e.g. the `privoxy` root) under manual trust, deliver it in a separate profile.
Signed profiles show as verified only if the signer's chain is already trusted.

## Limitations

* Revocation is by CRL only (no OCSP). CRL lifetimes: root 365 days, others
  30; publish a CRL before it expires.
* No HSM or PKCS#11: keys are passphrase-encrypted files. Keep the root key
  offline; it is as exposed as the host that holds it.
* S/MIME encryption certificates are RSA: Apple Mail does not support ECDH
  encryption certificates.
* The signature check inside an installer cannot detect an editor who removes
  it; verify first with `bin/verify_installer.sh`.
* The KeePassXC database opens only with its master password and key file;
  losing either loses every key passphrase and `.p12` password.
* Installers, profiles and the login-keychain master are macOS only.

## Testing

`test/pki_test.sh` rebuilds the PKI in its own tree, then runs positive and
negative tests: chain, purpose, nameConstraints, revocation, supersession,
keychain, installers, profiles, permissions. It is destructive: it runs only
if `.pki_test_tree` exists or `PKI_TEST_DESTROY_PKI=1`, and deletes the tree's
PKI and `bin/create_organization_pki.sh`. Run it in a scratch tree made by
`replicate_pki_structure.sh`. It needs `keepassxc-cli` and macOS `security`;
the master goes into a throwaway keychain. `PKI_TEST_VERIFY_FLAGS` overrides
the `openssl verify` flags, `PKI_TEST_SMIME_NAME` selects the S/MIME identity.

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

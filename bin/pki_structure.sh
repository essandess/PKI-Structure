#!/usr/bin/env bash

# pki_structure.sh

# exit when any command fails
set -e

set -E   # make the ERR trap fire inside functions and subshells
set -o pipefail
shopt -s inherit_errexit
trap 'rc=$?; echo "Error: $(basename "$0") failed (exit ${rc}) at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

shopt -s nullglob
shopt -s nocasematch

umask 077
# Precaution to avoid overwriting/clearing an existing PKI structure
if [ -z ${CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY+x} ] \
       || [ "${CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY}" == "0" ] \
   ; then
    cat <<CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY
The variable CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY must be set to run
this script:

export CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY=1
CREATE_PKI_WITHIN_THIS_PKI_DIRECTORY
    exit 1    
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKI_ROOT}" || exit

. ./identity.env

SHOW_CERT_TEXT=${SHOW_CERT_TEXT:-1}

show_cert_text() {
    if [ "${SHOW_CERT_TEXT}" != "0" ]; then
        openssl x509 -noout -text -certopt ca_default -nameopt ca_default -in "$1"
    fi
}

CATRUE=${CATRUE:-1}
CERTDIR=${CERTDIR:-root}
CERTNAME=${CERTNAME:-root}
ISSUERCADIR=${ISSUERCADIR:-root}
ISSUERCANAME=${ISSUERCANAME:-root}

# # run creata_root.sh if no Root CA exists
# if [ $(basename $0) != "create_${ISSUERCANAME}.sh" ] \
# 	&& [ "${CERTDIR}" != "${ISSUERCADIR}" ] \
#        && ! [ -f "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".cert.pem ]; then
#     ./"create_${ISSUERCANAME}.sh"
# fi

# 12 years (plus leap days)
DAYS=${DAYS:-4383}

ALGORITHM=${ALGORITHM:-EC}
# https://soatok.blog/2022/05/19/guidance-for-choosing-an-elliptic-curve-signature-algorithm-in-2022/
EC_PARAMGEN_CURVE=${EC_PARAMGEN_CURVE:-P-384}
RSA_KEYGEN_BITS=${RSA_KEYGEN_BITS:-3072}

case ${EC_PARAMGEN_CURVE} in
    P-256|prime256v1)
	EC_HASH_DIGEST=${EC_HASH_DIGEST:-sha256}
	;;
    P-384|secp384r1)
	EC_HASH_DIGEST=${EC_HASH_DIGEST:-sha384}
	;;
    P-521|secp521r1)
	EC_HASH_DIGEST=${EC_HASH_DIGEST:-sha512}
	;;
    *)
	echo "Unknown curve '${EC_PARAMGEN_CURVE}'"
	exit 1
esac
case ${RSA_KEYGEN_BITS} in
    2048)
	RSA_HASH_DIGEST=${RSA_HASH_DIGEST:-sha256}
	;;
    3072)
	RSA_HASH_DIGEST=${RSA_HASH_DIGEST:-sha384}
	;;
    4096)
	RSA_HASH_DIGEST=${RSA_HASH_DIGEST:-sha512}
	;;
    *)
	echo "Nonstandard RSA bits '${RSA_KEYGEN_BITS}'"
	RSA_HASH_DIGEST=${RSA_HASH_DIGEST:-sha384}
esac
if [ "${ALGORITHM}" == "EC" ]; then
	HASH_DIGEST=${HASH_DIGEST:-${EC_HASH_DIGEST}}
elif [ "${ALGORITHM}" == "RSA" ]; then
	HASH_DIGEST=${HASH_DIGEST:-${RSA_HASH_DIGEST}}
fi

VERYCLEAN=0
CLEAN=0
HELP=0


POSITIONAL_ARGS_USAGE=${POSITIONAL_ARGS_USAGE:-}
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
	-a|--algorithm)
	    ALGORITHM=$2
	    if [[ ! "${ALGORITHM}" =~ ^EC|RSA$ ]]; then
		echo "Unknown algorithm '${ALGORITHM}'"
		exit 1
	    fi
	    shift; shift
	    ;;
	-c|--clean)
	    CLEAN=1
	    shift
	    ;;
	-vc|--veryclean)
	    VERYCLEAN=1
	    CLEAN=1
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

$(basename "$0") [-a|--algorithm [EC (default)|RSA]] [-h|--help] [-c|--clean] ${POSITIONAL_ARGS_USAGE}

Note that the file ./${CERTDIR}/private/passphrase.txt will be created,
if it does not exist, with two independent strong passphrases, one per
line: line 1 protects the private key, line 2 protects .p12 exports. See:
* man openssl-passphrase-options
* sf-pwgen --algorithm memorable --count 2 --length 16 | paste -s -d -- '-'
USEAGE
    exit 0
fi

if [ "${CLEAN}" == "0" ] \
      && ! [ "${CERTDIR}" = "${ISSUERCADIR}" -a "${CERTNAME}" = "${ISSUERCANAME}" ] \
      && ! [ -f "${ISSUERCADIR}"/certs/"${ISSUERCANAME}".cert.pem ]; then
    echo "Issuer certificate ${ISSUERCADIR}/certs/${ISSUERCANAME}.cert.pem doesn't exist."
    exit 1
fi

# clean everything if `--clean` set
if [ "${CLEAN}" == "1" ]; then
    read -p "This will delete existing keys and certificates in '${CERTDIR}'. Are you sure [y/N]? " -r
    echo    # (optional) move to a new line
    if [[ ! "${REPLY}" =~ ^[y]$ ]]; then
        echo "Aborted." >&2
	exit 1
    fi
    for f in \
	"${CERTDIR}"/private/*.key.pem \
	    "${CERTDIR}"/private/*.key.pem.decrypted \
	    "${CERTDIR}"/certs/*.*.pem \
	    "${CERTDIR}"/certs/*.cer \
	    "${CERTDIR}"/private/*.p12 \
	    "${CERTDIR}"/certs/*.csr.pem \
	    "${CERTDIR}"/index.txt* \
	    "${CERTDIR}"/serial* \
	    "${CERTDIR}"/crlnumber* \
	    "${CERTDIR}"/crl/* \
	    "${CERTDIR}"/newcerts/* \
	; do
	for ff in "${f[@]}"; do
	    if [ -f "${ff}" ]; then
		rm "${ff}"
	    fi
	done
    done
    if [ "${VERYCLEAN}" == "1" ]; then
	read -p "This will delete the existing passphrase in '${CERTDIR}'. Are you sure [y/N]? " -r
	echo    # (optional) move to a new line
	if [[ ! "${REPLY}" =~ ^[y]$ ]]; then
            echo "Aborted." >&2
	    exit 1
	fi
	for f in \
	    "${CERTDIR}"/private/passphrase.txt \
	; do
	for ff in "${f[@]}"; do
	    if [ -f "${ff}" ]; then
		rm "${ff}"
	    fi
	done
    done
    fi
    for d in \
	"${CERTDIR}"/certs \
	    "${CERTDIR}"/crl \
	    "${CERTDIR}"/newcerts \
	    "${CERTDIR}"/private \
	; do
        shopt -s nullglob dotglob
        d_files=("${d}"/*)
	if [ -d "${d}" ] && [[ "${#d_files[@]}" -eq 0 ]]; then
	    rmdir "${d}"
	fi
    done
    exit 0
fi

for f in \
    "${CERTDIR}"/private/"${CERTNAME}".key.pem \
	    "${CERTDIR}"/certs/"${CERTNAME}".cert.pem \
    ; do
    if [ -f "${f}" ]; then
	echo "CA file '${f}' already exists."
	exit 1
    fi
done

# check for nonexistence of existing CA
for d in "${CERTDIR}"/certs "${CERTDIR}"/private; do
    if ! [ -d "${d}" ]; then
	mkdir -p "${d}"
    fi
done

for f in "${CERTDIR}"/private/passphrase.txt; do
    if ! [ -f "${f}" ]; then
        # passphrase generation function created/destroyed every time
        _pki_generate_passphrase() {
            local newpassphrase="" passphrase="" char doit idx=0
            if command -v sf-pwgen >/dev/null 2>&1; then
                # no comment metacharacters in the passphrase
                passphrase=$(sf-pwgen --algorithm memorable --count 2 --length 16 | paste -s -d -- '-' | tr '#' '&' | tr '\' '/')
                # RanDoM caPitAlizaTioN
                while [[ ${idx} -lt "${#passphrase}" ]]; do
                    char="${passphrase:${idx}:1}"
                    doit=$(( RANDOM % 10 ))
                    if [ -z "$(echo "${char}" | sed -E 's|[[:lower:]]||')" ]; then
                        # 30% chance flip lowercase
                        if [ ${doit} -lt 3 ] ; then
                            char="$(echo "${char}" | tr '[[:lower:]]' '[[:upper:]]')"
                        fi
                    elif [ -z "$(echo "${char}" | sed -E 's|[[:upper:]]||')" ]; then
                        # 50% chance flip uppercase
                        if [ ${doit} -lt 5 ]; then
                            char="$(echo "${char}" | tr '[[:upper:]]' '[[:lower:]]')"
                        fi
                    fi
                    newpassphrase="${newpassphrase}${char}"
                    idx=$(( idx + 1 ))
                done
            else
                newpassphrase=$(openssl rand -base64 20 | cut -c 1-24)
            fi
            echo "${newpassphrase:-$passphrase}"
        }

        # Two independent secrets, one per line: line 1 protects the
        # private key (-passin), line 2 protects .p12 exports (-passout).
        # See openssl-passphrase-options(1) on file:pathname passed to
        # both -passin and -passout.
        PASSIN=$(_pki_generate_passphrase)
        PASSOUT=$(_pki_generate_passphrase)
        unset -f _pki_generate_passphrase
        touch "${f}"
        chmod go-rwx "${f}"
        printf '%s\n%s\n' "${PASSIN}" "${PASSOUT}" > "${f}"
        unset PASSIN PASSOUT
    fi
done

if ! [ "${CATRUE}" == "0" ]; then
    # create necessary directory/file structure
    for d in "${CERTDIR}"/certs "${CERTDIR}"/crl "${CERTDIR}"/newcerts; do
	if ! [ -d "${d}" ]; then
	    mkdir -p "${d}"
	fi
    done
    for f in "${CERTDIR}"/index.txt; do
	if ! [ -f "${f}" ]; then
	    touch "${f}"
	fi
    done
    for f in "${CERTDIR}"/serial; do
	if ! [ -f "${f}" ]; then
	    # serial must have an *even* number of characters
	    echo '01' > "${f}"
	fi
    done
fi

# check for existence of passphrase
for f in "${CERTDIR}"/private/passphrase.txt; do
    if ! [ -f "${f}" ]; then
	echo "Passphrase file '${f}' doesn't exist."
	exit 1
    fi
done

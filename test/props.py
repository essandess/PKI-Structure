"""props.py DOMAIN FQDN NAME=PEM...: check the extensions, key sizes and
lifetimes of the PKI's certificates; print each violation, exit 1 if any."""
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

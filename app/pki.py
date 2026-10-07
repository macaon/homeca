"""All X.509 building. Every cert goes through issue(), so SKI/AKI can't be forgotten."""
import ipaddress
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID as AIA_OID
from cryptography.x509.oid import ExtendedKeyUsageOID as EKU
from cryptography.x509.oid import NameOID

KEY_TYPES = ("ec256", "ec384", "rsa2048", "rsa3072", "rsa4096")
USAGES = ("server", "client", "both")
REASONS = ("unspecified", "key_compromise", "affiliation_changed", "superseded", "cessation_of_operation")
_NAME_ATTRS = (("c", NameOID.COUNTRY_NAME), ("st", NameOID.STATE_OR_PROVINCE_NAME),
               ("l", NameOID.LOCALITY_NAME), ("o", NameOID.ORGANIZATION_NAME),
               ("ou", NameOID.ORGANIZATIONAL_UNIT_NAME), ("cn", NameOID.COMMON_NAME))


def gen_key(kt):
    if kt == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    if kt == "ec384":
        return ec.generate_private_key(ec.SECP384R1())
    if kt in KEY_TYPES:
        return rsa.generate_private_key(65537, int(kt[3:]))
    raise ValueError(f"unknown key type {kt}")


def _hash(key):
    p384 = isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name == "secp384r1"
    return hashes.SHA384() if p384 else hashes.SHA256()


def make_name(s):
    return x509.Name([x509.NameAttribute(oid, s[k].strip()) for k, oid in _NAME_ATTRS if s.get(k, "").strip()])


def _gn(v, constraint=False):
    v = v.strip()
    if constraint and "/" in v:
        return x509.IPAddress(ipaddress.ip_network(v, strict=False))
    try:
        return x509.IPAddress(ipaddress.ip_address(v))
    except ValueError:
        pass
    if "@" in v:
        return x509.RFC822Name(v)
    # RFC 5280 DNS constraints have no leading dot ("home.arpa" already covers subdomains)
    return x509.DNSName(v.lstrip(".") if constraint else v)


def _ku(**kw):
    d = dict.fromkeys(("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
                       "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only"), False)
    return x509.KeyUsage(**{**d, **kw})


def issue(kind, subject, pub, signer_key, issuer_cert=None, days=365, *, sans=(), usage="server",
          path_len=0, permitted=(), cdp=None, aia=None):
    """kind: root|intermediate|leaf. issuer_cert=None means self-signed (signer_key is the cert's own key)."""
    now = datetime.now(timezone.utc)
    nb, na = now - timedelta(minutes=5), now + timedelta(days=days)
    if issuer_cert is not None:
        na = min(na, issuer_cert.not_valid_after_utc)
        if na <= now:
            raise ValueError("issuer certificate is expired")
    sn = make_name(subject)
    if not len(sn):
        raise ValueError("subject is empty")

    b = (x509.CertificateBuilder().subject_name(sn).issuer_name(issuer_cert.subject if issuer_cert else sn)
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), False))
    if issuer_cert is None:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(pub)
    else:
        iski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(iski)
    b = b.add_extension(aki, False)

    if kind in ("root", "intermediate"):
        b = b.add_extension(x509.BasicConstraints(True, None if kind == "root" else path_len), True)
        b = b.add_extension(_ku(key_cert_sign=True, crl_sign=True), True)
        if permitted:
            b = b.add_extension(x509.NameConstraints([_gn(p, True) for p in permitted], None), True)
    elif kind == "leaf":
        if usage not in USAGES:
            raise ValueError("bad usage")
        names = [s.strip() for s in sans if s.strip()]
        cn = subject.get("cn", "").strip()
        if usage != "client" and cn and cn.lower() not in (n.lower() for n in names):
            names.append(cn)
        if usage != "client" and not names:
            raise ValueError("server certificates need at least one SAN")
        b = b.add_extension(x509.BasicConstraints(False, None), True)
        b = b.add_extension(_ku(digital_signature=True, key_encipherment=isinstance(pub, rsa.RSAPublicKey)), True)
        ekus = ([EKU.SERVER_AUTH] if usage != "client" else []) + ([EKU.CLIENT_AUTH] if usage != "server" else [])
        b = b.add_extension(x509.ExtendedKeyUsage(ekus), False)
        if names:
            b = b.add_extension(x509.SubjectAlternativeName([_gn(n) for n in names]), False)
    else:
        raise ValueError("bad kind")

    if issuer_cert is not None and cdp:
        b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier(cdp)], None, None, None)]), False)
    if issuer_cert is not None and aia:
        b = b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(AIA_OID.CA_ISSUERS, x509.UniformResourceIdentifier(aia))]), False)
    return b.sign(signer_key, _hash(signer_key))


def csr_info(pem):
    """Parse + verify a CSR. Returns (csr, subject dict, sans list)."""
    csr = x509.load_pem_x509_csr(pem.encode())
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    attrs = {k: (csr.subject.get_attributes_for_oid(oid) or [None])[0] for k, oid in _NAME_ATTRS}
    subject = {k: a.value for k, a in attrs.items() if a}
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = [str(v) for v in san.get_values_for_type(x509.DNSName)] \
            + [str(v) for v in san.get_values_for_type(x509.IPAddress)] \
            + [str(v) for v in san.get_values_for_type(x509.RFC822Name)]
    except x509.ExtensionNotFound:
        sans = []
    return csr, subject, sans


def make_crl(ca_cert, ca_key, revoked, number, days=30):
    """revoked: iterable of (serial int, datetime, reason str)."""
    now = datetime.now(timezone.utc)
    iski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    b = (x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject)
         .last_update(now).next_update(now + timedelta(days=days))
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(iski), False)
         .add_extension(x509.CRLNumber(number), False))
    for serial, when, reason in revoked:
        rb = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when)
        if reason and reason != "unspecified":
            rb = rb.add_extension(x509.CRLReason(x509.ReasonFlags[reason]), False)
        b = b.add_revoked_certificate(rb.build())
    return b.sign(ca_key, _hash(ca_key))


def p12(cert, key, chain, password, name):
    enc = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    return pkcs12.serialize_key_and_certificates(name.encode(), key, cert, chain, enc)


def key_pem(key, passphrase=None):
    enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc).decode()


def describe(cert):
    """Human-readable extension list for the UI."""
    out = []
    for e in cert.extensions:
        v = e.value
        if isinstance(v, x509.SubjectKeyIdentifier):
            s = v.digest.hex(":")
        elif isinstance(v, x509.AuthorityKeyIdentifier):
            s = v.key_identifier.hex(":") if v.key_identifier else "(none)"
        elif isinstance(v, x509.BasicConstraints):
            s = f"CA:{str(v.ca).upper()}" + (f", pathlen:{v.path_length}" if v.path_length is not None else "")
        elif isinstance(v, x509.KeyUsage):
            s = ", ".join(n for n in ("digital_signature", "key_encipherment", "key_cert_sign", "crl_sign") if getattr(v, n))
        elif isinstance(v, x509.ExtendedKeyUsage):
            s = ", ".join(o._name for o in v)
        elif isinstance(v, x509.SubjectAlternativeName):
            s = ", ".join(str(g.value) for g in v)
        elif isinstance(v, x509.NameConstraints):
            s = "permitted: " + ", ".join(str(g.value) for g in v.permitted_subtrees or [])
        elif isinstance(v, x509.CRLDistributionPoints):
            s = ", ".join(u.value for d in v for u in d.full_name)
        elif isinstance(v, x509.AuthorityInformationAccess):
            s = ", ".join(a.access_location.value for a in v)
        else:
            s = str(v)
        out.append({"name": getattr(e.oid, "_name", e.oid.dotted_string), "critical": e.critical, "value": s})
    return out

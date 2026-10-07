"""Run: .venv/bin/python -m pytest tests  (or: .venv/bin/python tests/test_pki.py)"""
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import verification

sys.path.insert(0, str(Path(__file__).parent.parent))
from app import pki  # noqa: E402


def ski(c):
    return c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest


def aki(c):
    return c.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier


def chain():
    rk = pki.gen_key("ec384")
    root = pki.issue("root", {"cn": "Root"}, rk.public_key(), rk, days=3650)
    ik = pki.gen_key("ec256")
    inter = pki.issue("intermediate", {"cn": "Inter"}, ik.public_key(), rk, root, 1825,
                      permitted=[".home.arpa", "10.0.0.0/8"], cdp="http://ca/crl/1.crl", aia="http://ca/ca/1.crt")
    lk = pki.gen_key("rsa2048")
    leaf = pki.issue("leaf", {"cn": "nas.home.arpa"}, lk.public_key(), ik, inter, 90,
                     sans=["nas.home.arpa", "10.1.2.3"], cdp="http://ca/crl/2.crl")
    return rk, root, ik, inter, lk, leaf


def test_ski_aki_and_strict_verify():
    rk, root, ik, inter, lk, leaf = chain()
    assert aki(root) == ski(root)
    assert aki(inter) == ski(root)
    assert aki(leaf) == ski(inter)
    store = verification.Store([root])
    v = verification.PolicyBuilder().store(store).build_server_verifier(x509.DNSName("nas.home.arpa"))
    v.verify(leaf, [inter])
    assert leaf.not_valid_after_utc <= inter.not_valid_after_utc <= root.not_valid_after_utc


def test_csr_keeps_public_key():
    rk, root, *_ = chain()
    k = pki.gen_key("ec256")
    csr = (x509.CertificateSigningRequestBuilder().subject_name(pki.make_name({"cn": "router"}))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName("router.home.arpa")]), False)
           .sign(k, __import__("cryptography.hazmat.primitives.hashes", fromlist=["x"]).SHA256()))
    pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    c, subj, sans = pki.csr_info(pem)
    assert sans == ["router.home.arpa"]
    cert = pki.issue("leaf", subj, c.public_key(), rk, root, 30, sans=sans)
    assert cert.public_key().public_numbers() == k.public_key().public_numbers()


def test_crl_lists_revoked():
    rk, root, ik, inter, lk, leaf = chain()
    crl = pki.make_crl(inter, ik, [(leaf.serial_number, datetime.now(timezone.utc), "key_compromise")], 1)
    assert crl.get_revoked_certificate_by_serial_number(leaf.serial_number) is not None
    assert crl.is_signature_valid(inter.public_key())


def test_server_needs_san():
    k = pki.gen_key("ec256")
    try:
        pki.issue("leaf", {"o": "x"}, k.public_key(), k, None, 1)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f()
            print("ok", n)

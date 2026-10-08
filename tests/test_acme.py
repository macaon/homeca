"""Login, master key and ACME flow, against the app in-process. Tests share one database, in file order."""
import base64
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509 import verification
from fastapi.testclient import TestClient

from app import acme, ca, main, pki

b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
PW = "correct horse battery"
S = {}  # state shared between tests


@pytest.fixture(autouse=True)
def fast_login(monkeypatch):
    monkeypatch.setattr(main.time, "sleep", lambda _: None)


@pytest.fixture(scope="module")
def ui():
    return TestClient(main.app)


class Client:
    """Tiny ACME client: ES256 account key, JWS signing, nonce handling."""

    def __init__(self, ip="10.1.1.5"):
        self.tc = TestClient(main.app, base_url="https://ca.home.arpa:8443", client=(ip, 4000))
        self.key = ec.generate_private_key(ec.SECP256R1())
        pn = self.key.public_key().public_numbers()
        self.jwk = {"crv": "P-256", "kty": "EC", "x": b64(pn.x.to_bytes(32, "big")), "y": b64(pn.y.to_bytes(32, "big"))}
        self.dir = self.tc.get("/acme/directory").json()
        self.nonce = self.tc.head(self.dir["newNonce"]).headers["Replay-Nonce"]
        self.kid = None

    def post(self, url, payload, nonce=None, sign_url=None, jwk=False):
        prot = {"alg": "ES256", "nonce": nonce or self.nonce, "url": sign_url or url}
        prot.update({"jwk": self.jwk} if jwk or not self.kid else {"kid": self.kid})
        p64 = b64(json.dumps(prot).encode())
        d64 = "" if payload is None else b64(json.dumps(payload).encode())
        r_, s_ = decode_dss_signature(self.key.sign(f"{p64}.{d64}".encode(), ec.ECDSA(hashes.SHA256())))
        body = {"protected": p64, "payload": d64, "signature": b64(r_.to_bytes(32, "big") + s_.to_bytes(32, "big"))}
        r = self.tc.post(url, content=json.dumps(body), headers={"content-type": "application/jose+json"})
        self.nonce = r.headers.get("Replay-Nonce", self.nonce)
        return r

    def register(self):
        r = self.post(self.dir["newAccount"], {"termsOfServiceAgreed": True}, jwk=True)
        assert r.status_code == 201, r.text
        self.kid = r.headers["Location"]


def csr_der(names, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False)
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER), key


# ---------- login ----------
def test_setup_login_password(ui):
    assert ui.get("/api/state").json()["setup_needed"]
    assert ui.post("/api/setup", json={"username": "admin", "password": "short"}).status_code == 400
    assert ui.post("/api/setup", json={"username": "admin", "password": PW}).status_code == 200
    assert ui.post("/api/setup", json={"username": "x", "password": PW}).status_code == 409
    other = TestClient(main.app)
    assert other.post("/api/login", json={"username": "admin", "password": "wrong password!"}).status_code == 401
    assert other.post("/api/login", json={"username": "root", "password": PW}).status_code == 401
    assert other.post("/api/login", json={"username": "admin", "password": PW}).status_code == 200
    assert other.get("/api/certs").status_code == 200
    # changing the password signs out other sessions and keeps keys readable (they use the master key)
    assert ui.post("/api/password", json={"current": "nope nope nope", "new": "another long password"}).status_code == 403
    assert ui.post("/api/password", json={"current": PW, "new": "another long password"}).status_code == 200
    assert other.get("/api/certs").status_code == 401
    assert TestClient(main.app).post("/api/login", json={"username": "admin", "password": PW}).status_code == 401
    assert ui.post("/api/password", json={"current": "another long password", "new": PW}).status_code == 200


def test_master_key_checks(tmp_path, monkeypatch):
    good = ca.master()
    f = tmp_path / "k"
    f.write_text("a-different-master-key\n")
    monkeypatch.setattr(ca, "_master", None)
    monkeypatch.setenv("HOMECA_MASTER_KEY_FILE", str(f))
    with pytest.raises(RuntimeError, match="does not match"):
        ca.master()
    f.write_text("short")
    with pytest.raises(RuntimeError, match="12 characters"):
        ca.master()
    # an old install's passphrase works as the master key; a trailing newline is ignored
    f.write_text("test-master-key-123456\r\n")
    assert ca.master() == good


# ---------- ACME ----------
def test_acme_setup(ui):
    root = ui.post("/api/certs", json={"kind": "root", "subject": {"cn": "Test Root"}, "days": 3650}).json()["id"]
    inter = ui.post("/api/certs", json={"kind": "intermediate", "parent_id": root, "subject": {"cn": "Test Int"},
                                        "days": 1825, "permitted": ["home.arpa"]}).json()["id"]
    assert ui.post("/api/acme/ca", json={"id": root}).status_code == 400  # only intermediates
    bad = ui.post("/api/certs", json={"kind": "intermediate", "parent_id": root, "subject": {"cn": "Narrow"},
                                      "permitted": ["example.org"]}).json()["id"]
    assert ui.post("/api/acme/ca", json={"id": bad}).status_code == 400  # can't cover homeca's own hostname
    st = ui.post("/api/acme/ca", json={"id": inter}).json()
    assert st["enabled"] and st["directory"] == "https://ca.home.arpa:8443/acme/directory"
    S.update(root=root, inter=inter)


def test_acme_access_control():
    assert Client(ip="10.1.1.5").dir["newOrder"].endswith("/acme/new-order")
    r = TestClient(main.app, base_url="https://ca.home.arpa:8443", client=("10.9.9.9", 1)).get("/acme/directory")
    assert r.status_code == 403 and r.json()["type"].endswith(":unauthorized")


def test_full_flow(ui, monkeypatch):
    c = Client()
    c.register()
    # same key again returns the same account
    assert c.post(c.dir["newAccount"], {"onlyReturnExisting": True}, jwk=True).headers["Location"] == c.kid
    r = c.post(c.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "nas.home.arpa"}]})
    assert r.status_code == 201, r.text
    order_url, order = r.headers["Location"], r.json()
    assert order["status"] == "pending"
    authz = c.post(order["authorizations"][0], None).json()
    ch = authz["challenges"][0]
    assert ch["type"] == "http-01" and authz["status"] == "pending"

    # finalizing early is refused
    csr, key = csr_der(["nas.home.arpa"])
    r = c.post(order["finalize"], {"csr": b64(csr)})
    assert r.status_code == 403 and r.json()["type"].endswith(":orderNotReady")

    thumb = b64(hashlib.sha256(json.dumps(c.jwk, separators=(",", ":"), sort_keys=True).encode()).digest())
    seen = {}
    def fake(name, token, tp):
        seen.update(name=name, token=token, tp=tp)
        return True, None
    monkeypatch.setattr(acme, "validate_http01", fake)
    assert c.post(ch["url"], {}).json()["status"] == "valid"
    assert seen == {"name": "nas.home.arpa", "token": ch["token"], "tp": thumb}  # RFC 7638 thumbprint
    assert c.post(order_url, None).json()["status"] == "ready"

    # CSR with a name that's not in the order is refused
    bad, _ = csr_der(["nas.home.arpa", "evil.home.arpa"])
    assert c.post(order["finalize"], {"csr": b64(bad)}).json()["type"].endswith(":badCSR")

    r = c.post(order["finalize"], {"csr": b64(csr)})
    assert r.status_code == 200 and r.json()["status"] == "valid", r.text
    pem = c.post(r.json()["certificate"], None)
    assert pem.headers["content-type"] == "application/pem-certificate-chain"
    certs = x509.load_pem_x509_certificates(pem.content)
    assert len(certs) == 2  # leaf + intermediate, no root
    leaf, inter = certs
    root = x509.load_pem_x509_certificate(ui.get(f"/ca/{S['root']}.pem").content)
    assert leaf.public_key().public_numbers() == key.public_key().public_numbers()
    v = verification.PolicyBuilder().store(verification.Store([root])).build_server_verifier(x509.DNSName("nas.home.arpa"))
    v.verify(leaf, [inter])
    ski = lambda x: x.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest  # noqa: E731
    aki = lambda x: x.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier  # noqa: E731
    assert aki(leaf) == ski(inter)
    assert 89 <= (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days <= 90
    S["leaf"], S["acct"] = leaf, c

    row = next(x for x in ui.get("/api/certs").json() if x["cn"] == "nas.home.arpa")
    assert row["acme"] and not row["has_key"]
    assert ui.post(f"/api/certs/{row['id']}/renew").status_code == 400  # ACME certs renew via ACME
    S["leaf_id"] = row["id"]


def test_rejections(monkeypatch):
    c = Client()
    c.register()
    order = lambda *names: c.post(c.dir["newOrder"], {"identifiers": [{"type": "dns", "value": n} for n in names]})  # noqa: E731
    assert order("*.home.arpa").json()["type"].endswith(":rejectedIdentifier")
    assert order("host.example.org").json()["type"].endswith(":rejectedIdentifier")  # outside name constraints
    assert order("evilhome.arpa").json()["type"].endswith(":rejectedIdentifier")  # suffix match is label-aware
    assert c.post(c.dir["newOrder"], {"identifiers": [{"type": "ip", "value": "10.0.0.1"}]}).json()["type"].endswith(":unsupportedIdentifier")
    # url in the JWS must match the request, nonces are single-use
    assert c.post(c.dir["newOrder"], {"identifiers": []}, sign_url="https://ca.home.arpa:8443/acme/other").status_code == 401
    n = c.nonce
    assert c.post(c.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "a.home.arpa"}]}, nonce=n).status_code == 201
    r = c.post(c.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "a.home.arpa"}]}, nonce=n)
    assert r.json()["type"].endswith(":badNonce")
    # a failed challenge invalidates the authorization and the order
    o = order("fail.home.arpa").json()
    monkeypatch.setattr(acme, "validate_http01", lambda *a: (False, "nope"))
    ch = c.post(o["authorizations"][0], None).json()["challenges"][0]
    assert c.post(ch["url"], {}).json()["status"] == "invalid"
    # another account can't read someone else's order
    other = Client()
    other.register()
    assert other.post(o["authorizations"][0], None).status_code == 403


def test_revoke(ui):
    c, leaf = S["acct"], S["leaf"]
    der = leaf.public_bytes(serialization.Encoding.DER)
    stranger = Client()
    stranger.register()
    assert stranger.post(c.dir["revokeCert"], {"certificate": b64(der)}).status_code == 403
    assert c.post(c.dir["revokeCert"], {"certificate": b64(der), "reason": 4}).status_code == 200
    assert c.post(c.dir["revokeCert"], {"certificate": b64(der)}).json()["type"].endswith(":alreadyRevoked")
    crl = x509.load_der_x509_crl(ui.get(f"/crl/{S['inter']}.crl").content)
    entry = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    assert entry is not None and entry.extensions.get_extension_for_class(x509.CRLReason).value.reason == x509.ReasonFlags.superseded
    assert next(x for x in ui.get("/api/certs").json() if x["id"] == S["leaf_id"])["status"] == "revoked"


def test_self_tls_cert():
    from app.__main__ import ensure_tls
    cert, key, serial = ensure_tls()
    assert ensure_tls()[2] == serial  # reused until two-thirds of its life has passed
    leaf, inter = x509.load_pem_x509_certificates(Path(cert).read_bytes())
    assert leaf.subject.rfc4514_string() == "CN=ca.home.arpa"
    assert oct(os.stat(key).st_mode & 0o777) == "0o600"
    serialization.load_pem_private_key(Path(key).read_bytes(), None)

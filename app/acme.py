"""Minimal RFC 8555 ACME server: HTTP-01 only, DNS identifiers only, ES256/ES384/RS256 account keys.
Enough for certbot (and so Nginx Proxy Manager). Not implemented: keyChange, account order lists,
pre-authorization, external account binding."""
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import ssl
import threading
import urllib.error
import urllib.request
from datetime import timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import APIRouter, Body, Depends, Request, Response
from fastapi.responses import JSONResponse

from . import ca, pki
from .store import db

CLIENTS = [ipaddress.ip_network(x.strip(), strict=False)
           for x in os.environ.get("HOMECA_ACME_CLIENTS", "").split(",") if x.strip()]
HOSTNAME = os.environ.get("HOMECA_ACME_HOSTNAME", "").strip().lower()
TLS_PORT = int(os.environ.get("HOMECA_TLS_PORT", "8443"))
DAYS = int(os.environ.get("HOMECA_ACME_DAYS", "90"))
ORDER_TTL = timedelta(days=7)
NAME_RE = re.compile(r"(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")
REASON_CODES = {1: "key_compromise", 3: "affiliation_changed", 4: "superseded", 5: "cessation_of_operation"}


class AcmeError(Exception):
    def __init__(self, type, detail, status=400):
        self.type, self.detail, self.status = type, detail, status


def problem(request, exc):
    return JSONResponse({"type": f"urn:ietf:params:acme:error:{exc.type}", "detail": exc.detail},
                        status_code=exc.status, media_type="application/problem+json",
                        headers={"Replay-Nonce": new_nonce(), "Cache-Control": "no-store"})


# ---------- nonces ----------
# ponytail: in-memory, bounded; a restart invalidates them and clients retry on badNonce.
NONCES: dict[str, None] = {}
_lock = threading.Lock()


def new_nonce():
    n = secrets.token_urlsafe(16)
    with _lock:
        if len(NONCES) > 10000:
            for k in list(NONCES)[:5000]:
                del NONCES[k]
        NONCES[n] = None
    return n


def take_nonce(n):
    with _lock:
        return NONCES.pop(n, 1) is None


# ---------- access control ----------
def gate(request: Request):
    with db() as c:
        if ca.acme_ca(c) is None:
            raise AcmeError("serverInternal", "no CA is selected for ACME", 503)
    if not CLIENTS:
        raise AcmeError("unauthorized", "ACME is disabled: HOMECA_ACME_CLIENTS is empty", 403)
    try:
        ip = ipaddress.ip_address(request.client.host)
        ip = getattr(ip, "ipv4_mapped", None) or ip
    except (ValueError, AttributeError):
        raise AcmeError("unauthorized", "unknown client address", 403)
    if not any(ip in n for n in CLIENTS):
        raise AcmeError("unauthorized", f"{ip} is not an allowed ACME client", 403)


router = APIRouter(prefix="/acme", dependencies=[Depends(gate)])


# ---------- JWS ----------
def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk_key(jwk):
    try:
        if jwk["kty"] == "EC":
            curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}[jwk["crv"]]
            return ec.EllipticCurvePublicNumbers(int.from_bytes(b64d(jwk["x"]), "big"),
                                                 int.from_bytes(b64d(jwk["y"]), "big"), curve).public_key()
        if jwk["kty"] == "RSA":
            n = int.from_bytes(b64d(jwk["n"]), "big")
            if n.bit_length() >= 2048:
                return rsa.RSAPublicNumbers(int.from_bytes(b64d(jwk["e"]), "big"), n).public_key()
    except (KeyError, ValueError, TypeError):
        pass
    raise AcmeError("badPublicKey", "unsupported or invalid account key (EC P-256/P-384 or RSA 2048+)")


def thumbprint(jwk):
    keys = ("crv", "kty", "x", "y") if jwk["kty"] == "EC" else ("e", "kty", "n")
    return b64e(hashlib.sha256(json.dumps({k: jwk[k] for k in keys}, separators=(",", ":")).encode()).digest())


def check_sig(key, alg, data, sig):
    try:
        if alg in ("ES256", "ES384"):
            size, h, name = (32, hashes.SHA256(), "secp256r1") if alg == "ES256" else (48, hashes.SHA384(), "secp384r1")
            if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != name or len(sig) != 2 * size:
                raise InvalidSignature
            key.verify(encode_dss_signature(int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big")),
                       data, ec.ECDSA(h))
        elif alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise AcmeError("badSignatureAlgorithm", f"unsupported algorithm {alg}")
    except InvalidSignature:
        raise AcmeError("malformed", "JWS signature is invalid")


def base(request):
    return str(request.base_url).rstrip("/")


def verify(request, body, allow_jwk=False):
    """Validate a flattened JWS. Returns (payload dict | None for POST-as-GET, account row | None, jwk)."""
    try:
        prot_b64, pay_b64, sig = body["protected"], body["payload"], b64d(body["signature"])
        protected, raw = json.loads(b64d(prot_b64)), b64d(pay_b64)
        payload = json.loads(raw) if raw else None
        assert isinstance(protected, dict) and (payload is None or isinstance(payload, dict))
    except (KeyError, ValueError, TypeError, AssertionError):
        raise AcmeError("malformed", "request body is not a valid JWS")
    if protected.get("url") != str(request.url):
        raise AcmeError("unauthorized", "JWS url does not match the request URL", 401)
    if not take_nonce(str(protected.get("nonce", ""))):
        raise AcmeError("badNonce", "invalid or reused nonce")
    jwk, kid, account = protected.get("jwk"), protected.get("kid"), None
    if bool(jwk) == bool(kid) or (jwk and not allow_jwk):
        raise AcmeError("malformed", "exactly one of jwk/kid is required" if bool(jwk) == bool(kid)
                        else "this request must use kid")
    if kid:
        m = re.fullmatch(re.escape(base(request)) + r"/acme/acct/(\d+)", str(kid))
        with db() as c:
            account = m and c.execute("SELECT * FROM acme_accounts WHERE id=?", (int(m[1]),)).fetchone()
        if not account or account["status"] != "valid":
            raise AcmeError("accountDoesNotExist", "unknown or deactivated account")
        jwk = json.loads(account["jwk"])
    check_sig(jwk_key(jwk), protected.get("alg"), f"{prot_b64}.{pay_b64}".encode(), sig)
    return payload, account, jwk


def reply(request, data, status=200, **headers):
    return JSONResponse(data, status_code=status, headers={
        "Replay-Nonce": new_nonce(), "Cache-Control": "no-store",
        "Link": f'<{base(request)}/acme/directory>;rel="index"', **headers})


# ---------- resource helpers ----------
def url(request, kind, id):
    return f"{base(request)}/acme/{kind}/{id}"


def account_obj(request, a):
    return {"status": a["status"], "contact": json.loads(a["contact"] or "[]"),
            "orders": url(request, "acct", f"{a['id']}/orders")}


def order_obj(request, c, o):
    authz = c.execute("SELECT * FROM acme_authz WHERE order_id=? ORDER BY rowid", (o["id"],)).fetchall()
    status = o["status"]
    if status in ("pending", "ready"):
        sts = {a["status"] for a in authz}
        if ca.parse(o["expires"]) <= ca.now() or "invalid" in sts:
            status = "invalid"
        elif sts == {"valid"}:
            status = "ready"
        if status != o["status"]:
            c.execute("UPDATE acme_orders SET status=? WHERE id=?", (status, o["id"]))
    obj = {"status": status, "expires": o["expires"],
           "identifiers": [{"type": "dns", "value": a["name"]} for a in authz],
           "authorizations": [url(request, "authz", a["id"]) for a in authz],
           "finalize": url(request, "order", f"{o['id']}/finalize")}
    if o["cert_id"]:
        obj["certificate"] = url(request, "cert", o["cert_id"])
    return obj


def own_order(c, id, account):
    o = c.execute("SELECT * FROM acme_orders WHERE id=?", (id,)).fetchone()
    if not o or o["account_id"] != account["id"]:
        raise AcmeError("unauthorized", "no such order for this account", 403)
    return o


def authz_obj(request, a):
    ch = {"type": "http-01", "url": url(request, "chall", a["id"]), "token": a["token"], "status": a["status"]}
    obj = {"status": a["status"], "expires": a["expires"], "identifier": {"type": "dns", "value": a["name"]},
           "challenges": [ch]}
    if a["error"]:
        ch["error"] = {"type": "urn:ietf:params:acme:error:unauthorized", "detail": a["error"]}
    return obj


def own_authz(c, id, account):
    a = c.execute("SELECT * FROM acme_authz WHERE id=?", (id,)).fetchone()
    o = a and c.execute("SELECT * FROM acme_orders WHERE id=?", (a["order_id"],)).fetchone()
    if not a or o["account_id"] != account["id"]:
        raise AcmeError("unauthorized", "no such authorization for this account", 403)
    return a


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith(("http://", "https://")):
            raise urllib.error.URLError("redirect to an unsupported scheme")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_http01(name, token, thumb):
    """Fetch the challenge file. Returns (ok, error detail). Blocking; endpoints run in a thread pool."""
    u = f"http://{name}/.well-known/acme-challenge/{token}"
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # RFC 8555 §8.3: don't verify after an https redirect
    opener = urllib.request.build_opener(_Redirect, urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(urllib.request.Request(u, headers={"User-Agent": "homeca-acme"}), timeout=10) as r:
            got = r.read(4096).decode("ascii", "replace").strip()
    except Exception as e:  # noqa: BLE001 - any failure is just "validation failed"
        return False, f"could not fetch {u}: {e}"
    return (True, None) if got == f"{token}.{thumb}" else (False, f"{u} returned the wrong key authorization")


# ---------- endpoints ----------
@router.get("/directory")
def directory(request: Request):
    b = base(request) + "/acme"
    return reply(request, {"newNonce": f"{b}/new-nonce", "newAccount": f"{b}/new-account",
                           "newOrder": f"{b}/new-order", "revokeCert": f"{b}/revoke-cert",
                           "meta": {"externalAccountRequired": False}})


@router.api_route("/new-nonce", methods=["GET", "HEAD"])
def new_nonce_route(request: Request):
    return Response(status_code=200 if request.method == "HEAD" else 204,
                    headers={"Replay-Nonce": new_nonce(), "Cache-Control": "no-store"})


@router.post("/new-account")
def new_account(request: Request, body: dict = Body(...)):
    payload, _, jwk = verify(request, body, allow_jwk=True)
    payload = payload or {}
    tp = thumbprint(jwk)
    with db() as c:
        a = c.execute("SELECT * FROM acme_accounts WHERE thumbprint=?", (tp,)).fetchone()
        if a is None:
            if payload.get("onlyReturnExisting"):
                raise AcmeError("accountDoesNotExist", "no account for this key")
            contact = [x for x in payload.get("contact", []) if isinstance(x, str)][:5]
            cur = c.execute("INSERT INTO acme_accounts (jwk, thumbprint, contact, created) VALUES (?,?,?,?)",
                            (json.dumps(jwk), tp, json.dumps(contact), ca.iso(ca.now())))
            a = c.execute("SELECT * FROM acme_accounts WHERE id=?", (cur.lastrowid,)).fetchone()
            created = True
        else:
            created = False
    return reply(request, account_obj(request, a), 201 if created else 200, Location=url(request, "acct", a["id"]))


@router.post("/acct/{id}")
def account(id: int, request: Request, body: dict = Body(...)):
    payload, acct, _ = verify(request, body)
    if acct["id"] != id:
        raise AcmeError("unauthorized", "not your account", 403)
    if payload and payload.get("status") == "deactivated":
        with db() as c:
            c.execute("UPDATE acme_accounts SET status='deactivated' WHERE id=?", (id,))
        acct = {**dict(acct), "status": "deactivated"}
    return reply(request, account_obj(request, acct))


@router.post("/new-order")
def new_order(request: Request, body: dict = Body(...)):
    payload, acct, _ = verify(request, body)
    ids = (payload or {}).get("identifiers")
    if not isinstance(ids, list) or not 1 <= len(ids) <= 20:
        raise AcmeError("malformed", "identifiers must be a list of 1 to 20 entries")
    names = []
    for i in ids:
        if not isinstance(i, dict) or i.get("type") != "dns" or not isinstance(i.get("value"), str):
            raise AcmeError("unsupportedIdentifier", "only dns identifiers are supported")
        n = i["value"].strip().lower()
        if "*" in n:
            raise AcmeError("rejectedIdentifier", "wildcards need DNS-01, which homeca doesn't support")
        if not NAME_RE.fullmatch(n):
            raise AcmeError("rejectedIdentifier", f"{n!r} is not a valid host name")
        if n not in names:
            names.append(n)
    with db() as c:
        subtrees = ca.permitted_dns(ca.cert_of(ca.acme_ca(c)))
        for n in names:
            if not ca.name_allowed(n, subtrees):
                raise AcmeError("rejectedIdentifier", f"{n} is outside the names this CA may issue for")
        oid, exp = secrets.token_urlsafe(12), ca.iso(ca.now() + ORDER_TTL)
        c.execute("INSERT INTO acme_orders (id, account_id, status, identifiers, expires) VALUES (?,?,?,?,?)",
                  (oid, acct["id"], "pending", json.dumps(names), exp))
        for n in names:
            c.execute("INSERT INTO acme_authz (id, order_id, name, token, status, expires) VALUES (?,?,?,?,?,?)",
                      (secrets.token_urlsafe(12), oid, n, secrets.token_urlsafe(32), "pending", exp))
        obj = order_obj(request, c, own_order(c, oid, acct))
    return reply(request, obj, 201, Location=url(request, "order", oid))


@router.post("/order/{id}")
def order(id: str, request: Request, body: dict = Body(...)):
    _, acct, _ = verify(request, body)
    with db() as c:
        return reply(request, order_obj(request, c, own_order(c, id, acct)))


@router.post("/authz/{id}")
def authz(id: str, request: Request, body: dict = Body(...)):
    _, acct, _ = verify(request, body)
    with db() as c:
        return reply(request, authz_obj(request, own_authz(c, id, acct)))


@router.post("/chall/{id}")
def challenge(id: str, request: Request, body: dict = Body(...)):
    _, acct, _ = verify(request, body)
    with db() as c:
        a = own_authz(c, id, acct)
        if a["status"] == "pending" and ca.parse(a["expires"]) > ca.now():
            ok, err = validate_http01(a["name"], a["token"], thumbprint(json.loads(acct["jwk"])))
            c.execute("UPDATE acme_authz SET status=?, error=? WHERE id=?", ("valid" if ok else "invalid", err, id))
            a = own_authz(c, id, acct)
    return reply(request, authz_obj(request, a)["challenges"][0], Link=f'<{url(request, "authz", id)}>;rel="up"')


@router.post("/order/{id}/finalize")
def finalize(id: str, request: Request, body: dict = Body(...)):
    payload, acct, _ = verify(request, body)
    with db() as c:
        o = own_order(c, id, acct)
        if order_obj(request, c, o)["status"] != "ready":
            raise AcmeError("orderNotReady", "order is not ready; complete all challenges first", 403)
        names = json.loads(o["identifiers"])
        try:
            csr = x509.load_der_x509_csr(b64d(payload["csr"]))
            assert csr.is_signature_valid
            try:
                san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                if len(san) != len(san.get_values_for_type(x509.DNSName)):
                    raise AssertionError
                csr_names = {n.lower() for n in san.get_values_for_type(x509.DNSName)}
            except x509.ExtensionNotFound:
                csr_names = set()
            cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            csr_names |= {a.value.lower() for a in cn}
        except (KeyError, TypeError, ValueError, AssertionError):
            raise AcmeError("badCSR", "CSR is malformed, badly signed, or has non-DNS names")
        if csr_names != set(names):
            raise AcmeError("badCSR", "CSR names must match the order's identifiers exactly")
        pub = csr.public_key()
        if not (isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.name in ("secp256r1", "secp384r1")
                or isinstance(pub, rsa.RSAPublicKey) and pub.key_size >= 2048):
            raise AcmeError("badPublicKey", "use an EC P-256/P-384 or RSA 2048+ key")
        issuer = ca.acme_ca(c)
        cdp, aia = ca.urls(issuer["id"])
        try:
            cert = pki.issue("leaf", {"cn": names[0]}, pub, ca.key_of(issuer), ca.cert_of(issuer), DAYS,
                             sans=names, usage="server", cdp=cdp, aia=aia)
        except ValueError as e:
            raise AcmeError("serverInternal", str(e), 500)
        cid = ca.store_cert(c, "leaf", issuer["id"], cert, None,
                            {"subject": {"cn": names[0]}, "sans": names, "usage": "server", "acme": True,
                             "account": acct["id"]})
        c.execute("UPDATE acme_orders SET status='valid', cert_id=? WHERE id=?", (cid, id))
        obj = order_obj(request, c, own_order(c, id, acct))
    return reply(request, obj, Location=url(request, "order", id))


@router.post("/cert/{id}")
def certificate(id: int, request: Request, body: dict = Body(...)):
    _, acct, _ = verify(request, body)
    with db() as c:
        r = c.execute("SELECT * FROM certs WHERE id=?", (id,)).fetchone()
        if not r or json.loads(r["params"]).get("account") != acct["id"]:
            raise AcmeError("unauthorized", "no such certificate for this account", 403)
        pem = b"".join(x.public_bytes(serialization.Encoding.PEM)
                       for x in [ca.cert_of(r), *ca.chain(c, r)[:-1]])  # leaf + intermediates, root omitted
    return Response(pem, media_type="application/pem-certificate-chain",
                    headers={"Replay-Nonce": new_nonce(), "Cache-Control": "no-store"})


@router.post("/revoke-cert")
def revoke_cert(request: Request, body: dict = Body(...)):
    payload, acct, jwk = verify(request, body, allow_jwk=True)
    try:
        der = b64d(payload["certificate"])
        cert = x509.load_der_x509_certificate(der)
    except (KeyError, TypeError, ValueError):
        raise AcmeError("malformed", "certificate must be base64url DER")
    with db() as c:
        r = next((x for x in c.execute("SELECT * FROM certs WHERE serial=?", (format(cert.serial_number, "x"),))
                  if ca.cert_of(x).public_bytes(serialization.Encoding.DER) == der), None)
        if r is None or not json.loads(r["params"]).get("acme"):
            raise AcmeError("malformed", "unknown certificate (only ACME-issued certificates can be revoked here)")
        spki = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)  # noqa: E731
        if acct is not None:
            allowed = json.loads(r["params"]).get("account") == acct["id"]
        else:  # signed with the certificate's own key
            allowed = spki(jwk_key(jwk)) == spki(cert.public_key())
        if not allowed:
            raise AcmeError("unauthorized", "not authorized to revoke this certificate", 403)
        if r["revoked_at"]:
            raise AcmeError("alreadyRevoked", "certificate is already revoked")
        ca.revoke_cert(c, r["id"], REASON_CODES.get(payload.get("reason"), "unspecified"))
    return Response(status_code=200, headers={"Replay-Nonce": new_nonce(), "Cache-Control": "no-store"})


# ---------- for the UI ----------
def status(r):
    return {"enabled": bool(r and CLIENTS), "ca_id": r["id"] if r else None, "ca_cn": r["cn"] if r else None,
            "clients": [str(n) for n in CLIENTS], "hostname": HOSTNAME, "tls_port": TLS_PORT, "days": DAYS,
            "directory": f"https://{HOSTNAME}:{TLS_PORT}/acme/directory" if HOSTNAME else None}

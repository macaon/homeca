import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import Cookie, Depends, FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import pki
from .store import db

PUBLIC_URL = os.environ.get("HOMECA_PUBLIC_URL", "").rstrip("/")
SECURE = os.environ.get("HOMECA_SECURE_COOKIE") == "1"
STATIC = Path(__file__).parent / "static"
CRL_DAYS = 30
EXPIRING_DAYS = 30

app = FastAPI(title="homeca", docs_url=None, redoc_url=None)
# ponytail: in-memory sessions {token: passphrase bytes}; restart = re-login. Keys need unlocking anyway.
SESSIONS: dict[str, bytes] = {}


def now():
    return datetime.now(timezone.utc)


def iso(d):
    return d.isoformat()


def parse(s):
    return datetime.fromisoformat(s)


# ---------- auth ----------
def _hash_pw(pw, salt):
    return hashlib.scrypt(pw.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024).hex()


def _setting(c, k):
    r = c.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    return r["v"] if r else None


def session(homeca: str | None = Cookie(None)) -> bytes:
    if homeca not in SESSIONS:
        raise HTTPException(401, "not logged in")
    return SESSIONS[homeca]


class Pw(BaseModel):
    passphrase: str


def _login(r: Response, pw: str):
    tok = secrets.token_urlsafe(32)
    SESSIONS[tok] = pw.encode()
    r.set_cookie("homeca", tok, httponly=True, samesite="strict", secure=SECURE, max_age=12 * 3600)


@app.get("/api/state")
def state(homeca: str | None = Cookie(None)):
    with db() as c:
        return {"setup_needed": _setting(c, "pw_hash") is None, "logged_in": homeca in SESSIONS}


@app.post("/api/setup")
def setup(b: Pw, r: Response):
    if len(b.passphrase) < 12:
        raise HTTPException(400, "passphrase must be at least 12 characters")
    with db() as c:
        if _setting(c, "pw_hash") is not None:
            raise HTTPException(409, "already set up")
        salt = secrets.token_bytes(16)
        c.execute("INSERT INTO settings VALUES ('salt',?),('pw_hash',?)", (salt.hex(), _hash_pw(b.passphrase, salt)))
    _login(r, b.passphrase)
    return {}


@app.post("/api/login")
def login(b: Pw, r: Response):
    with db() as c:
        salt, h = _setting(c, "salt"), _setting(c, "pw_hash")
    if h is None or not hmac.compare_digest(_hash_pw(b.passphrase, bytes.fromhex(salt)), h):
        time.sleep(1)
        raise HTTPException(401, "wrong passphrase")
    _login(r, b.passphrase)
    _refresh_crls(b.passphrase.encode())
    return {}


@app.post("/api/logout")
def logout(r: Response, homeca: str | None = Cookie(None)):
    SESSIONS.pop(homeca, None)
    r.delete_cookie("homeca")
    return {}


# ---------- helpers ----------
def _row(c, id):
    r = c.execute("SELECT * FROM certs WHERE id=?", (id,)).fetchone()
    if not r:
        raise HTTPException(404, "no such certificate")
    return r


def _cert(r):
    return x509.load_pem_x509_certificate(r["cert_pem"].encode())


def _key(r, pw):
    if not r["key_enc"]:
        raise HTTPException(400, "private key is not stored (CSR-signed)")
    return serialization.load_pem_private_key(r["key_enc"].encode(), pw)


def _enc(key, pw):
    return pki.key_pem(key, pw)


def _status(r):
    if r["revoked_at"]:
        return "revoked", None
    days = (parse(r["not_after"]) - now()).days
    return ("expired" if days < 0 else "expiring" if days < EXPIRING_DAYS else "valid"), days


def _write_crl(c, ca_row, pw):
    ca = _cert(ca_row)
    revoked = [(int(x["serial"], 16), parse(x["revoked_at"]), x["revoke_reason"])
               for x in c.execute("SELECT * FROM certs WHERE parent_id=? AND revoked_at IS NOT NULL", (ca_row["id"],))]
    n = (ca_row["crl_number"] or 0) + 1
    crl = pki.make_crl(ca, _key(ca_row, pw), revoked, n, CRL_DAYS)
    c.execute("UPDATE certs SET crl_der=?, crl_next=?, crl_number=? WHERE id=?",
              (crl.public_bytes(serialization.Encoding.DER), iso(crl.next_update_utc), n, ca_row["id"]))


def _refresh_crls(pw):
    with db() as c:
        for r in c.execute("SELECT * FROM certs WHERE kind!='leaf' AND revoked_at IS NULL").fetchall():
            if parse(r["not_after"]) > now() and (not r["crl_next"] or (parse(r["crl_next"]) - now()).days < CRL_DAYS // 2):
                _write_crl(c, r, pw)


def _store(c, kind, parent_id, cert, key, pw, params):
    return c.execute(
        "INSERT INTO certs (parent_id,kind,cn,serial,not_before,not_after,cert_pem,key_enc,params) VALUES (?,?,?,?,?,?,?,?,?)",
        (parent_id, kind, params["subject"].get("cn", ""), format(cert.serial_number, "x"),
         iso(cert.not_valid_before_utc), iso(cert.not_valid_after_utc),
         cert.public_bytes(serialization.Encoding.PEM).decode(),
         _enc(key, pw) if key else None, json.dumps(params))).lastrowid


def _parent(c, parent_id, kind):
    r = _row(c, parent_id)
    if r["kind"] == "leaf" or r["revoked_at"]:
        raise HTTPException(400, "parent is not a usable CA")
    if kind == "intermediate":
        pl = _cert(r).extensions.get_extension_for_class(x509.BasicConstraints).value.path_length
        if pl == 0:
            raise HTTPException(400, "parent CA has pathlen:0 and cannot issue intermediates")
    return r


def _urls(parent_id):
    if not PUBLIC_URL:
        return None, None
    return f"{PUBLIC_URL}/crl/{parent_id}.crl", f"{PUBLIC_URL}/ca/{parent_id}.crt"


def _issue(c, pw, kind, parent_id, subject, pub, key, params, days):
    """Issue + persist; maps validation problems to HTTP 400."""
    p = params
    try:
        if parent_id is None:
            cert = pki.issue("root", subject, pub, key, None, days)
        else:
            pr = _parent(c, parent_id, kind)
            pl = p.get("path_len", 0)
            ppl = _cert(pr).extensions.get_extension_for_class(x509.BasicConstraints).value.path_length
            if ppl is not None:
                pl = min(pl, ppl - 1)
            cdp, aia = _urls(parent_id)
            cert = pki.issue(kind, subject, pub, _key(pr, pw), _cert(pr), days, sans=p.get("sans", []),
                             usage=p.get("usage", "server"), path_len=pl, permitted=p.get("permitted", []),
                             cdp=cdp, aia=aia)
    except ValueError as e:
        raise HTTPException(400, str(e))
    cid = _store(c, kind, parent_id, cert, key, pw, params)
    if kind != "leaf":
        _write_crl(c, _row(c, cid), pw)
    return cid


# ---------- certs ----------
class NewCert(BaseModel):
    kind: str = Field(pattern="^(root|intermediate|leaf)$")
    parent_id: int | None = None
    subject: dict[str, str]
    sans: list[str] = []
    key_type: str = "ec256"
    days: int = Field(365, ge=1, le=36500)
    path_len: int = Field(0, ge=0, le=10)
    permitted: list[str] = []
    usage: str = "server"


class SignCsr(BaseModel):
    parent_id: int
    csr_pem: str
    sans: list[str] | None = None
    days: int = Field(365, ge=1, le=36500)
    usage: str = "server"


@app.get("/api/certs")
def list_certs(_: bytes = Depends(session)):
    with db() as c:
        rows = c.execute("SELECT * FROM certs").fetchall()
    out = []
    for r in rows:
        st, days = _status(r)
        p = json.loads(r["params"])
        newer = any(o["parent_id"] == r["parent_id"] and o["cn"] == r["cn"] and o["id"] != r["id"] and not o["revoked_at"]
                    and o["kind"] == "leaf" and o["not_after"] > r["not_after"] for o in rows)
        out.append({"id": r["id"], "parent_id": r["parent_id"], "kind": r["kind"], "cn": r["cn"],
                    "not_after": r["not_after"], "status": st, "days_left": days, "superseded": newer,
                    "sans": p.get("sans", []), "has_key": bool(r["key_enc"]), "crl_next": r["crl_next"]})
    return out


@app.get("/api/certs/{id}")
def get_cert(id: int, _: bytes = Depends(session)):
    with db() as c:
        r = _row(c, id)
    cert = _cert(r)
    st, days = _status(r)
    fp = lambda h: cert.fingerprint(h).hex(":")  # noqa: E731
    return {"id": id, "kind": r["kind"], "parent_id": r["parent_id"], "status": st, "days_left": days,
            "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "serial": r["serial"], "not_before": r["not_before"], "not_after": r["not_after"],
            "revoked_at": r["revoked_at"], "revoke_reason": r["revoke_reason"], "has_key": bool(r["key_enc"]),
            "sha256": fp(hashes.SHA256()), "extensions": pki.describe(cert), "params": json.loads(r["params"])}


@app.post("/api/certs")
def create(b: NewCert, pw: bytes = Depends(session)):
    if (b.kind == "root") != (b.parent_id is None):
        raise HTTPException(400, "root has no parent; intermediate/leaf need one")
    if b.key_type not in pki.KEY_TYPES:
        raise HTTPException(400, "bad key type")
    params = b.model_dump(exclude={"parent_id", "days"})
    key = pki.gen_key(b.key_type)
    with db() as c:
        return {"id": _issue(c, pw, b.kind, b.parent_id, b.subject, key.public_key(), key, params, b.days)}


@app.post("/api/certs/sign-csr")
def sign_csr(b: SignCsr, pw: bytes = Depends(session)):
    try:
        csr, subject, csr_sans = pki.csr_info(b.csr_pem)
    except ValueError as e:
        raise HTTPException(400, str(e))
    sans = csr_sans if b.sans is None else b.sans
    params = {"subject": subject, "sans": sans, "usage": b.usage, "csr": True}
    with db() as c:
        return {"id": _issue(c, pw, "leaf", b.parent_id, subject, csr.public_key(), None, params, b.days)}


@app.post("/api/certs/{id}/renew")
def renew(id: int, pw: bytes = Depends(session)):
    with db() as c:
        r = _row(c, id)
        if r["kind"] != "leaf":
            raise HTTPException(400, "only leaf certificates can be renewed")
        p = json.loads(r["params"])
        days = (parse(r["not_after"]) - parse(r["not_before"])).days
        # new key if we hold one; CSR-signed certs keep the device's public key
        key = pki.gen_key(p["key_type"]) if r["key_enc"] else None
        pub = key.public_key() if key else _cert(r).public_key()
        return {"id": _issue(c, pw, "leaf", r["parent_id"], p["subject"], pub, key, p, max(days, 1))}


class Revoke(BaseModel):
    reason: str = "unspecified"


@app.post("/api/certs/{id}/revoke")
def revoke(id: int, b: Revoke, pw: bytes = Depends(session)):
    if b.reason not in pki.REASONS:
        raise HTTPException(400, "bad reason")
    with db() as c:
        r = _row(c, id)
        if r["parent_id"] is None:
            raise HTTPException(400, "a root CA has no issuer to publish its revocation")
        if r["revoked_at"]:
            raise HTTPException(409, "already revoked")
        c.execute("UPDATE certs SET revoked_at=?, revoke_reason=? WHERE id=?", (iso(now()), b.reason, id))
        _write_crl(c, _row(c, r["parent_id"]), pw)
    return {}


@app.delete("/api/certs/{id}")
def delete(id: int, _: bytes = Depends(session)):
    with db() as c:
        if c.execute("SELECT 1 FROM certs WHERE parent_id=?", (id,)).fetchone():
            raise HTTPException(409, "has issued certificates; delete those first")
        c.execute("DELETE FROM certs WHERE id=?", (id,))
    return {}


def _chain(c, r):
    out = []
    while r["parent_id"] is not None:
        r = _row(c, r["parent_id"])
        out.append(_cert(r))
    return out


@app.get("/api/certs/{id}/download")
def download(id: int, format: str = "pem", pw_p12: str = "", pw: bytes = Depends(session)):
    PEM = serialization.Encoding.PEM
    with db() as c:
        r = _row(c, id)
        cert, chain = _cert(r), _chain(c, r)
        name = (r["cn"] or "cert").replace("/", "_").replace(" ", "_")
        if format == "pem":
            body, mt, ext = cert.public_bytes(PEM), "application/x-pem-file", "crt"
        elif format == "der":
            body, mt, ext = cert.public_bytes(serialization.Encoding.DER), "application/pkix-cert", "der"
        elif format == "chain":
            body = b"".join(x.public_bytes(PEM) for x in [cert, *chain])
            mt, ext = "application/x-pem-file", "chain.pem"
        elif format == "key":
            body, mt, ext = pki.key_pem(_key(r, pw)).encode(), "application/x-pem-file", "key"
        elif format == "p12":
            body = pki.p12(cert, _key(r, pw), chain, pw_p12, name)
            mt, ext = "application/x-pkcs12", "p12"
        else:
            raise HTTPException(400, "bad format")
    return Response(body, media_type=mt, headers={"Content-Disposition": f'attachment; filename="{name}.{ext}"'})


# ---------- public (devices fetch these; no login) ----------
@app.get("/crl/{id}.crl")
def crl(id: int):
    with db() as c:
        r = _row(c, id)
    if not r["crl_der"]:
        raise HTTPException(404, "no CRL")
    return Response(r["crl_der"], media_type="application/pkix-crl")


@app.get("/ca/{id}.crt")
def ca_der(id: int):
    with db() as c:
        r = _row(c, id)
    if r["kind"] == "leaf":
        raise HTTPException(404)
    return Response(_cert(r).public_bytes(serialization.Encoding.DER), media_type="application/pkix-cert")


@app.get("/ca/{id}.pem")
def ca_pem(id: int):
    with db() as c:
        r = _row(c, id)
    if r["kind"] == "leaf":
        raise HTTPException(404)
    return Response(r["cert_pem"], media_type="application/x-pem-file")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")

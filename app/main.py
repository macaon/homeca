import asyncio
import hmac
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import Cookie, Depends, FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import acme, pki
from .ca import (cert_of, chain, hash_pw, iso, key_of, now, parse, revoke_cert, row, set_setting, setting,
                 status_of, store_cert, urls, write_crl)
from . import ca
from .store import db

SECURE = os.environ.get("HOMECA_SECURE_COOKIE") == "1"
STATIC = Path(__file__).parent / "static"


async def _daily():
    while True:
        try:
            await asyncio.to_thread(ca.refresh_crls)
        except Exception as e:  # keep the loop alive; the dashboard shows CRL expiry
            print("CRL refresh failed:", e, flush=True)
        await asyncio.sleep(86400)


_daily_started = False


@asynccontextmanager
async def lifespan(_):
    global _daily_started
    ca.master()  # fail fast on a missing or wrong master key
    task = None
    if not _daily_started:  # the HTTP and HTTPS servers share this app; run the job once
        _daily_started = True
        task = asyncio.create_task(_daily())
    yield
    if task:
        task.cancel()


app = FastAPI(title="homeca", docs_url=None, redoc_url=None, lifespan=lifespan)
app.include_router(acme.router)
app.add_exception_handler(acme.AcmeError, acme.problem)
# ponytail: in-memory sessions {token: username}; restart = re-login.
SESSIONS: dict[str, str] = {}


# ---------- auth ----------
def session(homeca: str | None = Cookie(None)) -> str:
    if homeca not in SESSIONS:
        raise HTTPException(401, "not logged in")
    return SESSIONS[homeca]


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str


class PwChange(BaseModel):
    current: str
    new: str


def _login(r: Response, user: str):
    tok = secrets.token_urlsafe(32)
    SESSIONS[tok] = user
    r.set_cookie("homeca", tok, httponly=True, samesite="strict", secure=SECURE, max_age=12 * 3600)


def _set_admin(c, user, pw):
    if len(pw) < 12:
        raise HTTPException(400, "password must be at least 12 characters")
    salt = secrets.token_bytes(16)
    set_setting(c, "admin_user", user)
    set_setting(c, "admin_salt", salt.hex())
    set_setting(c, "admin_hash", hash_pw(pw, salt))


def _check_admin(c, user, pw):
    h, salt, u = setting(c, "admin_hash"), setting(c, "admin_salt"), setting(c, "admin_user")
    if h is None:
        return False
    ok_pw = hmac.compare_digest(hash_pw(pw, bytes.fromhex(salt)), h)  # always hash, whatever the username
    return ok_pw and hmac.compare_digest((user or "").encode(), u.encode())


@app.get("/api/state")
def state(homeca: str | None = Cookie(None)):
    with db() as c:
        return {"setup_needed": setting(c, "admin_hash") is None, "logged_in": homeca in SESSIONS,
                "user": SESSIONS.get(homeca)}


@app.post("/api/setup")
def setup(b: Login, r: Response):
    with db() as c:
        if setting(c, "admin_hash") is not None:
            raise HTTPException(409, "already set up")
        _set_admin(c, b.username.strip(), b.password)
    _login(r, b.username.strip())
    return {}


@app.post("/api/login")
def login(b: Login, r: Response):
    with db() as c:
        ok = _check_admin(c, b.username.strip(), b.password)
    if not ok:
        time.sleep(1)
        raise HTTPException(401, "wrong username or password")
    _login(r, b.username.strip())
    return {}


@app.post("/api/password")
def change_password(b: PwChange, user: str = Depends(session), homeca: str | None = Cookie(None)):
    with db() as c:
        if not _check_admin(c, user, b.current):
            time.sleep(1)
            raise HTTPException(403, "current password is wrong")  # not 401: that means "session expired" to the UI
        _set_admin(c, user, b.new)
    for t in [t for t in SESSIONS if t != homeca]:  # sign out everywhere else
        del SESSIONS[t]
    return {}


@app.post("/api/logout")
def logout(r: Response, homeca: str | None = Cookie(None)):
    SESSIONS.pop(homeca, None)
    r.delete_cookie("homeca")
    return {}


# ---------- issuing ----------
def _parent(c, parent_id, kind):
    r = row(c, parent_id)
    if r["kind"] == "leaf" or r["revoked_at"]:
        raise HTTPException(400, "parent is not a usable CA")
    if kind == "intermediate":
        pl = cert_of(r).extensions.get_extension_for_class(x509.BasicConstraints).value.path_length
        if pl == 0:
            raise HTTPException(400, "parent CA has pathlen:0 and cannot issue intermediates")
    return r


def _issue(c, kind, parent_id, subject, pub, key, params, days):
    """Issue + persist; maps validation problems to HTTP 400."""
    p = params
    try:
        if parent_id is None:
            cert = pki.issue("root", subject, pub, key, None, days)
        else:
            pr = _parent(c, parent_id, kind)
            pl = p.get("path_len", 0)
            ppl = cert_of(pr).extensions.get_extension_for_class(x509.BasicConstraints).value.path_length
            if ppl is not None:
                pl = min(pl, ppl - 1)
            cdp, aia = urls(parent_id)
            cert = pki.issue(kind, subject, pub, key_of(pr), cert_of(pr), days, sans=p.get("sans", []),
                             usage=p.get("usage", "server"), path_len=pl, permitted=p.get("permitted", []),
                             cdp=cdp, aia=aia)
    except ValueError as e:
        raise HTTPException(400, str(e))
    cid = store_cert(c, kind, parent_id, cert, key, params)
    if kind != "leaf":
        write_crl(c, row(c, cid))
    return cid


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
def list_certs(_: str = Depends(session)):
    with db() as c:
        rows = c.execute("SELECT * FROM certs").fetchall()
    out = []
    for r in rows:
        st, days = status_of(r)
        p = json.loads(r["params"])
        newer = any(o["parent_id"] == r["parent_id"] and o["cn"] == r["cn"] and o["id"] != r["id"] and not o["revoked_at"]
                    and o["kind"] == "leaf" and o["not_after"] > r["not_after"] for o in rows)
        out.append({"id": r["id"], "parent_id": r["parent_id"], "kind": r["kind"], "cn": r["cn"],
                    "not_after": r["not_after"], "status": st, "days_left": days, "superseded": newer,
                    "sans": p.get("sans", []), "has_key": bool(r["key_enc"]), "crl_next": r["crl_next"],
                    "acme": bool(p.get("acme")), "self": bool(p.get("self"))})
    return out


@app.get("/api/certs/{id}")
def get_cert(id: int, _: str = Depends(session)):
    with db() as c:
        r = row(c, id)
    cert = cert_of(r)
    st, days = status_of(r)
    p = json.loads(r["params"])
    return {"id": id, "kind": r["kind"], "parent_id": r["parent_id"], "status": st, "days_left": days,
            "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "serial": r["serial"], "not_before": r["not_before"], "not_after": r["not_after"],
            "revoked_at": r["revoked_at"], "revoke_reason": r["revoke_reason"], "has_key": bool(r["key_enc"]),
            "sha256": cert.fingerprint(hashes.SHA256()).hex(":"), "extensions": pki.describe(cert), "params": p,
            "acme": bool(p.get("acme")), "self": bool(p.get("self"))}


@app.post("/api/certs")
def create(b: NewCert, _: str = Depends(session)):
    if (b.kind == "root") != (b.parent_id is None):
        raise HTTPException(400, "root has no parent; intermediate/leaf need one")
    if b.key_type not in pki.KEY_TYPES:
        raise HTTPException(400, "bad key type")
    params = b.model_dump(exclude={"parent_id", "days"})
    key = pki.gen_key(b.key_type)
    with db() as c:
        return {"id": _issue(c, b.kind, b.parent_id, b.subject, key.public_key(), key, params, b.days)}


@app.post("/api/certs/sign-csr")
def sign_csr(b: SignCsr, _: str = Depends(session)):
    try:
        csr, subject, csr_sans = pki.csr_info(b.csr_pem)
    except ValueError as e:
        raise HTTPException(400, str(e))
    sans = csr_sans if b.sans is None else b.sans
    params = {"subject": subject, "sans": sans, "usage": b.usage, "csr": True}
    with db() as c:
        return {"id": _issue(c, "leaf", b.parent_id, subject, csr.public_key(), None, params, b.days)}


@app.post("/api/certs/{id}/renew")
def renew(id: int, _: str = Depends(session)):
    with db() as c:
        r = row(c, id)
        if r["kind"] != "leaf":
            raise HTTPException(400, "only leaf certificates can be renewed")
        p = json.loads(r["params"])
        if p.get("acme") or p.get("self"):
            raise HTTPException(400, "this certificate is renewed automatically through ACME")
        days = (parse(r["not_after"]) - parse(r["not_before"])).days
        # new key if we hold one; CSR-signed certs keep the device's public key
        key = pki.gen_key(p["key_type"]) if r["key_enc"] else None
        pub = key.public_key() if key else cert_of(r).public_key()
        return {"id": _issue(c, "leaf", r["parent_id"], p["subject"], pub, key, p, max(days, 1))}


class Revoke(BaseModel):
    reason: str = "unspecified"


@app.post("/api/certs/{id}/revoke")
def revoke(id: int, b: Revoke, _: str = Depends(session)):
    if b.reason not in pki.REASONS:
        raise HTTPException(400, "bad reason")
    with db() as c:
        revoke_cert(c, id, b.reason)
    return {}


@app.delete("/api/certs/{id}")
def delete(id: int, _: str = Depends(session)):
    with db() as c:
        if c.execute("SELECT 1 FROM certs WHERE parent_id=?", (id,)).fetchone():
            raise HTTPException(409, "has issued certificates; delete those first")
        c.execute("DELETE FROM certs WHERE id=?", (id,))
    return {}


@app.get("/api/certs/{id}/download")
def download(id: int, format: str = "pem", pw_p12: str = "", _: str = Depends(session)):
    PEM = serialization.Encoding.PEM
    with db() as c:
        r = row(c, id)
        cert, anc = cert_of(r), chain(c, r)
        name = (r["cn"] or "cert").replace("/", "_").replace(" ", "_")
        if format == "pem":
            body, mt, ext = cert.public_bytes(PEM), "application/x-pem-file", "crt"
        elif format == "der":
            body, mt, ext = cert.public_bytes(serialization.Encoding.DER), "application/pkix-cert", "der"
        elif format == "chain":
            body = b"".join(x.public_bytes(PEM) for x in [cert, *anc])
            mt, ext = "application/x-pem-file", "chain.pem"
        elif format == "key":
            body, mt, ext = pki.key_pem(key_of(r)).encode(), "application/x-pem-file", "key"
        elif format == "p12":
            body = pki.p12(cert, key_of(r), anc, pw_p12, name)
            mt, ext = "application/x-pkcs12", "p12"
        else:
            raise HTTPException(400, "bad format")
    return Response(body, media_type=mt, headers={"Content-Disposition": f'attachment; filename="{name}.{ext}"'})


# ---------- ACME admin ----------
class AcmeCa(BaseModel):
    id: int | None = None


@app.get("/api/acme")
def acme_status(_: str = Depends(session)):
    with db() as c:
        return acme.status(ca.acme_ca(c))


@app.post("/api/acme/ca")
def acme_set_ca(b: AcmeCa, _: str = Depends(session)):
    with db() as c:
        if b.id is None:
            set_setting(c, "acme_ca_id", "")
        else:
            r = row(c, b.id)
            if r["kind"] != "intermediate" or r["revoked_at"] or parse(r["not_after"]) <= now():
                raise HTTPException(400, "choose a valid intermediate CA")
            host = acme.HOSTNAME
            if host and not ca.name_allowed(host, ca.permitted_dns(cert_of(r))):
                raise HTTPException(400, f"this CA's name constraints don't permit {host}, "
                                         "which homeca needs for its own TLS certificate")
            set_setting(c, "acme_ca_id", str(b.id))
        return acme.status(ca.acme_ca(c))


# ---------- public (devices fetch these; no login) ----------
@app.get("/crl/{id}.crl")
def crl(id: int):
    with db() as c:
        r = row(c, id)
    if not r["crl_der"]:
        raise HTTPException(404, "no CRL")
    return Response(r["crl_der"], media_type="application/pkix-crl")


@app.get("/ca/{id}.crt")
def ca_der(id: int):
    with db() as c:
        r = row(c, id)
    if r["kind"] == "leaf":
        raise HTTPException(404)
    return Response(cert_of(r).public_bytes(serialization.Encoding.DER), media_type="application/pkix-cert")


@app.get("/ca/{id}.pem")
def ca_pem(id: int):
    with db() as c:
        r = row(c, id)
    if r["kind"] == "leaf":
        raise HTTPException(404)
    return Response(r["cert_pem"], media_type="application/x-pem-file")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")

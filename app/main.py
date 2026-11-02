import asyncio
import hmac
import json
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from . import acme, pki
from .ca import (cert_of, chain, hash_pw, iso, key_of, now, parse, revoke_cert, row, set_setting, setting,
                 status_of, store_cert, urls, write_crl)
from . import ca, preferences
from .store import db
from . import accounts, apitokens, auditlog
from .auditlog import audit
from .home_security import LoginGuard, parse_networks

SECURE = os.environ.get("HOMECA_SECURE_COOKIE") == "1"
STATIC = Path(__file__).parent / "static"
if not ca.PUBLIC_URLS:
    print("WARNING: HOMECA_PUBLIC_URL is not set; issued certificates will have no CRL or CA-issuer URL, "
          "so clients cannot check revocation or fetch the chain.", flush=True)

# ---------- legacy deployment defaults; UI settings take precedence ----------
OIDC_ISSUER = os.environ.get("HOMECA_OIDC_ISSUER")
OIDC_CLIENT_ID = os.environ.get("HOMECA_OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET_FILE = os.environ.get("HOMECA_OIDC_CLIENT_SECRET_FILE")
OIDC_ADMIN_MATCH = os.environ.get("HOMECA_OIDC_ADMIN_MATCH")
OIDC_CA_FILE = os.environ.get("HOMECA_OIDC_CA_FILE")  # only needed if the IdP's cert is from a private CA


async def _daily():
    while True:
        try:
            await asyncio.to_thread(ca.refresh_crls)
        except Exception as e:  # keep the loop alive; the dashboard shows CRL expiry
            print("CRL refresh failed:", e, flush=True)
            audit("system", "CRL refresh failed", detail=str(e)[:200])
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
ca.master()  # load the master key now (fails fast), never in the middle of a database transaction
# ponytail: in-memory sessions {token: username}; restart = re-login.
SESSIONS: dict[str, str] = {}
# Always installed: OIDC can now be configured without restarting the server.
app.add_middleware(SessionMiddleware, secret_key=ca.derived_secret(b"homeca oidc session v1"),
                   session_cookie="homeca_oidc", same_site="lax", https_only=SECURE, max_age=600)


# ---------- auth ----------
def session(homeca: str | None = Cookie(None)) -> str:
    if homeca not in SESSIONS:
        raise HTTPException(401, "not logged in")
    user = SESSIONS[homeca]
    with db() as c:
        if not accounts.exists(c,user):
            SESSIONS.pop(homeca,None)
            raise HTTPException(401,"Account no longer exists")
    return user


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
    accounts.save_password(c,user,pw)


def _check_admin(c, user, pw):
    return accounts.check_password(c,user,pw)


accounts.register(app,session,SESSIONS,_set_admin)
auditlog.register(app,session)
# Sign-ins are limited per source and account. HOMECA_TRUSTED_PROXIES lists the reverse proxy's address or network
# (e.g. 172.28.0.1); only requests from it may name the real client in X-Forwarded-For. This is separate from
# uvicorn's proxy_headers, which stays off: the ACME client allowlist must keep seeing the real peer address.
TRUSTED_PROXIES = parse_networks(os.environ.get("HOMECA_TRUSTED_PROXIES", ""))
guard = LoginGuard(TRUSTED_PROXIES, on_block=lambda username, source: audit(username, "Sign-in blocked", detail=source + " · too many attempts"))
read = apitokens.register(app, session, TRUSTED_PROXIES)  # session or read-only API token


def _local_account(username):
    if not username:return False
    with db() as c:
        accounts.ensure(c)
        row=c.execute("SELECT password FROM users WHERE username=?",(username,)).fetchone()
        return bool(row and row['password'])


@app.get("/api/state")
def state(homeca: str | None = Cookie(None)):
    with db() as c:
        return {"setup_needed": setting(c, "admin_hash") is None, "logged_in": homeca in SESSIONS,
                "user": SESSIONS.get(homeca), "local": _local_account(SESSIONS.get(homeca)), "sso": preferences.oidc_options()["enabled"],
                "ui": {"theme": setting(c, "ui_theme") or "auto"}}


@app.post("/api/setup")
def setup(b: Login, r: Response, request: Request):
    with db() as c:
        if setting(c, "admin_hash") is not None:
            raise HTTPException(409, "already set up")
        _set_admin(c, b.username.strip(), b.password)
    _login(r, b.username.strip())
    audit(b.username.strip(), "Administrator created", detail=guard.source(request))
    return {}


@app.post("/api/login")
def login(b: Login, r: Response, request: Request):
    guard.check(request, b.username)
    with db() as c:
        ok = _check_admin(c, b.username.strip(), b.password)
    if not ok:
        if guard.fail(request, b.username):  # one record per source per minute, so guessing cannot flood the log
            audit(b.username.strip(), "Sign-in failed", detail=guard.source(request))
        raise HTTPException(401, "wrong username or password")
    guard.success(request, b.username)
    _login(r, b.username.strip())
    audit(b.username.strip(), "Signed in", detail=guard.source(request))
    return {}


@app.post("/api/password")
def change_password(b: PwChange, request: Request, user: str = Depends(session), homeca: str | None = Cookie(None)):
    guard.check(request, user)  # a stolen session must not be able to guess the current password
    with db() as c:
        ok = _check_admin(c, user, b.current)
        if ok:
            if user == setting(c,"admin_user"):_set_admin(c,user,b.new)
            else:accounts.save_password(c,user,b.new)
    if not ok:  # outside the transaction: the audit entry needs its own connection and must not be rolled back
        if guard.fail(request, user):
            audit(user, "Password change refused", detail=guard.source(request))
        raise HTTPException(403, "current password is wrong")  # not 401: that means "session expired" to the UI
    guard.success(request, user)
    for t in [t for t in SESSIONS if t != homeca and SESSIONS[t] == user]:  # sign out everywhere else
        del SESSIONS[t]
    audit(user, "Password changed")
    return {}


@app.post("/api/logout")
def logout(r: Response, homeca: str | None = Cookie(None)):
    SESSIONS.pop(homeca, None)
    r.delete_cookie("homeca")
    return {}


# ---------- OIDC login (an alternative front door; everything past this point is still the same admin session) ----------
def _oidc_login(c, ident):
    """ident: the Keycloak preferred_username or email from the ID token. Returns the admin username to log in as."""
    user = setting(c, "admin_user")
    if user is None:
        raise HTTPException(409, "finish local setup first")
    if not ident or ident.lower() != OIDC_ADMIN_MATCH.lower():
        raise HTTPException(403, "this account is not the homeca admin")
    return user


def _external_url(request: Request, path: str) -> str:
    """Like request.url_for, but trusts Caddy's forwarded scheme/host for just this one URL - unlike HomeCaddy,
    homeca can't turn on uvicorn's proxy_headers globally: the ACME client allowlist needs the real peer IP,
    not whatever a spoofable X-Forwarded-For claims, so that stays proxy_headers=False everywhere else."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    return f"{scheme}://{host}{path}"


def oidc_failure(error):
    code = "tls" if "CERTIFICATE_VERIFY_FAILED" in str(error) else "failed"
    return RedirectResponse("/?sso_error=" + code)


@app.get("/login/oidc")
async def login_oidc(request: Request):
    try:
        provider, options = preferences.runtime()
        if not provider:
            raise HTTPException(404, "OIDC is not configured")
        with db() as c:
            if setting(c, "admin_user") is None:
                raise HTTPException(409, "Finish local setup first")
        # Reject a callback after an administrator changes providers mid-login.
        request.session['provider_config'] = ca.hash_pw(json.dumps(options, sort_keys=True), b'homeca oidc config')
        return await provider.oidc.authorize_redirect(request, _external_url(request, "/auth/callback"))
    except HTTPException:
        raise
    except Exception as error:
        return oidc_failure(error)


@app.get("/auth/callback", name="oidc_callback")
async def oidc_callback(request: Request):
    info = {}
    try:
        provider, options = preferences.runtime()
        if not provider or request.session.pop('provider_config', None) != ca.hash_pw(json.dumps(options, sort_keys=True), b'homeca oidc config'):
            raise ValueError("Provider changed or login not started")
        token = await provider.oidc.authorize_access_token(request)
        info = token.get("userinfo") or {}
        if not info.get('sub'):
            raise ValueError('Missing subject')
        with db() as c:
            c.execute("BEGIN IMMEDIATE")
            legacy = OIDC_ADMIN_MATCH if preferences.saved('oidc_config') is None else ""
            user = accounts.sso_user(c, info, options, legacy or "")
        response = RedirectResponse('/')
        _login(response, user)
        audit(user, "Signed in", detail="SSO")
        return response
    except Exception as error:
        if isinstance(error, HTTPException) and error.status_code == 403:
            audit(info.get("preferred_username") or info.get("email") or "unknown", "SSO sign-in refused", detail=str(error.detail)[:200])
        return oidc_failure(error)


# All authenticated HomeCA sessions are CA administrators, including existing OIDC sessions.
class InterfaceSettings(BaseModel):
    theme: str


@app.get("/api/settings/interface")
def interface_settings(user: str = Depends(session)):
    with db() as c:
        return {"theme": setting(c, "ui_theme") or "auto"}


@app.put("/api/settings/interface")
async def save_interface_settings(b: InterfaceSettings, request: Request, user: str = Depends(session)):
    if not request.headers.get("content-type", "").split(";")[0].strip().lower() == "application/json":
        raise HTTPException(415, "JSON required")
    if b.theme not in {"auto", "light", "dark"}:
        raise HTTPException(400, "choose Auto, Light or Dark")
    with db() as c:
        set_setting(c, "ui_theme", b.theme)
    audit(user, "Interface settings changed", detail="default appearance: " + b.theme)
    return {"theme": b.theme}


class OIDCSettings(BaseModel):
    enabled: bool = False
    issuer: str = Field(default='', max_length=2048)
    client_id: str = Field(default='', max_length=256)
    client_secret: str = Field(default='', max_length=8192)
    allowed_users: str = Field(default='', max_length=4096)


@app.get('/api/settings')
def server_settings(request: Request, user: str = Depends(session)):
    value = preferences.oidc_options()
    with db() as c:
        theme = setting(c, 'ui_theme') or 'auto'
    return {'ui':{'theme':theme}, 'oidc':{k:v for k,v in value.items() if k != 'secret_enc'},
            'oidc_secret_configured':bool(value['secret_enc'] or (preferences.saved('oidc_config') is None and OIDC_CLIENT_SECRET_FILE)),
            'callback_url':_external_url(request, '/auth/callback')}


@app.put('/api/settings/oidc')
def save_oidc(body: OIDCSettings, request: Request, user: str = Depends(session)):
    preferences.update_oidc(body)
    audit(user, 'OIDC settings changed', detail='enabled' if body.enabled else 'disabled')  # never the secret
    return {'settings':server_settings(request, user)}


class TrustUpload(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    certificate: str = Field(min_length=1, max_length=500000)


@app.get('/api/settings/trust')
def list_trust(user: str = Depends(session)):
    return preferences.public_trust()


@app.post('/api/settings/trust')
def upload_trust(body: TrustUpload, user: str = Depends(session)):
    count = preferences.add_trust(body.name, body.certificate)
    audit(user, 'Trust certificate added', body.name.strip(), f'{count} certificate(s)')
    return {'added':count, 'certificates':preferences.public_trust()}


@app.delete('/api/settings/trust/{fingerprint}')
def remove_trust(fingerprint: str, user: str = Depends(session)):
    with db() as c:
        entries = json.loads(setting(c, 'trusted_certificates') or '[]')
        remaining = [entry for entry in entries if entry['fingerprint'] != fingerprint]
        if len(entries) == len(remaining):
            raise HTTPException(404, 'Certificate not found')
        removed = next(entry for entry in entries if entry['fingerprint'] == fingerprint)
        set_setting(c, 'trusted_certificates', json.dumps(remaining))
    preferences.provider.cache_clear()
    audit(user, 'Trust certificate removed', str(removed.get('name', ''))[:80], fingerprint[:16])
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


def cert_list(c):
    rows = c.execute("SELECT * FROM certs").fetchall()
    out = []
    meta = {r["id"]: json.loads(r["params"]) for r in rows}
    # Certificates for the same name only supersede each other within the same origin: homeca's own
    # HTTPS certificate, ACME-issued ones (e.g. NPM's) and hand-issued ones are independent.
    origin = lambda r: "self" if meta[r["id"]].get("self") else "acme" if meta[r["id"]].get("acme") else "manual"  # noqa: E731
    for r in rows:
        st, days = status_of(r)
        p = meta[r["id"]]
        newer = any(o["parent_id"] == r["parent_id"] and o["cn"] == r["cn"] and o["id"] != r["id"] and not o["revoked_at"]
                    and o["kind"] == "leaf" and o["not_after"] > r["not_after"] and origin(o) == origin(r) for o in rows)
        out.append({"id": r["id"], "parent_id": r["parent_id"], "kind": r["kind"], "cn": r["cn"],
                    "not_after": r["not_after"], "status": st, "days_left": days, "superseded": newer,
                    "sans": p.get("sans", []), "has_key": bool(r["key_enc"]), "crl_next": r["crl_next"],
                    "acme": bool(p.get("acme")), "self": bool(p.get("self"))})
    return out


@app.get("/api/certs")
def list_certs(_: str = Depends(session)):
    with db() as c:
        return cert_list(c)


@app.get("/api/summary")
def summary(_: str = Depends(read)):
    """What a dashboard needs and nothing more: counts, authority expiry and CRL freshness, and the certificates
    that need attention (the same rule as the UI's Needs attention box). No keys, PEM data, SANs or serials."""
    with db() as c:
        certs, acme_ca = cert_list(c), ca.acme_ca(c)
    live = [x for x in certs if x["status"] != "revoked" and not x["superseded"]]
    stamp = now()
    attention = sorted((x for x in live if x["status"] in ("expiring", "expired")), key=lambda x: x["days_left"])
    return {
        "roots": sum(x["kind"] == "root" for x in certs), "intermediates": sum(x["kind"] == "intermediate" for x in certs),
        "active_leaves": sum(x["kind"] == "leaf" and x["status"] != "expired" for x in live),
        "expiring": sum(x["status"] == "expiring" for x in live), "expired": sum(x["status"] == "expired" for x in live),
        "revoked": sum(x["status"] == "revoked" for x in certs),
        "authorities": [{"kind": x["kind"], "cn": x["cn"], "status": x["status"], "days_left": x["days_left"],
                         "crl_next": x["crl_next"], "crl_overdue": bool(x["crl_next"] and parse(x["crl_next"]) < stamp)}
                        for x in live if x["kind"] != "leaf"],
        "attention": [{"cn": x["cn"], "kind": x["kind"], "status": x["status"], "days_left": x["days_left"], "acme": x["acme"]}
                      for x in attention[:20]],
        "acme": {"enabled": bool(acme_ca and acme.CLIENTS), "ca": acme_ca["cn"] if acme_ca else None},
    }


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
def create(b: NewCert, user: str = Depends(session)):
    if (b.kind == "root") != (b.parent_id is None):
        raise HTTPException(400, "root has no parent; intermediate/leaf need one")
    if b.key_type not in pki.KEY_TYPES:
        raise HTTPException(400, "bad key type")
    params = b.model_dump(exclude={"parent_id", "days"})
    key = pki.gen_key(b.key_type)
    with db() as c:
        cid = _issue(c, b.kind, b.parent_id, b.subject, key.public_key(), key, params, b.days)
    audit(user, "Certificate created", b.subject.get("cn", ""), f"{b.kind} · certificate {cid}")
    return {"id": cid}


@app.post("/api/certs/sign-csr")
def sign_csr(b: SignCsr, user: str = Depends(session)):
    try:
        csr, subject, csr_sans = pki.csr_info(b.csr_pem)
    except ValueError as e:
        raise HTTPException(400, str(e))
    sans = csr_sans if b.sans is None else b.sans
    params = {"subject": subject, "sans": sans, "usage": b.usage, "csr": True}
    with db() as c:
        cid = _issue(c, "leaf", b.parent_id, subject, csr.public_key(), None, params, b.days)
    audit(user, "Certificate signed from CSR", subject.get("cn", ""), f"certificate {cid}")
    return {"id": cid}


@app.post("/api/certs/{id}/renew")
def renew(id: int, user: str = Depends(session)):
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
        cid = _issue(c, "leaf", r["parent_id"], p["subject"], pub, key, p, max(days, 1))
    audit(user, "Certificate renewed", p["subject"].get("cn", ""), f"certificate {id} replaced by {cid}")
    return {"id": cid}


class Revoke(BaseModel):
    reason: str = "unspecified"


@app.post("/api/certs/{id}/revoke")
def revoke(id: int, b: Revoke, user: str = Depends(session)):
    if b.reason not in pki.REASONS:
        raise HTTPException(400, "bad reason")
    with db() as c:
        cn = row(c, id)["cn"]
        revoke_cert(c, id, b.reason)
    audit(user, "Certificate revoked", cn, f"certificate {id} · {b.reason}")
    return {}


@app.delete("/api/certs/{id}")
def delete(id: int, user: str = Depends(session)):
    with db() as c:
        cn = row(c, id)["cn"]
        if c.execute("SELECT 1 FROM certs WHERE parent_id=?", (id,)).fetchone():
            raise HTTPException(409, "has issued certificates; delete those first")
        c.execute("DELETE FROM certs WHERE id=?", (id,))
    audit(user, "Certificate deleted", cn, f"certificate {id}")
    return {}


@app.get("/api/certs/{id}/download")
def download(id: int, format: str = "pem", pw_p12: str = "", user: str = Depends(session)):
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
        cn = r["cn"]
    if format in ("key", "p12"):  # only downloads that carry the private key are recorded
        audit(user, "Private key downloaded" if format == "key" else "PKCS#12 bundle downloaded", cn, f"certificate {id}")
    return Response(body, media_type=mt, headers={"Content-Disposition": f'attachment; filename="{name}.{ext}"'})


# ---------- ACME admin ----------
class AcmeCa(BaseModel):
    id: int | None = None


@app.get("/api/acme")
def acme_status(_: str = Depends(session)):
    with db() as c:
        return acme.status(ca.acme_ca(c))


@app.post("/api/acme/ca")
def acme_set_ca(b: AcmeCa, user: str = Depends(session)):
    with db() as c:
        if b.id is None:
            set_setting(c, "acme_ca_id", "")
            audit(user, "ACME issuing CA changed", "none (ACME disabled)", c=c)
        else:
            r = row(c, b.id)
            if r["kind"] != "intermediate" or r["revoked_at"] or parse(r["not_after"]) <= now():
                raise HTTPException(400, "choose a valid intermediate CA")
            host = acme.HOSTNAME
            if host and not ca.name_allowed(host, ca.permitted_dns(cert_of(r))):
                raise HTTPException(400, f"this CA's name constraints don't permit {host}, "
                                         "which homeca needs for its own TLS certificate")
            set_setting(c, "acme_ca_id", str(b.id))
            audit(user, "ACME issuing CA changed", r["cn"], f"certificate {b.id}", c=c)
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
    with db() as c:
        theme = setting(c, "ui_theme") or "auto"
    # Allowlisted attribute rendered before CSS avoids a flash of the wrong login theme.
    attribute = f' data-theme="{theme}"' if theme in {"light", "dark"} else ""
    html = (STATIC / "index.html").read_text().replace('<html lang="en">', f'<html lang="en"{attribute}>')
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")

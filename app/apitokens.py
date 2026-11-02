"""Read-only API tokens for other services (a dashboard, a monitor). A token carries one scope, belongs to an
administrator, is stored only as a hash and is shown once. It opens read-only routes and nothing else:
private keys, issuing, revoking, deleting, settings and token management stay behind an administrator login."""
import hashlib
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from . import accounts
from .auditlog import audit
from .store import db

SCOPES = [("read", "Read", "Read the certificate summary: counts, authority expiry, revocation list freshness and "
                           "which certificates need attention. Cannot download keys or change anything.")]
INVALID: dict[str, list[float]] = {}  # recent invalid token attempts per source


def iso_now(offset=timedelta()):
    return (datetime.now(timezone.utc) + offset).isoformat(timespec="seconds")


def digest(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


def token_actor(request, raw):
    """Name of the token's owner-approved identity, or an HTTP error. Valid tokens are never throttled (a
    256-bit token cannot be guessed, and behind a proxy every caller shares one address); invalid ones are slowed
    down so they cannot churn the database."""
    with db() as c:
        row = c.execute("SELECT * FROM api_tokens WHERE token_hash=?", (digest(raw),)).fetchone()
        if not row or (row["expires"] and row["expires"] <= iso_now()) or not accounts.exists(c, row["owner"]):
            source = request.client.host if request.client else ""
            now = time.monotonic()
            recent = [t for t in INVALID.get(source, []) if now - t < 300]
            if len(recent) >= 10:
                raise HTTPException(429, "Too many invalid tokens. Try again in five minutes.")
            INVALID[source] = recent + [now]
            raise HTTPException(401, "Invalid or expired API token")
        c.execute("UPDATE api_tokens SET last_used=? WHERE id=? AND (last_used IS NULL OR last_used<?)",
                  (iso_now(), row["id"], iso_now(-timedelta(seconds=60))))
    return "token: " + row["name"]


class TokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    scope: str = Field(max_length=32)
    expires_days: int | None = Field(default=None, ge=1, le=3650)


def register(app, session):
    """Adds the token routes (administrator login only) and returns `read`, the dependency for routes that
    accept an administrator session or a bearer token. A bearer header never falls back to the session cookie."""

    def read(request: Request, homeca: str | None = Cookie(None)):
        header = request.headers.get("authorization", "")
        if header[:7].lower() == "bearer ":
            return token_actor(request, header[7:].strip())
        return session(homeca)

    @app.get("/api/tokens")
    def list_tokens(_: str = Depends(session)):
        with db() as c:
            rows = c.execute("SELECT id,name,scope,owner,created,expires,last_used FROM api_tokens ORDER BY created DESC").fetchall()
        return {"tokens": [{**dict(r), "expired": bool(r["expires"] and r["expires"] <= iso_now())} for r in rows],
                "scopes": [{"id": i, "label": label, "description": description} for i, label, description in SCOPES]}

    @app.post("/api/tokens")
    def create_token(body: TokenIn, user: str = Depends(session)):
        name = body.name.strip()
        if not name:
            raise HTTPException(400, "Enter a token name")
        if body.scope not in [i for i, _, _ in SCOPES]:
            raise HTTPException(400, "Choose a valid access level")
        raw = "homeca_" + secrets.token_urlsafe(32)  # a recognisable prefix helps secret scanners
        expires = iso_now(timedelta(days=body.expires_days)) if body.expires_days else None
        try:
            with db() as c:
                if c.execute("SELECT count(*) FROM api_tokens").fetchone()[0] >= 100:
                    raise HTTPException(400, "Revoke unused tokens before creating more (limit 100)")
                tid = secrets.token_hex(16)
                c.execute("INSERT INTO api_tokens VALUES (?,?,?,?,?,?,?,NULL)",
                          (tid, name, digest(raw), body.scope, user, iso_now(), expires))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "A token with this name already exists")
        audit(user, "API token created", name, body.scope + " · " + (f"expires in {body.expires_days} days" if expires else "no expiry"))
        return {"id": tid, "token": raw}  # the raw token is never stored; this response is the only time it is shown

    @app.delete("/api/tokens/{tid}")
    def revoke_token(tid: str, user: str = Depends(session)):
        with db() as c:
            row = c.execute("SELECT name FROM api_tokens WHERE id=?", (tid,)).fetchone()
            if not row:
                raise HTTPException(404, "Token not found")
            c.execute("DELETE FROM api_tokens WHERE id=?", (tid,))
        audit(user, "API token revoked", row["name"])
        return {"ok": True}

    return read

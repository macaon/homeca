"""Named administrators with a protected recovery account and issuer/subject SSO links."""
import hmac
import json
import secrets
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from .store import db
from .ca import hash_pw, setting


def ensure(c):
    username = setting(c, "admin_user")
    password = setting(c, "admin_hash")
    if username and password:
        c.execute("INSERT OR IGNORE INTO users(username,salt,password) VALUES (?,?,?)", (username, setting(c,"admin_salt"), password))


def save_password(c, username, password):
    if len(password) < 12 or len(password) > 1024:
        raise HTTPException(400, "Use a password between 12 and 1024 characters")
    salt = secrets.token_bytes(16)
    c.execute("INSERT INTO users(username,salt,password) VALUES (?,?,?) ON CONFLICT(username) DO UPDATE SET salt=excluded.salt,password=excluded.password", (username, salt.hex(), hash_pw(password,salt)))


def check_password(c, username, password):
    ensure(c)
    row = c.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
    actual = hash_pw(password, bytes.fromhex(row['salt']) if row and row['password'] else bytes(16))
    return bool(row and row['password'] and hmac.compare_digest(actual,row['password']))


def exists(c, username):
    ensure(c)
    return c.execute("SELECT 1 FROM users WHERE username=?",(username,)).fetchone() is not None


def sso_user(c, info, options, legacy_match=""):
    ensure(c)
    if not setting(c, "admin_user"):
        raise HTTPException(403, "Complete local administrator setup first")
    sub = info.get("sub")
    if not isinstance(sub,str) or not sub or not options.get("issuer"):
        raise HTTPException(403, "Missing SSO identity")
    username = info.get("preferred_username") or (info.get("email") if info.get("email_verified") is True else "")
    if not isinstance(username,str) or not username.strip() or len(username)>64:
        raise HTTPException(403, "Unsupported username")
    username=username.strip()
    identities={username.casefold()}
    if info.get("email_verified") is True:identities.add(str(info.get("email", "")).casefold())
    allowed={x.strip().casefold() for x in options["allowed_users"].split(",") if x.strip()}
    if not allowed.intersection(identities):raise HTTPException(403, "Identity is not an allowed administrator")
    subject=json.dumps([options["issuer"].rstrip("/"),sub],separators=(",",":"))
    if c.execute("SELECT 1 FROM blocked_users WHERE username=? OR subject=?",(username,subject)).fetchone():
        raise HTTPException(403, "This account was removed; ask an administrator to restore access")
    row=c.execute("SELECT * FROM users WHERE subject=?",(subject,)).fetchone()
    if row:return row['username']
    # Only the legacy environment-configured identity retains the original shared-admin mapping.
    if legacy_match and legacy_match.casefold() in identities:username=setting(c,"admin_user")
    row=c.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
    if row:
        if row['subject'] and row['subject']!=subject:raise HTTPException(403,"This account is already linked to another SSO identity")
        c.execute("UPDATE users SET subject=? WHERE username=?",(subject,username))
    else:
        c.execute("INSERT INTO users(username,subject) VALUES (?,?)",(username,subject))
    return username


class UserIn(BaseModel):
    username: str = Field(min_length=1,max_length=64,pattern=r"^[A-Za-z0-9_.@-]+$")
    password: str = Field(min_length=12,max_length=1024)
class PasswordIn(BaseModel):
    password: str = Field(min_length=12,max_length=1024)


def register(app, session, sessions, set_primary_password):
    def revoke(username):
        for token in list(sessions):
            if sessions.get(token)==username:sessions.pop(token,None)

    @app.get("/api/users")
    def users(_=Depends(session)):
        with db() as c:
            ensure(c)
            primary=setting(c,"admin_user")
            return [{"username":r['username'],"local":bool(r['password']),"primary":r['username']==primary,"admin":True} for r in c.execute("SELECT * FROM users ORDER BY username")]

    @app.post("/api/users")
    def add_user(body:UserIn,_=Depends(session)):
        with db() as c:
            c.execute("BEGIN IMMEDIATE")
            ensure(c)
            if c.execute("SELECT 1 FROM users WHERE username=?",(body.username,)).fetchone():raise HTTPException(409,"Username already exists")
            save_password(c,body.username,body.password)
            c.execute("DELETE FROM blocked_users WHERE username=?",(body.username,))
        return {"ok":True}

    @app.put("/api/users/{username}/password")
    def reset_password(username:str,body:PasswordIn,user=Depends(session)):
        if username==user:raise HTTPException(400,"Use your account menu to change your own password")
        with db() as c:
            if not exists(c,username):raise HTTPException(404,"User not found")
            if username==setting(c,"admin_user"):set_primary_password(c,username,body.password)
            else:save_password(c,username,body.password)
        revoke(username)
        return {"ok":True}

    @app.delete("/api/users/{username}")
    def remove_user(username:str,user=Depends(session)):
        with db() as c:
            ensure(c)
            if username==user or username==setting(c,"admin_user"):raise HTTPException(400,"You cannot remove your own account or the original administrator")
            row=c.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
            if not row:raise HTTPException(404,"User not found")
            c.execute("INSERT OR REPLACE INTO blocked_users(username,subject) VALUES (?,?)",(username,row['subject']))
            c.execute("DELETE FROM users WHERE username=?",(username,))
        revoke(username)
        return {"ok":True}

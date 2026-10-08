"""Shared CA operations used by the UI API (main.py) and the ACME endpoints (acme.py)."""
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException

from . import pki
from .store import db

PUBLIC_URL = os.environ.get("HOMECA_PUBLIC_URL", "").rstrip("/")
CRL_DAYS = 30
_master: bytes | None = None


def now():
    return datetime.now(timezone.utc)


def iso(d):
    return d.isoformat()


def parse(s):
    return datetime.fromisoformat(s)


def hash_pw(pw, salt):
    return hashlib.scrypt(pw.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024).hex()


def setting(c, k):
    r = c.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    return r["v"] if r else None


def set_setting(c, k, v):
    c.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (k, v))


def master() -> bytes:
    """Secret that encrypts every stored private key. Read once from HOMECA_MASTER_KEY_FILE."""
    global _master
    if _master is None:
        path = os.environ.get("HOMECA_MASTER_KEY_FILE")
        if not path:
            raise RuntimeError("HOMECA_MASTER_KEY_FILE must point at a file containing the master key "
                               "(for an existing install, the old passphrase)")
        pw = Path(path).read_text().rstrip("\r\n")
        if len(pw) < 12:
            raise RuntimeError("master key must be at least 12 characters")
        with db() as c:
            h = setting(c, "pw_hash")
            if h is None:  # fresh install: remember a hash so a wrong key is detected later
                salt = secrets.token_bytes(16)
                set_setting(c, "salt", salt.hex())
                set_setting(c, "pw_hash", hash_pw(pw, salt))
            elif not hmac.compare_digest(hash_pw(pw, bytes.fromhex(setting(c, "salt"))), h):
                raise RuntimeError("master key does not match this database")
        _master = pw.encode()
    return _master


# ---------- certificate rows ----------
def row(c, id):
    r = c.execute("SELECT * FROM certs WHERE id=?", (id,)).fetchone()
    if not r:
        raise HTTPException(404, "no such certificate")
    return r


def cert_of(r):
    return x509.load_pem_x509_certificate(r["cert_pem"].encode())


def key_of(r):
    if not r["key_enc"]:
        raise HTTPException(400, "private key is not stored (CSR-signed or ACME)")
    return serialization.load_pem_private_key(r["key_enc"].encode(), master())


def status_of(r):
    if r["revoked_at"]:
        return "revoked", None
    days = (parse(r["not_after"]) - now()).days
    return ("expired" if days < 0 else "expiring" if days < 30 else "valid"), days


def store_cert(c, kind, parent_id, cert, key, params):
    return c.execute(
        "INSERT INTO certs (parent_id,kind,cn,serial,not_before,not_after,cert_pem,key_enc,params) VALUES (?,?,?,?,?,?,?,?,?)",
        (parent_id, kind, params["subject"].get("cn", ""), format(cert.serial_number, "x"),
         iso(cert.not_valid_before_utc), iso(cert.not_valid_after_utc),
         cert.public_bytes(serialization.Encoding.PEM).decode(),
         pki.key_pem(key, master()) if key else None, json.dumps(params))).lastrowid


def chain(c, r):
    """All ancestors of r, nearest first, root last."""
    out = []
    while r["parent_id"] is not None:
        r = row(c, r["parent_id"])
        out.append(cert_of(r))
    return out


def urls(parent_id):
    if not PUBLIC_URL:
        return None, None
    return f"{PUBLIC_URL}/crl/{parent_id}.crl", f"{PUBLIC_URL}/ca/{parent_id}.crt"


# ---------- revocation ----------
def write_crl(c, ca_row):
    ca = cert_of(ca_row)
    revoked = [(int(x["serial"], 16), parse(x["revoked_at"]), x["revoke_reason"])
               for x in c.execute("SELECT * FROM certs WHERE parent_id=? AND revoked_at IS NOT NULL", (ca_row["id"],))]
    n = (ca_row["crl_number"] or 0) + 1
    crl = pki.make_crl(ca, key_of(ca_row), revoked, n, CRL_DAYS)
    c.execute("UPDATE certs SET crl_der=?, crl_next=?, crl_number=? WHERE id=?",
              (crl.public_bytes(serialization.Encoding.DER), iso(crl.next_update_utc), n, ca_row["id"]))


def refresh_crls():
    with db() as c:
        for r in c.execute("SELECT * FROM certs WHERE kind!='leaf' AND revoked_at IS NULL").fetchall():
            if parse(r["not_after"]) > now() and (not r["crl_next"] or (parse(r["crl_next"]) - now()).days < CRL_DAYS // 2):
                write_crl(c, r)


def revoke_cert(c, id, reason="unspecified"):
    r = row(c, id)
    if r["parent_id"] is None:
        raise HTTPException(400, "a root CA has no issuer to publish its revocation")
    if r["revoked_at"]:
        raise HTTPException(409, "already revoked")
    c.execute("UPDATE certs SET revoked_at=?, revoke_reason=? WHERE id=?", (iso(now()), reason, id))
    write_crl(c, row(c, r["parent_id"]))


# ---------- ACME CA selection ----------
def acme_ca(c):
    """Row of the intermediate chosen for ACME issuance, or None."""
    v = setting(c, "acme_ca_id")
    if not v:
        return None
    r = c.execute("SELECT * FROM certs WHERE id=?", (int(v),)).fetchone()
    if not r or r["kind"] != "intermediate" or r["revoked_at"] or parse(r["not_after"]) <= now():
        return None
    return r


def permitted_dns(ca_cert):
    """DNS subtrees the CA may issue for, or None if unconstrained."""
    try:
        nc = ca_cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return None
    dns = [g.value.lower() for g in nc.permitted_subtrees or [] if isinstance(g, x509.DNSName)]
    return dns or None


def name_allowed(name, subtrees):
    return subtrees is None or any(name == p or name.endswith("." + p) for p in subtrees)

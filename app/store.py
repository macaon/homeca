import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DATA = Path(os.environ.get("HOMECA_DATA", "./data"))
DATA.mkdir(parents=True, exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS certs (
  id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES certs(id), kind TEXT NOT NULL,
  cn TEXT, serial TEXT, not_before TEXT, not_after TEXT,
  cert_pem TEXT NOT NULL, key_enc TEXT, params TEXT,
  revoked_at TEXT, revoke_reason TEXT,
  crl_der BLOB, crl_next TEXT, crl_number INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS acme_accounts (
  id INTEGER PRIMARY KEY, jwk TEXT NOT NULL, thumbprint TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'valid', contact TEXT, created TEXT
);
CREATE TABLE IF NOT EXISTS acme_orders (
  id TEXT PRIMARY KEY, account_id INTEGER NOT NULL, status TEXT NOT NULL,
  identifiers TEXT NOT NULL, expires TEXT NOT NULL, cert_id INTEGER, error TEXT
);
CREATE TABLE IF NOT EXISTS acme_authz (
  id TEXT PRIMARY KEY, order_id TEXT NOT NULL, name TEXT NOT NULL, token TEXT NOT NULL,
  status TEXT NOT NULL, expires TEXT NOT NULL, error TEXT
);
"""


@contextmanager
def db():
    c = sqlite3.connect(DATA / "homeca.db")
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    try:
        with c:  # commit/rollback
            yield c
    finally:
        c.close()

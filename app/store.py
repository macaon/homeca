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

"""Run: .venv/bin/python -m pytest tests  (or: .venv/bin/python tests/test_auth.py)"""
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).parent.parent))
from app import ca, main, store  # noqa: E402


def test_oidc_login_matches_configured_identity():
    """_oidc_login() in isolation: no local admin yet, a match, a case-insensitive match, a mismatch."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(store.SCHEMA)
    main.OIDC_ADMIN_MATCH = "alice@example.com"

    with pytest.raises(HTTPException) as e:
        main._oidc_login(conn, "alice@example.com")
    assert e.value.status_code == 409

    ca.set_setting(conn, "admin_user", "admin")
    assert main._oidc_login(conn, "alice@example.com") == "admin"
    assert main._oidc_login(conn, "ALICE@EXAMPLE.COM") == "admin"
    with pytest.raises(HTTPException) as e:
        main._oidc_login(conn, "bob@example.com")
    assert e.value.status_code == 403


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f()
            print("ok", n)

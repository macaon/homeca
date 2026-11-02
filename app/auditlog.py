"""Append-only who/what/when record of administrative actions, for administrators only.
Never pass passwords, private keys, tokens, secrets or certificate contents."""
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Query

from .store import db

AUDIT_DAYS, AUDIT_ROWS = 90, 50000


def audit(actor, action, target="", detail="", c=None):
    """Pass the caller's open connection as `c` when called inside a write transaction: a second connection
    would wait for that transaction and fail with "database is locked"."""
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=AUDIT_DAYS)).isoformat(timespec="seconds")

    def write(conn):
        conn.execute("INSERT INTO audit (ts,actor,action,target,detail) VALUES (?,?,?,?,?)",
                     (now.isoformat(timespec="seconds"), str(actor)[:100], action[:100], str(target)[:200], str(detail)[:500]))
        # Bounded by age and by row count, so a flood of events cannot grow the database without limit.
        conn.execute("DELETE FROM audit WHERE ts<? OR id<=(SELECT max(id) FROM audit)-?", (cutoff, AUDIT_ROWS))

    if c is not None:
        write(c)
    else:
        with db() as conn:
            write(conn)


def register(app, session):
    @app.get("/api/audit")
    def audit_log(before: int | None = None, limit: int = Query(50, ge=1, le=200), _: str = Depends(session)):
        with db() as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM audit WHERE (?1 IS NULL OR id<?1) ORDER BY id DESC LIMIT ?2",
                                               (before, limit + 1))]
        return {"entries": rows[:limit], "more": len(rows) > limit}

"""python -m app: HTTP on :8080 always; HTTPS on :8443 once an ACME CA is selected.
The HTTPS listener uses a certificate homeca issues to itself (HOMECA_ACME_HOSTNAME) and renews live."""
import asyncio
import json
import os
import threading
import time

import uvicorn

from . import acme, ca, pki
from .main import app
from .store import DATA, db

TLS_DIR = DATA / "tls"


def ensure_tls():
    """Issue or renew homeca's own certificate. Returns (certfile, keyfile, serial) or None if not configured."""
    with db() as c:
        issuer = ca.acme_ca(c)
        if not issuer or not acme.HOSTNAME:
            return None
        cur = next((r for r in c.execute(
            "SELECT * FROM certs WHERE kind='leaf' AND revoked_at IS NULL AND parent_id=? AND cn=? ORDER BY id DESC",
            (issuer["id"], acme.HOSTNAME)) if json.loads(r["params"]).get("self")), None)
        if cur:
            nb, na = ca.parse(cur["not_before"]), ca.parse(cur["not_after"])
            if ca.now() > nb + (na - nb) * 2 / 3:  # renew at two-thirds of its life
                cur = None
        if cur is None:
            key = pki.gen_key("ec256")
            cdp, aia = ca.urls(issuer["id"])
            cert = pki.issue("leaf", {"cn": acme.HOSTNAME}, key.public_key(), ca.key_of(issuer), ca.cert_of(issuer),
                             acme.DAYS, sans=[acme.HOSTNAME], usage="server", cdp=cdp, aia=aia)
            cur = ca.row(c, ca.store_cert(c, "leaf", issuer["id"], cert, key,
                                          {"subject": {"cn": acme.HOSTNAME}, "sans": [acme.HOSTNAME], "usage": "server",
                                           "key_type": "ec256", "self": True}))
        pem = "".join(x.public_bytes(pki.serialization.Encoding.PEM).decode()
                      for x in [ca.cert_of(cur), *ca.chain(c, cur)[:-1]])  # leaf + intermediates, no root
        key_pem = pki.key_pem(ca.key_of(cur))
    TLS_DIR.mkdir(exist_ok=True, mode=0o700)
    paths = []
    for name, data in (("fullchain.pem", pem), ("key.pem", key_pem)):
        p = TLS_DIR / name
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(data)
        paths.append(str(p))
    return paths[0], paths[1], cur["serial"]


class TlsRunner:
    def __init__(self):
        self.stopping = False
        self.server = None

    def stop(self):
        self.stopping = True
        if self.server:
            self.server.should_exit = True

    def run(self):
        asyncio.run(self._serve())

    async def _serve(self):
        files = None
        while not files and not self.stopping:
            try:
                files = await asyncio.to_thread(ensure_tls)
            except Exception as e:  # noqa: BLE001
                print("TLS setup failed:", e, flush=True)
            if not files:
                await asyncio.sleep(10)  # wait for an ACME CA to be selected in the UI
        if self.stopping:
            return
        cert, key, serial = files
        self.server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=acme.TLS_PORT, ssl_certfile=cert,
                                                    ssl_keyfile=key, proxy_headers=False))
        task = asyncio.create_task(self.server.serve())
        last = time.monotonic()
        while not task.done() and not self.stopping:
            await asyncio.sleep(2)
            if time.monotonic() - last > 3600:
                last = time.monotonic()
                try:
                    new = await asyncio.to_thread(ensure_tls)
                    if new and new[2] != serial:  # live reload: new handshakes use the new certificate
                        self.server.config.ssl.load_cert_chain(new[0], new[1])
                        serial = new[2]
                except Exception as e:  # noqa: BLE001
                    print("TLS renewal failed:", e, flush=True)
        self.server.should_exit = True
        await task


if __name__ == "__main__":
    ca.master()  # fail fast on a missing or wrong master key
    tls = TlsRunner()
    threading.Thread(target=tls.run, daemon=True).start()
    # proxy_headers off: the ACME client allowlist must see the real peer, not a spoofable X-Forwarded-For
    uvicorn.run(app, host="0.0.0.0", port=8080, proxy_headers=False)
    tls.stop()

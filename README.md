# homeca

A small, self-hosted certificate authority with a web UI, built for homelabs.

It exists because some CA tools don't write Subject/Authority Key Identifier (SKI/AKI) extensions,
which breaks strict chain validation (`openssl verify -x509_strict`, and some Java, Go and Apple
clients). Every certificate homeca issues goes through one function, `pki.issue()`, so those
extensions cannot be forgotten.

## Features

- Root, intermediate and leaf certificates with RFC 5280-correct extensions
- Sign CSRs from devices, so their private keys never leave them
- Revocation with a signed CRL served over HTTP
- Dashboard of expiring and expired certificates, with one-click renew
- Downloads: certificate, full chain, DER, private key, PKCS#12
- ECDSA P-256 / P-384 and RSA 2048 / 3072 / 4096 keys
- Single passphrase; private keys are encrypted at rest
- Vanilla HTML/JS/CSS frontend with no build step and no CDN; light and dark themes

## Quick start

    podman compose up --build -d      # docker compose works too
    open http://localhost:8080

1. Edit `HOMECA_PUBLIC_URL` in `compose.yaml` first (see [Configuration](#configuration)).
2. On first visit, choose a passphrase (12+ characters).
3. **+ New → Root CA**, then **Intermediate CA** under it, then **Leaf** certificates under that.
4. Install the root on your clients. Fetch it from `/ca/<id>.pem` (or `.crt` for DER).
5. Issue leaves from the intermediate and keep the root offline-ish: after creating the intermediate
   you rarely need the root again.

Verify a chain yourself:

    openssl verify -x509_strict -CAfile root.pem -untrusted intermediate.pem leaf.pem

## Configuration

Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `HOMECA_DATA` | `./data` (`/data` in the container) | Directory holding `homeca.db` |
| `HOMECA_PUBLIC_URL` | unset | Base URL devices use to reach this service, e.g. `http://ca.home.arpa:8080`. Embedded in issued certs as the CRL distribution point and CA-issuer (AIA) URL. If unset, those extensions are omitted. Use plain HTTP: clients must not need TLS to validate TLS. |
| `HOMECA_SECURE_COOKIE` | `0` | Set `1` once the UI is served over HTTPS by your reverse proxy |

Run it behind a reverse proxy for TLS. Proxy only the UI over HTTPS if you like, but keep `/crl/*`
and `/ca/*` reachable over plain HTTP at `HOMECA_PUBLIC_URL`.

## Certificate profiles

| | BasicConstraints | KeyUsage | Other | Default validity |
|---|---|---|---|---|
| Root | CA:TRUE | keyCertSign, cRLSign | AKI = own SKI | 10 years |
| Intermediate | CA:TRUE, pathlen (default 0) | keyCertSign, cRLSign | optional critical NameConstraints (`home.arpa`, `10.0.0.0/8`), CDP, AIA | 5 years |
| Leaf | CA:FALSE | digitalSignature (+ keyEncipherment for RSA) | EKU serverAuth / clientAuth, SAN, CDP, AIA | 1 year |

All certificates: random 159-bit serial, SKI from the public key, AKI from the issuer's SKI, and a
`notAfter` clamped to the issuer's. The UI warns above 398 days for server certificates, which
Apple platforms reject.

DNS name constraints are written without a leading dot (`home.arpa` already covers subdomains), as
RFC 5280 requires.

## Signing a CSR

Generate a request on the device, then **+ New → Sign CSR**:

    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout router.key -out router.csr -subj "/CN=router.home.arpa" \
      -addext "subjectAltName=DNS:router.home.arpa,IP:192.168.1.1"

The CSR's signature is checked, its public key and subject are kept, and homeca applies its own leaf
profile. Extensions requested in the CSR other than SAN are ignored; SANs can be overridden in the UI.

## Revocation and CRLs

Revoking a certificate re-signs its issuer's CRL (30-day lifetime). A root has no issuer, so it
cannot be revoked. CRLs are also refreshed at login when under 15 days remain, so **log in at least
every two weeks** or the CRL will expire. The dashboard does not yet warn about this.

Renewing a leaf issues a new certificate (new key if homeca holds the key, otherwise the device's
existing public key) and marks the old one "superseded" without revoking it. Revoke it yourself if
the old key may be compromised. Intermediates and roots cannot be renewed; create a new one.

## Security model

- The passphrase is hashed with scrypt for login, and private keys are stored as passphrase-encrypted
  PKCS#8. There is **no recovery and no passphrase change**. Back up the data volume and remember
  the passphrase.
- Sessions live in memory with an `HttpOnly`, `SameSite=Strict` cookie; a restart logs everyone out.
  Failed logins are delayed one second. The API only accepts JSON, which together with
  `SameSite=Strict` covers CSRF.
- A logged-in session can download private keys. Treat access to the UI as access to the CA.
- There is deliberately **no OIDC/Keycloak login**. If Keycloak's own certificate comes from this CA,
  an expiry would lock you out of the tool needed to fix it.
- Public unauthenticated endpoints: `/crl/<id>.crl`, `/ca/<id>.crt`, `/ca/<id>.pem`.

## Backup

    podman volume export homeca-data > homeca-backup.tar

The volume holds only `homeca.db` (encrypted keys, certificates, CRLs). Without the passphrase the
backup is useless; without the backup the passphrase is useless.

## API

All `/api` routes except `state`, `setup` and `login` need the session cookie.

| Route | Purpose |
|---|---|
| `GET /api/state` | `{setup_needed, logged_in}` |
| `POST /api/setup`, `/api/login`, `/api/logout` | Authentication (`{"passphrase": "..."}`) |
| `GET /api/certs` | All certificates with status and days left |
| `GET /api/certs/{id}` | Details and decoded extensions |
| `POST /api/certs` | Create root / intermediate / leaf |
| `POST /api/certs/sign-csr` | Sign a CSR |
| `POST /api/certs/{id}/renew` | Re-issue a leaf |
| `POST /api/certs/{id}/revoke` | Revoke with a reason |
| `DELETE /api/certs/{id}` | Delete (only if it has issued nothing) |
| `GET /api/certs/{id}/download?format=pem\|der\|chain\|key\|p12` | Download; `pw_p12` sets the PKCS#12 password |

## Layout

    app/pki.py       X.509 building (keys, profiles, CRL, PKCS#12)
    app/store.py     SQLite schema and connection helper
    app/main.py      FastAPI routes, auth, public CRL/CA endpoints
    app/static/      index.html, app.js, style.css
    tests/           test_pki.py
    Containerfile, compose.yaml

## Development

    python -m venv .venv && .venv/bin/pip install -r requirements.txt
    .venv/bin/python tests/test_pki.py                     # or: pytest tests
    HOMECA_DATA=./data .venv/bin/uvicorn app.main:app --reload

The test builds root → intermediate → leaf and checks AKI/SKI linkage, strict verification with
`cryptography`'s verifier, CSR key preservation and CRL contents.

## Not included

ACME, OCSP, passphrase rotation, importing an existing CA, multiple users, and unattended CRL
refresh. ACME is the most natural next step if you want Traefik or Caddy to renew automatically.

---

Built with the assistance of Claude (Anthropic).

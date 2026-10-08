# HomeCA

A small, self-hosted certificate authority with a web UI, built for homelabs.

It exists because some CA tools don't write Subject/Authority Key Identifier (SKI/AKI) extensions,
which breaks strict chain validation (`openssl verify -x509_strict`, and some Java, Go and Apple
clients). Every certificate HomeCA issues goes through one function, `pki.issue()`, so those
extensions cannot be forgotten.

## Features

- Root, intermediate and leaf certificates with RFC 5280-correct extensions
- **ACME server** (HTTP-01): Nginx Proxy Manager, certbot and Caddy can request and renew certificates automatically
- Sign CSRs from devices, so their private keys never leave them
- Revocation with a signed CRL served over HTTP, refreshed automatically
- Dashboard of expiring and expired certificates, with one-click renew
- Downloads: certificate, full chain, DER, private key, PKCS#12
- ECDSA P-256 / P-384 and RSA 2048 / 3072 / 4096 keys
- Username/password login; private keys are encrypted at rest with a separate master key
- Vanilla HTML/JS/CSS frontend with no build step and no CDN; light and dark themes

## Quick start (Docker or Podman)

    openssl rand -base64 32 > master.key
    chown 10001 master.key && chmod 400 master.key     # the container runs as uid 10001
    $EDITOR compose.yaml                               # set HOMECA_PUBLIC_URL, HOMECA_ACME_* (see below)
    docker compose up --build -d                       # podman compose works too
    open http://localhost:8080

1. On first visit, create the admin user (password of 12+ characters).
2. **+ New → Root CA**, then **Intermediate CA** under it, then **Leaf** certificates under that.
3. Install the root on your clients. Fetch it from `/ca/<id>.pem` (or `.crt` for DER).
4. Issue leaves from the intermediate. After creating the intermediate you rarely need the root again.

Verify a chain yourself:

    openssl verify -x509_strict -CAfile root.pem -untrusted intermediate.pem leaf.pem

## Configuration

Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `HOMECA_MASTER_KEY_FILE` | **required** | File containing the master key (12+ characters). Use a Docker/compose secret. |
| `HOMECA_DATA` | `./data` (`/data` in the container) | Directory holding `homeca.db` |
| `HOMECA_PUBLIC_URL` | unset | Base URL devices use to reach the plain-HTTP port, e.g. `http://ca.home.arpa:8080`. Embedded in issued certs as the CRL distribution point and CA-issuer (AIA) URL. If unset, those extensions are omitted. Keep it plain HTTP: clients must not need TLS to validate TLS. |
| `HOMECA_SECURE_COOKIE` | `0` | Set `1` once the UI is served over HTTPS by your reverse proxy |
| `HOMECA_ACME_CLIENTS` | unset | Comma-separated CIDRs allowed to use ACME, e.g. `10.1.1.0/24` or NPM's IP. **Empty disables ACME.** |
| `HOMECA_ACME_HOSTNAME` | unset | Name ACME clients use for HomeCA, e.g. `ca.home.arpa`. HomeCA issues itself a TLS certificate for it. |
| `HOMECA_TLS_PORT` | `8443` | Port of the HTTPS (ACME) listener |
| `HOMECA_ACME_DAYS` | `90` | Lifetime of ACME-issued certificates |

Put the UI behind your reverse proxy for TLS if you like, but keep `/crl/*` and `/ca/*` reachable over
plain HTTP at `HOMECA_PUBLIC_URL`.

## Certificate profiles

| | BasicConstraints | KeyUsage | Other | Default validity |
|---|---|---|---|---|
| Root | CA:TRUE | keyCertSign, cRLSign | AKI = own SKI | 10 years |
| Intermediate | CA:TRUE, pathlen (default 0) | keyCertSign, cRLSign | optional critical NameConstraints (`home.arpa`, `10.0.0.0/8`), CDP, AIA | 5 years |
| Leaf | CA:FALSE | digitalSignature (+ keyEncipherment for RSA) | EKU serverAuth / clientAuth, SAN, CDP, AIA | 1 year (90 days via ACME) |

All certificates: random 159-bit serial, SKI from the public key, AKI from the issuer's SKI, and a
`notAfter` clamped to the issuer's.

DNS name constraints are written without a leading dot (`home.arpa` already covers subdomains), as
RFC 5280 requires.

## ACME and Nginx Proxy Manager

HomeCA implements the ACME protocol (RFC 8555) with the HTTP-01 challenge, so tools that normally talk
to Let's Encrypt can use it. Certificates are per host name; wildcards (which need DNS-01) are not supported.

**In HomeCA**

1. Create an intermediate CA, ideally with a name constraint such as `home.arpa`. ACME refuses names
   outside the CA's constraints.
2. Open the intermediate and choose **Use for ACME**. The ACME card then shows the directory URL.
3. Set `HOMECA_ACME_CLIENTS` to the address of your ACME client and `HOMECA_ACME_HOSTNAME` to a name that
   resolves to HomeCA, then restart. HomeCA issues itself a TLS certificate for that name from the chosen
   CA and starts the HTTPS listener on 8443 (it can take about ten seconds after selecting the CA).
   That certificate is renewed automatically with no restart.

**In NPM** (the setting is environment-only; there is no GUI field)

    environment:
      LE_SERVER: https://ca.home.arpa:8443/acme/directory
      REQUESTS_CA_BUNDLE: /homeca-root.pem          # so certbot trusts homeca's TLS
    volumes:
      - ./homeca-root.pem:/homeca-root.pem:ro       # download from homeca: /ca/<root id>.pem

Then add certificates in NPM as usual with **Let's Encrypt**. NPM requests them from HomeCA and renews
them itself. Notes:

- With `LE_SERVER` set, NPM can no longer get real Let's Encrypt certificates.
- For HTTP-01, HomeCA must be able to resolve the host name and reach port 80 on NPM.
- The same works with plain certbot: `certbot certonly --standalone --server https://ca.home.arpa:8443/acme/directory -d host.home.arpa`
  with `REQUESTS_CA_BUNDLE` pointing at the root. To revoke, pass the same `--server`.
- The client allowlist uses the real peer address. Docker's default port publishing keeps it; if HomeCA
  sees a bridge address instead of NPM's, put both on one Docker network and allow that subnet.
- ACME-issued certificates have no stored key (the client holds it) and renew through ACME, so
  HomeCA's own Renew button is hidden for them. `X-Forwarded-For` is deliberately ignored.
- Unsupported: DNS-01, `keyChange`, external account binding, IP identifiers.

NPM's LE_SERVER support was verified against its source (`backend/lib/config.js`, `develop` branch);
check your NPM version if it doesn't take effect.

## Signing a CSR

Generate a request on the device, then **+ New → Sign CSR**:

    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout router.key -out router.csr -subj "/CN=router.home.arpa" \
      -addext "subjectAltName=DNS:router.home.arpa,IP:192.168.1.1"

The CSR's signature is checked, its public key and subject are kept, and HomeCA applies its own leaf
profile. Extensions requested in the CSR other than SAN are ignored; SANs can be overridden in the UI.

## Revocation and CRLs

Revoking a certificate re-signs its issuer's CRL (30-day lifetime). A root has no issuer, so it
cannot be revoked. A daily job re-signs CRLs that have under 15 days left, so no login is needed to keep
them valid. ACME clients revoke through the protocol (`certbot revoke`).

Renewing a leaf in the UI issues a new certificate (new key if HomeCA holds the key, otherwise the
device's existing public key) and marks the old one "superseded" without revoking it. Revoke it yourself
if the old key may be compromised. Intermediates and roots cannot be renewed; create a new one.

## Security model

- **Two secrets.** The admin **password** only logs you in (scrypt-hashed). The **master key** file
  encrypts every private key (passphrase-encrypted PKCS#8) and lets HomeCA sign without anyone logged in,
  which ACME and the daily CRL job need. A stolen backup or volume is useless without the master key;
  anyone who can read both the running container's secret and its data can use the CA.
- Losing the master key means losing every stored private key. Keep a copy somewhere safe, separate from backups.
- You can change the admin password in the UI. The master key cannot be rotated in place.
- Sessions live in memory with an `HttpOnly`, `SameSite=Strict` cookie; a restart logs everyone out.
  Failed logins are delayed one second. The API only accepts JSON, which together with
  `SameSite=Strict` covers CSRF.
- A logged-in session can download private keys. Treat access to the UI as access to the CA.
- ACME needs three things to issue: the client's address in `HOMECA_ACME_CLIENTS`, proof of control of the
  name over HTTP-01, and the name being inside the chosen CA's name constraints.
- There is deliberately **no OIDC/Keycloak login**. If Keycloak's own certificate comes from this CA,
  an expiry would lock you out of the tool needed to fix it.
- Public unauthenticated endpoints: `/crl/<id>.crl`, `/ca/<id>.crt`, `/ca/<id>.pem`.

### Upgrading from the passphrase version

Earlier versions used one passphrase for both login and key encryption. Put that passphrase into the
master key file and start the new version: it already matches what is stored, so no keys are
re-encrypted. The first visit then asks you to create the admin user.

## Backup

    docker run --rm -v homeca-data:/d -v "$PWD":/b alpine tar czf /b/homeca-backup.tgz -C /d .

The volume holds only `homeca.db` (encrypted keys, certificates, CRLs, ACME accounts) and `tls/`.
Back up `master.key` separately; the backup is useless without it, and it is useless without the backup.

## API

All `/api` routes except `state`, `setup` and `login` need the session cookie.

| Route | Purpose |
|---|---|
| `GET /api/state` | `{setup_needed, logged_in, user}` |
| `POST /api/setup`, `/api/login`, `/api/logout` | Authentication (`{"username": "...", "password": "..."}`) |
| `POST /api/password` | Change the admin password (`{"current", "new"}`) |
| `GET /api/certs` | All certificates with status and days left |
| `GET /api/certs/{id}` | Details and decoded extensions |
| `POST /api/certs` | Create root / intermediate / leaf |
| `POST /api/certs/sign-csr` | Sign a CSR |
| `POST /api/certs/{id}/renew` | Re-issue a leaf (not ACME-managed ones) |
| `POST /api/certs/{id}/revoke` | Revoke with a reason |
| `DELETE /api/certs/{id}` | Delete (only if it has issued nothing) |
| `GET /api/certs/{id}/download?format=pem\|der\|chain\|key\|p12` | Download; `pw_p12` sets the PKCS#12 password |
| `GET /api/acme`, `POST /api/acme/ca` | ACME status; choose the issuing intermediate (`{"id": 2}` or `{"id": null}`) |
| `/acme/*` | The ACME protocol itself (directory, new-account, new-order, ...) |

## Layout

    app/pki.py       X.509 building (keys, profiles, CRL, PKCS#12)
    app/ca.py        shared CA operations: master key, storage, CRLs, revocation
    app/acme.py      ACME server (RFC 8555, HTTP-01)
    app/main.py      FastAPI routes, auth, public CRL/CA endpoints
    app/__main__.py  entry point: HTTP :8080 and the HTTPS ACME listener with live certificate reload
    app/store.py     SQLite schema and connection helper
    app/static/      index.html, app.js, style.css
    tests/           test_pki.py, test_acme.py
    Containerfile, compose.yaml

## Development

    python -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
    .venv/bin/python -m pytest tests
    HOMECA_MASTER_KEY_FILE=./master.key HOMECA_DATA=./data .venv/bin/python -m app

The tests cover chain building (AKI/SKI linkage, strict verification), login and master-key checks, and
a complete ACME client flow: account, order, challenge, finalize, certificate, revocation and rejection
cases. The ACME flow was also run end to end against real certbot (issue, renew, revoke).

## Not included

DNS-01 / wildcards, OCSP, importing an existing CA, multiple users, and master-key rotation.

---

Built with the assistance of Claude (Anthropic).

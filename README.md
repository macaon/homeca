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
- Versioned HomeUI frontend with no build step or CDN; Auto, Light and Dark appearance
- Tabbed server settings for interface defaults, private CA trust and optional OIDC login

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
| `HOMECA_TRUSTED_PROXIES` | unset | Your reverse proxy's address or network (comma-separated), e.g. `172.28.0.1`. Only requests from it may name the real client in `X-Forwarded-For`; everyone else's header is ignored. Without it sign-in limits and the audit log see the proxy's address for every user. Unrelated to the ACME allowlist, which always uses the real peer address. |
| `HOMECA_ACME_CLIENTS` | unset | Comma-separated CIDRs allowed to use ACME, e.g. `10.1.1.0/24` or NPM's IP. **Empty disables ACME.** |
| `HOMECA_ACME_HOSTNAME` | unset | Name ACME clients use for HomeCA, e.g. `ca.home.arpa`. HomeCA issues itself a TLS certificate for it. |
| `HOMECA_TLS_PORT` | `8443` | Port of the HTTPS (ACME) listener |
| `HOMECA_ACME_DAYS` | `90` | Lifetime of ACME-issued certificates |

Put the UI behind your reverse proxy for TLS if you like, but keep `/crl/*` and `/ca/*` reachable over
plain HTTP at `HOMECA_PUBLIC_URL`.

## Interface and single sign-on

HomeCA vendors **HomeUI 0.1.1** from HomeTemplate under `app/static/ui/`; the adopted [design guideline](docs/design-guidelines.md) and `HOMEUI_VERSION` record the baseline. App-specific certificate styles remain separate.

The settings cog sits immediately left of the account name. The account menu contains password and logout. Appearance is configured under the settings cog. With one dashboard there is no navigation hamburger; certificate creation lives beside the certificate list.

Under **Server settings**:

- **User Interface:** choose Auto, Light or Dark as the server default. Auto is the initial value. The dashboard and login page both follow this setting; there is no separate account-menu appearance override.
- **Trust:** upload multiple public PEM/DER certificates or a PEM bundle for your identity provider. System roots and `HOMECA_OIDC_CA_FILE` remain trusted. Private keys are rejected. Trust uploads are separate from your issuing CA hierarchy. The OAuth / OIDC tab links to Trust rather than having its own certificate field.
- **OAuth / OIDC:** enable SSO, paste an HTTPS issuer or full discovery URL, enter a client ID/secret and explicitly list the administrator usernames or verified emails allowed to sign in. The callback remains `/auth/callback`, shown with the external origin in the settings form. Saving does not require a restart. Saved fields remain populated; a masked secret placeholder means leave blank to retain it.

Existing `HOMECA_OIDC_ISSUER`, `HOMECA_OIDC_CLIENT_ID`, `HOMECA_OIDC_CLIENT_SECRET_FILE`, `HOMECA_OIDC_ADMIN_MATCH` and `HOMECA_OIDC_CA_FILE` deployments continue to work. On the first save, the UI configuration takes precedence and the existing secret is encrypted into the database. Back up the database and master key as before. Local admin credentials, issued certificates, ACME configuration and CA keys are not migrated.

If SSO fails, the login page shows a safe error. Log in locally to check provider settings or upload its root under Trust. Keep a working local password for recovery.

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

> **Warning: `LE_SERVER` applies to the whole NPM instance.** It is passed to certbot for every issue
> *and renewal*, so an NPM that also serves public sites with real Let's Encrypt certificates will fail to
> renew them. Only set it on an NPM used for internal hosts only, which needs its own host or IP for
> ports 80/443 if you already run another one. If you keep a single NPM for both, don't use this; upload
> HomeCA certificates as custom certificates in NPM instead, or point other ACME clients (Proxmox, Caddy,
> certbot, ...) at HomeCA.

    environment:
      LE_SERVER: https://ca.home.arpa:8443/acme/directory
      REQUESTS_CA_BUNDLE: /homeca-root.pem          # so certbot trusts homeca's TLS
    volumes:
      - ./homeca-root.pem:/homeca-root.pem:ro       # download from homeca: /ca/<root id>.pem

Then add certificates in NPM as usual with **Let's Encrypt**. NPM requests them from HomeCA and renews
them itself. Notes:

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
  After 10 failed sign-ins for an account from one source within five minutes (or 30 from one source across accounts) further attempts get HTTP 429 until the window passes; the same applies to wrong current passwords and to invalid API tokens. Only failures count. The first block, and at most one failed sign-in a minute per source, are audited. The shared `home_security.py` implements this. The API only accepts JSON, which together with
  `SameSite=Strict` covers CSRF.
- A logged-in session can download private keys. Treat access to the UI as access to the CA.
- ACME needs three things to issue: the client's address in `HOMECA_ACME_CLIENTS`, proof of control of the
  name over HTTP-01, and the name being inside the chosen CA's name constraints.
- Optional **OIDC/Keycloak login** is configured under **Server settings → OAuth / OIDC**. Local login stays available so an identity-provider outage or expired certificate cannot prevent CA recovery.
- Only explicitly allowed usernames or verified email addresses may use SSO. They use named administrator accounts with full access, including private-key downloads. The original local administrator remains the protected recovery account. Saved provider secrets are encrypted using a separate key derived from the existing master key.
- Public unauthenticated endpoints: `/crl/<id>.crl`, `/ca/<id>.crt`, `/ca/<id>.pem`.
- **API tokens** (Server settings → Access → API tokens) let a dashboard or monitor read `GET /api/summary` without a login. There is one level, **Read**, and it opens that one route: a token can never download a private key, list or fetch certificates, issue, renew, revoke or delete anything, change settings, read the audit log or manage tokens. Tokens belong to an administrator, are stored only as a SHA-256 hash, are shown once, can expire, and stop working when revoked or when their owner is removed. A bearer header never falls back to a login session, and repeated invalid tokens are throttled. Creating and revoking tokens is audited.
- **Audit log**, opened from the Logs button beside the settings cog, records who did what and when: sign-ins and failures, account and settings changes, every certificate created, signed, renewed, revoked or deleted, downloads of private keys and PKCS#12 bundles, the ACME issuing CA, and what ACME clients and the daily CRL job do (as `ACME client …` and `system`). Entries are kept 90 days (at most 50,000). Failed sign-ins are recorded once per source per minute. Passwords, keys, tokens, provider secrets and certificate contents are never written to it. Downloading public certificates is not recorded.

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
| `GET /api/summary` | Dashboard summary (login session **or** a Read API token); see below |
| `GET /api/tokens`, `POST /api/tokens`, `DELETE /api/tokens/{id}` | Manage API tokens (login session only) |
| `GET /api/audit?before=&limit=` | Audit entries, newest first (`before` is an entry id; `more` says whether older ones exist) |
| `GET /api/acme`, `POST /api/acme/ca` | ACME status; choose the issuing intermediate (`{"id": 2}` or `{"id": null}`) |
| `/acme/*` | The ACME protocol itself (directory, new-account, new-order, ...) |

### Summary for dashboards

    curl -H "Authorization: Bearer homeca_…" https://ca.example.net/api/summary

Returns the numbers the UI's overview shows, plus what needs attention, and nothing that identifies a key or certificate body:

- `roots`, `intermediates`, `active_leaves`, `expiring` (30 days or less), `expired`, `revoked`. Superseded leaves (renewed since) are ignored, as in the UI.
- `authorities`: for each root and intermediate, its common name, `status`, `days_left`, when its CRL is next due (`crl_next`) and `crl_overdue`.
- `attention`: up to 20 non-revoked, non-superseded certificates that are expiring or expired, with common name, `days_left` and whether ACME issued them. This is the one place a name of an issued certificate appears; SANs, serial numbers, PEM data and keys never do.
- `acme`: whether ACME is enabled and the issuing CA's name.

## Layout

    app/pki.py       X.509 building (keys, profiles, CRL, PKCS#12)
    app/ca.py        shared CA operations: master key, storage, CRLs, revocation
    app/auditlog.py  audit log: who did what, and GET /api/audit
    app/apitokens.py read-only API tokens: management routes and the session-or-token dependency
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

Trust uses the unchanged shared HomeTemplate `home-trust.js` and `home-trust.css` component. Uploads, certificate rows, messages and removal confirmation have one layout across Home* apps. OIDC provider roots belong in Trust. App-specific scope details are under “Where this trust store applies.”

## Administrator accounts

Server settings → Access groups named administrator accounts and OAuth / OIDC settings. Every account has full administrative access, matching HomeCaddy; application data remains shared. The original local administrator is migrated without changing its password and cannot be removed. Additional local accounts use passwords of at least 12 characters. Administrators can reset another account’s local password or remove an additional account; both actions revoke that account’s sessions. Password changes sign out only that account’s other sessions.

SSO identities are linked by issuer and subject to an exact username, with a verified email available for explicit allowlisting. Explicitly allowlisted new identities receive named SSO-only administrator accounts. The legacy environment-configured administrator match retains its original recovery-account mapping. Removing an account blocks its username and linked SSO subject from automatic provisioning; adding that username explicitly restores access. Removing an account does not remove certificates, keys, registry images or other shared application data.

Back up the application database before upgrading; it now also contains user password hashes, SSO links and removed-account blocks. Existing encryption/master-key backups remain necessary. Upgrading restarts the app and signs out existing in-memory sessions.

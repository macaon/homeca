# HomeCA

A small, self-hosted certificate authority with a web UI, built for homelabs.

It exists because some CA tools don't write Subject/Authority Key Identifier (SKI/AKI) extensions,
which breaks strict chain validation (`openssl verify -x509_strict`, and some Java, Go and Apple
clients). Every certificate HomeCA issues goes through one function, `pki.issue()`, so those
extensions cannot be forgotten.

## Features

- Root, intermediate and leaf certificates with RFC 5280-correct extensions
- **ACME server** (HTTP-01): Nginx Proxy Manager, certbot, Caddy and other ACME clients can request and renew certificates automatically
- Sign CSRs from devices, so their private keys never leave them
- Revocation with a signed CRL served over HTTP, refreshed automatically
- Dashboard of expiring and expired certificates, with one-click renew
- Downloads: certificate, full chain, DER, private key, PKCS#12
- ECDSA P-256 / P-384 and RSA 2048 / 3072 / 4096 keys
- Named administrator accounts, optional OIDC single sign-on, read-only API tokens for dashboards, and an audit log
- Private keys are encrypted at rest with a master key kept separate from the data
- Web UI with no build step or CDN; Auto, Light and Dark appearance

## Quick start (Docker or Podman)

    openssl rand -base64 32 > master.key
    chown 10001 master.key && chmod 400 master.key     # the container runs as uid 10001
    cp .env.example .env && $EDITOR .env               # set HOMECA_PUBLIC_URL, HOMECA_ACME_* (see below)
    docker compose up --build -d                       # podman compose works too
    open http://localhost:8080

1. On first visit, create the admin user (password of 12+ characters).
2. **+ New → Root CA**, then **Intermediate CA** under it, then **Leaf** certificates under that.
3. Install the root on your clients. Fetch it from `/ca/<id>.pem` (or `.crt` for DER).
4. Issue leaves from the intermediate. After creating the intermediate you rarely need the root again.

Verify a chain yourself:

    openssl verify -x509_strict -CAfile root.pem -untrusted intermediate.pem leaf.pem

A longer walkthrough is in [docs/usage.md](docs/usage.md).

## Configuration

Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `HOMECA_MASTER_KEY_FILE` | **required** | File containing the master key (12+ characters). Use a Docker/compose secret. |
| `HOMECA_DATA` | `./data` (`/data` in the container) | Directory holding `homeca.db` |
| `HOMECA_PUBLIC_URL` | unset | Base URL devices use to reach the plain-HTTP port, e.g. `http://ca.home.arpa:8080`. Comma-separate to list several (e.g. LAN and VPN names). Embedded in issued certs as the CRL distribution point and CA-issuer (AIA) URL; it is fixed at issuance, so changing it later doesn't update existing certs (renew them). If unset, those extensions are omitted and a warning is logged at startup. Keep it plain HTTP: clients must not need TLS to validate TLS. |
| `HOMECA_SECURE_COOKIE` | `0` | Set `1` once the UI is served over HTTPS by your reverse proxy |
| `HOMECA_TRUSTED_PROXIES` | unset | Your reverse proxy's address or network (comma-separated), e.g. `172.28.0.1`. Only requests from it may name the real client in `X-Forwarded-For`; everyone else's header is ignored. Without it sign-in limits and the audit log see the proxy's address for every user. Unrelated to the ACME allowlist, which always uses the real peer address. |
| `HOMECA_ACME_CLIENTS` | unset | Comma-separated CIDRs allowed to use ACME, e.g. `10.1.1.0/24` or NPM's IP. **Empty disables ACME.** |
| `HOMECA_ACME_HOSTNAME` | unset | Name ACME clients use for HomeCA, e.g. `ca.home.arpa`. HomeCA issues itself a TLS certificate for it. |
| `HOMECA_TLS_PORT` | `8443` | Port of the HTTPS (ACME) listener |
| `HOMECA_ACME_DAYS` | `90` | Lifetime of ACME-issued certificates |
| `HOMECA_OIDC_ISSUER`, `HOMECA_OIDC_CLIENT_ID`, `HOMECA_OIDC_CLIENT_SECRET_FILE`, `HOMECA_OIDC_ADMIN_MATCH`, `HOMECA_OIDC_CA_FILE` | unset | Optional single sign-on configured from the environment. The same settings can be made in the UI (see below), which then takes precedence. |

Put the UI behind your reverse proxy for TLS if you like, but keep `/crl/*` and `/ca/*` reachable over
plain HTTP at `HOMECA_PUBLIC_URL`.

## Server settings

The settings cog beside your account name opens **Server settings**:

- **User Interface:** Auto, Light or Dark as the server default. Auto is the initial value, and the login page follows it. Each account can also choose its own date format.
- **Trust:** upload public PEM/DER certificates or a PEM bundle for your identity provider. System roots and `HOMECA_OIDC_CA_FILE` remain trusted. Private keys are rejected. This trust store is separate from your issuing CA hierarchy.
- **OAuth / OIDC:** enable SSO, paste an HTTPS issuer or full discovery URL, enter a client ID and secret, and list the usernames or verified emails allowed to sign in. The callback URL is `/auth/callback` on the external origin and is shown in the form. Saving does not need a restart; a saved secret shows as a masked placeholder, and leaving it blank keeps it.
- **Access:** administrator accounts and API tokens.

The audit log opens from the **Logs** button beside the cog.

### Accounts and single sign-on

Every account is a full administrator, and certificates and keys are shared between them. The first
administrator, created at setup, is the protected recovery account and cannot be removed. Additional local
accounts need passwords of at least 12 characters. Administrators can reset another account's password or
remove an account; both revoke that account's sessions. Changing your own password signs out your other
sessions.

SSO identities are linked by issuer and subject to an exact username; a verified email can also be
allowlisted. Allowlisted new identities get named, SSO-only administrator accounts. Removing an account
blocks its username and linked subject from automatic provisioning until you add that username again
explicitly. It does not remove certificates or keys.

If SSO fails, the login page shows a safe error. Local login stays available so an identity-provider
outage or expired provider certificate cannot lock you out of the CA; keep a working local password for
recovery.

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

CRL and CA-issuer locations are written into each certificate as absolute URIs (CRL Distribution Points,
[RFC 5280 §4.2.1.13](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13); Authority Information Access,
[§4.2.2.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1)). The issuer must therefore know its own public
URL when it signs, which is why `HOMECA_PUBLIC_URL` is a setting rather than derived from the request, and why it
cannot change for certificates already issued. A distribution point may list several URIs, which is what a
comma-separated `HOMECA_PUBLIC_URL` produces.

Revoking a certificate re-signs its issuer's CRL (30-day lifetime). A root has no issuer, so it
cannot be revoked. A daily job re-signs CRLs that have under 15 days left, so no login is needed to keep
them valid. ACME clients revoke through the protocol (`certbot revoke`).

Renewing a leaf in the UI issues a new certificate (new key if HomeCA holds the key, otherwise the
device's existing public key) and marks the old one "superseded" without revoking it. Revoke it yourself
if the old key may be compromised. Intermediates and roots cannot be renewed; create a new one.

## API

The web UI is a client of a JSON API under `/api`, and you can script against it. It is not versioned,
so read the release notes before upgrading.

**Conventions**

- Request and response bodies are JSON. Send `Content-Type: application/json` on writes; a few settings
  routes reject anything else with `415`.
- Errors are `{"detail": "message"}` with a matching status: `400` bad input, `401` not signed in,
  `403` wrong current password, `404` not found, `409` conflict, `429` too many failed attempts.
- **Authentication** is a session cookie named `homeca`, set by `POST /api/login` (`HttpOnly`,
  `SameSite=Strict`, 12 hours; sessions are in memory, so a restart signs everyone out). `GET /api/summary`
  also accepts `Authorization: Bearer <token>` with a Read API token; no other route does.
- Every route below needs a session unless it says otherwise. All signed-in accounts are administrators.
- Timestamps are ISO 8601 UTC strings.

Example:

    curl -c jar -H 'Content-Type: application/json' -d '{"username":"admin","password":"…"}' https://ca.example.net/api/login
    curl -b jar https://ca.example.net/api/certs

### Session and account

| Route | Purpose |
|---|---|
| `GET /api/state` | **No login needed.** `{setup_needed, logged_in, user, local, sso, ui: {theme}, date_format}` |
| `POST /api/setup` | **No login needed.** Create the first administrator, only while `setup_needed` (`{"username", "password"}`, password 12+ characters). Signs you in. `409` once set up. |
| `POST /api/login` | **No login needed.** `{"username", "password"}`; `401` on failure, throttled with `429` |
| `POST /api/logout` | End the session |
| `POST /api/password` | Change your own password (`{"current", "new"}`); `403` if `current` is wrong. Signs out your other sessions. |
| `GET /api/preferences`, `PUT /api/preferences` | Per-account preferences: `{"date_format": "auto"\|"iso"\|"day"\|"month"}` |
| `GET /login/oidc`, `GET /auth/callback` | Browser redirects for single sign-on; not for scripts |

### Certificates

| Route | Purpose |
|---|---|
| `GET /api/certs` | All certificates: `id, parent_id, kind, cn, not_after, status, days_left, superseded, sans, has_key, crl_next, acme, self` |
| `GET /api/certs/{id}` | One certificate with `subject`, `issuer`, `serial`, `not_before`, `not_after`, `revoked_at`, `revoke_reason`, `sha256`, decoded `extensions` and the issuing `params` |
| `POST /api/certs` | Create a certificate; returns `{"id"}` (body below) |
| `POST /api/certs/sign-csr` | Sign a CSR; returns `{"id"}` (body below) |
| `POST /api/certs/{id}/renew` | Re-issue a leaf and mark the old one superseded; returns `{"id"}` of the new one. `400` for roots, intermediates and ACME-managed certificates. |
| `POST /api/certs/{id}/revoke` | `{"reason": "unspecified"\|"key_compromise"\|"affiliation_changed"\|"superseded"\|"cessation_of_operation"}`; re-signs the issuer's CRL |
| `DELETE /api/certs/{id}` | Delete; `409` while it has issued certificates |
| `GET /api/certs/{id}/download?format=…` | `pem` (default), `der`, `chain` (certificate plus ancestors), `key` (private key, PEM) or `p12` (PKCS#12; set its password with `pw_p12`). Private-key downloads are audited. |

`status` is one of `valid`, `expiring` (under 30 days), `expired` or `revoked`. `kind` is `root`,
`intermediate` or `leaf`.

`POST /api/certs`:

| Field | Meaning |
|---|---|
| `kind` | `root`, `intermediate` or `leaf` (required) |
| `parent_id` | Issuing CA's id; omit for a root, required otherwise |
| `subject` | Object with any of `c`, `st`, `l`, `o`, `ou`, `cn` |
| `sans` | Subject alternative names for leaves, plain names or IP addresses, e.g. `["host.home.arpa", "192.168.1.1"]` |
| `key_type` | `ec256` (default), `ec384`, `rsa2048`, `rsa3072`, `rsa4096` |
| `days` | Validity, 1 to 36500 (default 365); clamped to the issuer's `notAfter` |
| `path_len` | Intermediate path length, 0 to 10 (default 0) |
| `permitted` | Intermediate name constraints, e.g. `["home.arpa", "10.0.0.0/8"]` |
| `usage` | Leaf extended key usage: `server` (default), `client` or `both` |

`POST /api/certs/sign-csr`: `parent_id` (the issuing CA, required), `csr_pem` (required), `sans` (omit to
keep the CSR's), `days` and `usage` as above.

### ACME

| Route | Purpose |
|---|---|
| `GET /api/acme` | `{enabled, ca_id, ca_cn, clients, hostname, tls_port, days, directory}` |
| `POST /api/acme/ca` | Choose the issuing intermediate (`{"id": 2}`) or disable ACME (`{"id": null}`). Returns the new status; `400` if the CA isn't a valid intermediate or its name constraints exclude `HOMECA_ACME_HOSTNAME`. |
| `/acme/*` | The ACME protocol itself (directory, new-account, new-order, …) on the HTTPS port; used by ACME clients, not by scripts |

### Summary for dashboards

`GET /api/summary` takes a session **or** a Read API token:

    curl -H "Authorization: Bearer homeca_…" https://ca.example.net/api/summary

It returns the numbers the UI's overview shows, plus what needs attention, and nothing that identifies a key or certificate body:

- `roots`, `intermediates`, `active_leaves`, `expiring` (under 30 days), `expired`, `revoked`. Superseded leaves (renewed since) are ignored, as in the UI.
- `authorities`: for each root and intermediate, its `kind`, `cn`, `status`, `days_left`, when its CRL is next due (`crl_next`) and `crl_overdue`.
- `attention`: up to 20 non-revoked, non-superseded certificates that are expiring or expired, with `cn`, `kind`, `status`, `days_left` and whether ACME issued them. This is the one place a name of an issued certificate appears; SANs, serial numbers, PEM data and keys never do.
- `acme`: `{enabled, ca}`, whether ACME is enabled and the issuing CA's name.

### API tokens

Create them under **Server settings → Access**. There is one level, **Read**, and it opens `GET /api/summary` and nothing else.

| Route | Purpose |
|---|---|
| `GET /api/tokens` | `{tokens: [{id, name, scope, owner, created, expires, last_used, expired}], scopes}` |
| `POST /api/tokens` | `{"name", "scope": "read", "expires_days"?}` (days 1 to 3650, omit for no expiry). Returns `{"id", "token"}`; **the token is shown only in this response.** At most 100 tokens; names are unique. |
| `DELETE /api/tokens/{id}` | Revoke |

### Accounts, settings and audit

| Route | Purpose |
|---|---|
| `GET /api/users` | `[{username, local, primary, admin}]` |
| `POST /api/users` | Add a local account (`{"username", "password"}`; username letters, digits and `_ . @ -`, password 12+ characters) |
| `PUT /api/users/{username}/password` | Reset another account's password (`{"password"}`); revokes its sessions. Use `/api/password` for your own. |
| `DELETE /api/users/{username}` | Remove an account and its tokens. You cannot remove yourself or the original administrator. |
| `GET /api/settings` | `{ui: {theme}, oidc, oidc_secret_configured, callback_url}`; the client secret is never returned |
| `PUT /api/settings/interface` | `{"theme": "auto"\|"light"\|"dark"}`, the server default appearance |
| `PUT /api/settings/oidc` | `{enabled, issuer, client_id, client_secret, allowed_users}`; a blank `client_secret` keeps the saved one |
| `GET /api/settings/trust` | Uploaded provider trust certificates |
| `POST /api/settings/trust` | `{"name", "certificate"}` (PEM, DER or a PEM bundle); private keys are rejected |
| `DELETE /api/settings/trust/{fingerprint}` | Remove a trust certificate |
| `GET /api/audit?before=&limit=` | Audit entries `{id, ts, actor, action, target, detail}`, newest first. `limit` is 1 to 200 (default 50); pass the last `id` as `before` to page. The response is `{entries, more}`. |

### Public endpoints (no login)

Devices fetch these over plain HTTP, so keep them reachable at `HOMECA_PUBLIC_URL`.

| Route | Returns |
|---|---|
| `GET /crl/{id}.crl` | The CA's current CRL (DER) |
| `GET /ca/{id}.crt` | A root or intermediate certificate, DER |
| `GET /ca/{id}.pem` | A root or intermediate certificate, PEM |

## Security model

- **Two secrets.** The admin **password** only logs you in (scrypt-hashed). The **master key** file
  encrypts every private key (passphrase-encrypted PKCS#8) and lets HomeCA sign without anyone logged in,
  which ACME and the daily CRL job need. A stolen backup or volume is useless without the master key;
  anyone who can read both the running container's secret and its data can use the CA.
- Losing the master key means losing every stored private key. Keep a copy somewhere safe, separate from backups.
- You can change the admin password in the UI. The master key cannot be rotated in place. Saved SSO provider secrets are encrypted with a key derived from it.
- Sessions live in memory with an `HttpOnly`, `SameSite=Strict` cookie; a restart logs everyone out.
  After 10 failed sign-ins for an account from one source within five minutes (or 30 from one source across accounts) further attempts get HTTP 429 until the window passes; the same applies to wrong current passwords and to invalid API tokens. Only failures count. The first block, and at most one failed sign-in a minute per source, are audited. The API only accepts JSON, which together with `SameSite=Strict` covers CSRF.
- A logged-in session can download private keys. Treat access to the UI as access to the CA.
- ACME needs three things to issue: the client's address in `HOMECA_ACME_CLIENTS`, proof of control of the
  name over HTTP-01, and the name being inside the chosen CA's name constraints.
- Only explicitly allowed usernames or verified email addresses may use SSO, and they become full administrators with private-key access.
- **API tokens** let a dashboard or monitor read `GET /api/summary` without a login. A token can never download a private key, list or fetch certificates, issue, renew, revoke or delete anything, change settings, read the audit log or manage tokens. Tokens belong to an administrator, are stored only as a SHA-256 hash, are shown once, can expire, and stop working when revoked or when their owner is removed. A bearer header never falls back to a login session. Creating and revoking tokens is audited.
- **Audit log** records who did what and when: sign-ins and failures, account and settings changes, every certificate created, signed, renewed, revoked or deleted, downloads of private keys and PKCS#12 bundles, the ACME issuing CA, and what ACME clients and the daily CRL job do (as `ACME client …` and `system`). Entries are kept 90 days (at most 50,000). Failed sign-ins are recorded once per source per minute. Passwords, keys, tokens, provider secrets and certificate contents are never written to it. Downloading public certificates is not recorded. Each event is also written as one JSON line on stdout for log collectors.

### Upgrading from the passphrase version

Earlier versions used one passphrase for both login and key encryption. Put that passphrase into the
master key file and start the new version: it already matches what is stored, so no keys are
re-encrypted. The first visit then asks you to create the admin user.

## Backup

    docker run --rm -v homeca-data:/d -v "$PWD":/b alpine tar czf /b/homeca-backup.tgz -C /d .

The volume holds `homeca.db` (encrypted keys, certificates, CRLs, ACME accounts, accounts, SSO links, settings and the audit log) and `tls/`.
Back up `master.key` separately; the backup is useless without it, and it is useless without the backup.
Back up before upgrading; the app restarts and signs everyone out.

## Layout

    app/pki.py         X.509 building (keys, profiles, CRL, PKCS#12)
    app/ca.py          shared CA operations: master key, storage, CRLs, revocation
    app/acme.py        ACME server (RFC 8555, HTTP-01)
    app/main.py        FastAPI routes, auth, public CRL/CA endpoints
    app/accounts.py    administrator accounts
    app/apitokens.py   read-only API tokens
    app/auditlog.py    audit log and GET /api/audit
    app/preferences.py per-account preferences, OIDC and trust settings
    app/__main__.py    entry point: HTTP :8080 and the HTTPS ACME listener with live certificate reload
    app/store.py       SQLite schema and connection helper
    app/static/        the web UI (vendored, no build step)
    tests/             test suite
    Containerfile, compose.yaml

## Development

    python -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
    .venv/bin/python -m pytest tests
    HOMECA_MASTER_KEY_FILE=./master.key HOMECA_DATA=./data .venv/bin/python -m app

The tests cover chain building (AKI/SKI linkage, strict verification), login and master-key checks, and
a complete ACME client flow: account, order, challenge, finalize, certificate, revocation and rejection
cases. The ACME flow was also run end to end against real certbot (issue, renew, revoke).

## Not included

DNS-01 / wildcards, OCSP, importing an existing CA, per-user roles, and master-key rotation.

## License

HomeCA is free software, released under the GNU General Public License, version 3. See [LICENSE](LICENSE).

## AI disclosure

Parts of this project's code, tests and documentation were written with the help of AI coding assistants. A human directs the work and reviews it. Use at your own risk, and read what it does before trusting it with your CA's keys.

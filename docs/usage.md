# HomeCA — Usage Guide

HomeCA is your private certificate authority. You use it to hand out TLS certificates to
things on your own network — the NAS, Proxmox, the router, internal web apps — so browsers
and clients stop complaining, without anything being exposed to the public internet.

<p class="callout info">This page covers <strong>using</strong> HomeCA day to day. Installation, environment variables and backups live in the repository README.</p>

This guide assumes HomeCA is already running and reachable, and that a root CA either exists
or is about to be created by you.

---

## The mental model

HomeCA issues three kinds of certificate, in a strict hierarchy:

| Kind | What it is | How often you touch it |
|---|---|---|
| **Root** | The anchor of trust. Its public certificate is what you install on your laptops, phones and servers. | Once, then almost never |
| **Intermediate** | Signs everything day to day on the root's behalf. | Once every few years |
| **Leaf** | The actual certificate a service presents to clients. | Constantly |

The rule of thumb: **create one root, create one intermediate under it, then only ever work
with leaves.** Clients trust the root; the root's private key then sits idle, which is the
whole point of having an intermediate.

<p class="callout warning">HomeCA will let you issue leaves straight from the root and shows a warning when you try. It works, but it keeps the root key in daily use and puts every leaf on the root's revocation list. Use an intermediate.</p>

---

## The dashboard

After logging in you land on a single page with four areas.

**The counters along the top**

`Root CAs` · `Intermediates` · `Active leaves` · `Expiring ≤ 30 d` · `Expired` · `Revoked`

Revoked and superseded certificates are excluded from the live counts, so "Active leaves"
is what is actually in service.

**ACME** — whether automatic issuance is on, and which CA serves it. Covered under
*Automatic certificates with ACME* below.

**Needs attention** — only appears when something expires within 30 days or has already
expired, sorted by urgency. This is the list to act on.

**Certificates** — the full hierarchy as a tree: roots at the top level, their
intermediates indented beneath, leaves beneath those. Click any entry to open it.

### Reading the badges

| Badge | Meaning |
|---|---|
| `valid` | More than 30 days of life left |
| `expiring` | 30 days or fewer remain — renew it |
| `expired` | Past its `notAfter`; clients are already rejecting it |
| `revoked` | Deliberately invalidated and listed on the issuer's CRL |
| `superseded` | A newer certificate replaced it (via **Renew**). Still technically valid, not revoked, and greyed out in the tree |
| `ACME` | Issued automatically to a client over the ACME protocol |
| `HomeCA TLS` | HomeCA's own certificate for its HTTPS/ACME port. It renews itself — leave it alone |

---

## Issuing certificates

Everything starts with the **+ New** button in the header. It opens one dialog with four
tabs: **Root CA**, **Intermediate CA**, **Leaf** and **Sign CSR**. HomeCA pre-selects the
tab that makes sense — Root on an empty install, Intermediate once a root exists, Leaf once
an intermediate exists.

### Creating the root CA

Only the subject matters here.

| Field | Guidance |
|---|---|
| **Common name** | A human label, not a host name. `Home Root CA` is fine. |
| **Valid for (days)** | Defaults to 3650 (10 years). Longer is reasonable for a root: replacing it means re-installing trust on every client. |
| **Key** | `ECDSA P-256` unless you have a client that can't handle it. Small, fast, universally supported now. Pick RSA 2048/3072/4096 only for genuinely old gear. |
| **More subject fields** | Organisation, Unit, Country, State, Locality. Cosmetic — they show up when someone inspects the certificate. |

### Creating the intermediate

Same fields, plus two that matter:

- **Name constraints** *(optional, one per line)* — a hard limit on what this CA is allowed
  to certify, e.g. `home.arpa` and `10.0.0.0/8`. Anything outside is refused at issuance
  time, including over ACME. Write DNS names **without** a leading dot: `home.arpa` already
  covers `nas.home.arpa`.
- **Path length** — how many further CA levels may exist below this one. Leave it at `0`:
  this intermediate may sign leaves, and nothing else may sign CAs.

<p class="callout success">A name constraint is the single most useful safety feature here. If this CA's key ever leaks, the damage is confined to names you own.</p>

Default validity is 1825 days (5 years). An intermediate cannot be renewed — when it nears
expiry you create a new one and re-issue leaves from it.

### Issuing a leaf (HomeCA holds the key)

This is the common case: HomeCA generates the key pair, signs the certificate, and you
download both.

| Field | Guidance |
|---|---|
| **Issuer** | The intermediate. HomeCA pre-selects the lowest CA in the hierarchy. |
| **Common name** | The primary host name, e.g. `nas.home.arpa`. |
| **Subject alternative names** | One per line. DNS names, IP addresses or e-mail addresses. **Modern clients only look at SANs, not the common name** — so repeat the host name here and add every other name and IP the service answers on. |
| **Usage** | `Server (TLS)` for anything a browser or client connects to. `Client (mTLS)` for a certificate that authenticates *to* something. `Both` when it does both. |
| **Valid for (days)** | Defaults to 365. |
| **Key** | As for CAs — `ECDSA P-256` by default. |

<p class="callout warning">Apple platforms reject <em>server</em> certificates valid for more than 398 days. HomeCA warns you inline when you exceed that with a server or dual-usage certificate. If any iPhone, iPad or Mac will connect to this service, stay at or below 398 days.</p>

A `notAfter` later than the issuing CA's own expiry is clamped automatically — a leaf can
never outlive its issuer.

### Signing a CSR (the device keeps its key)

Use this whenever the device can make its own key — then the private key never travels and
never sits in HomeCA's database. Generate the request on the device:

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout router.key -out router.csr -subj "/CN=router.home.arpa" \
  -addext "subjectAltName=DNS:router.home.arpa,IP:192.168.1.1"
```

Then **+ New → Sign CSR**, pick the issuer, paste the PEM block, set usage and validity.

What HomeCA does with it:

- Verifies the request's self-signature.
- Keeps the **public key** and the **subject**.
- Applies its own leaf profile. **Extensions requested in the CSR are ignored**, except SANs.
- Leaves the SAN list editable in the dialog — fill it in to override what the CSR asked for.

The result has no stored private key, so the detail view offers no **Private key** or
**PKCS#12** download.

---

## Working with an existing certificate

Click any entry in the tree or in **Needs attention** to open its detail dialog. It shows
the subject, the status, a bar for how much of the lifetime is gone, the validity dates,
the issuer, the serial, the SHA-256 fingerprint, the SANs, and a full table of decoded
X.509 extensions — useful when a client is being picky and you want to see exactly what was
written.

### Downloads

| Button | File | Use it for |
|---|---|---|
| **Certificate** | PEM, this certificate only | Most Linux services, alongside the key |
| **Full chain** | PEM, leaf + intermediates | What nearly every web server actually wants. **Start here.** |
| **DER** | Binary | Windows, Java keystores, network gear |
| **Private key** | Unencrypted PEM | Only when HomeCA generated the key |
| **PKCS#12…** | `.p12` bundle, password-prompted | Windows, macOS keychains, Java, printers, anything that imports "a certificate with its key" as one file |

Choosing **PKCS#12…** prompts for a password. Set one — many importers refuse a bundle
without it.

### Renewing a leaf

**Renew** issues a fresh certificate with the same subject, SANs and lifetime:

- If HomeCA holds the key, it generates a **new key pair**. You must download and install
  the new key as well as the new certificate.
- If the certificate came from a CSR, it reuses the device's existing public key — so the
  device only needs the new certificate file.
- The old certificate is marked `superseded`. **It is not revoked** and keeps working until
  it expires, which gives you a window to roll out the new one.

<p class="callout info">If the old key might be compromised, revoke the superseded certificate yourself — renewing alone does not invalidate it.</p>

Renew is only offered for leaves that HomeCA manages. It is deliberately hidden for
ACME-issued certificates (the client renews those itself) and for HomeCA's own TLS
certificate. Roots and intermediates cannot be renewed at all — create a new one.

### Revoking

**Revoke…** asks for a reason: `unspecified`, `key_compromise`, `affiliation_changed`,
`superseded`, `cessation_of_operation`. HomeCA then immediately re-signs the issuing CA's
CRL, which is published at `/crl/<issuer id>.crl` and embedded in every certificate it
issues as the CRL distribution point.

Notes on revocation:

- **A root cannot be revoked** — it has no issuer to revoke it. To retire a root, remove it
  from your clients' trust stores.
- CRLs have a 30-day lifetime, and a daily job re-signs any with under 15 days left. Nobody
  needs to be logged in for that to happen.
- Revocation is only as good as your clients' willingness to check a CRL. Many don't. Treat
  it as hygiene, not as a kill switch — for that, reconfigure the service.
- ACME clients revoke through the protocol: `certbot revoke --server <directory url>`.

### Deleting

**Delete** removes the record and any stored private key permanently. A certificate that
has issued others cannot be deleted — you get `has issued certificates; delete those first`.
Deleting is not revoking: if the certificate is still deployed somewhere, it carries on
working, and you have thrown away the ability to revoke it. Revoke first, delete later.

---

## Getting the root onto your clients

Nothing trusts HomeCA until you install the root. Download it from the root's detail view,
or fetch it directly — these two URLs need no login:

```
http://ca.home.arpa:8080/ca/<id>.pem    # PEM, for Linux, Caddy, curl, most tooling
http://ca.home.arpa:8080/ca/<id>.crt    # DER, for Windows and Android
```

Rough guide per platform:

- **Debian/Ubuntu** — drop the PEM in `/usr/local/share/ca-certificates/` as `.crt`, run `update-ca-certificates`
- **Fedora/RHEL** — drop it in `/etc/pki/ca-trust/source/anchors/`, run `update-ca-trust`
- **Windows** — import the `.crt` into *Trusted Root Certification Authorities* (machine store)
- **macOS** — add to the System keychain, then set it to *Always Trust*
- **iOS/Android** — install the profile, then explicitly enable it for SSL in settings
- **Firefox** — has its own store; import separately
- **Java / Python / Node** — each may need its own truststore or `*_CA_BUNDLE` variable

Install the **root** only. Intermediates travel with the leaf, which is why servers should
be configured with the **Full chain** download.

Verify a chain the way a strict client would:

```bash
openssl verify -x509_strict -CAfile root.pem -untrusted intermediate.pem leaf.pem
```

---

## Automatic certificates with ACME

HomeCA speaks ACME (the Let's Encrypt protocol) with the HTTP-01 challenge, so Caddy,
certbot, Nginx Proxy Manager, Proxmox and HomeCaddy can request and renew certificates on
their own. Certificates are 90 days by default, and the client renews them without you.

**Turning it on:** open a valid **intermediate** and click **Use for ACME**. The ACME card
on the dashboard then shows the directory URL to give your clients. Allowed client addresses
and the hostname are set through configuration, not the UI — see the README.

The ACME card tells you where you stand:

| Row | What to check |
|---|---|
| `Issuing CA` | Which intermediate signs ACME requests. `none` means ACME is off |
| `Directory` | The URL clients need, e.g. `https://ca.home.arpa:8443/acme/directory` |
| `Allowed clients` | The networks permitted to ask. Empty means nothing can |
| `Lifetime` | Days per issued certificate |

The badge reads `enabled`, `no clients allowed` (a CA is chosen but the allowlist is empty)
or `off`. **Turn off** stops ACME without deleting anything; existing certificates keep
working, renewals stop.

Three things must all be true for an ACME request to succeed:

1. The client's real address is in the allowed list.
2. The client proves control of the name over HTTP-01 — HomeCA must be able to resolve the
   name and reach **port 80** on the client.
3. The name falls inside the issuing CA's name constraints.

<p class="callout warning">Wildcards are not available over ACME. They need the DNS-01 challenge, which HomeCA does not implement. Issue wildcards by hand as a leaf instead.</p>

Certificates that arrive this way show an `ACME` badge, have no stored private key (the
client holds it) and no **Renew** button.

---

## Routine maintenance

**Weekly, in 30 seconds.** Open the dashboard. If **Needs attention** is absent, you are
done. If not, each entry is a click away from **Renew** (or a certbot run on the client, for
ACME ones).

**Changing your password.** **Password** in the header. Needs the current one, the new one
must be 12+ characters. All other sessions are signed out. Stored private keys are untouched
— they are encrypted with the master key, not your password.

<p class="callout danger">The master key file is separate from your password and cannot be rotated in place. Lose it and every stored private key is unrecoverable. Keep a copy somewhere other than your backups — a backup without the key is useless, and the key without a backup is useless.</p>

**A restart logs everyone out.** Sessions are held in memory only. That is normal, not a
fault.

---

## Troubleshooting

| What you see | What it means |
|---|---|
| `has issued certificates; delete those first` | You are deleting a CA that still has children. Delete or retire them first. |
| `only leaf certificates can be renewed` | Roots and intermediates are not renewable. Create a new one. |
| `this certificate is renewed automatically through ACME` | The client owns this certificate's renewal. Run the renewal there. |
| No **Renew** button on a leaf | It is ACME-issued or it is HomeCA's own TLS certificate. |
| No **Private key** / **PKCS#12** button | HomeCA never had the key — it was a CSR or an ACME certificate. |
| Browser still warns after installing the root | The server is probably serving the leaf alone. Re-deploy with **Full chain**. Or: the browser has its own trust store (Firefox), or the SAN list is missing the name actually being used. |
| `openssl verify` fails but the browser is happy | Check the SAN list, and that you passed the intermediate with `-untrusted`. |
| An ACME client gets a 403 or no response | Its address is outside the allowed list, the requested name is outside the CA's name constraints, or HomeCA can't reach it on port 80 for the challenge. |
| The directory row says `set HOMECA_ACME_HOSTNAME` | ACME has no hostname configured — a setup task, see the README. |
| A certificate is `expired` but the service still works | The client isn't validating, or it cached the old certificate. Fix it anyway. |

---

## API, for scripting

Anything the UI does can be done over HTTP. All `/api` routes except `state`, `setup` and
`login` need the session cookie from `POST /api/login`.

| Route | Purpose |
|---|---|
| `GET /api/certs` | Every certificate with status and days left |
| `GET /api/certs/{id}` | Details and decoded extensions |
| `POST /api/certs` | Create a root, intermediate or leaf |
| `POST /api/certs/sign-csr` | Sign a CSR |
| `POST /api/certs/{id}/renew` | Re-issue a leaf |
| `POST /api/certs/{id}/revoke` | Revoke, with a reason |
| `GET /api/certs/{id}/download?format=pem\|der\|chain\|key\|p12` | Download |
| `GET /api/acme` · `POST /api/acme/ca` | ACME status; pick the issuing CA |
| `GET /crl/{id}.crl` · `GET /ca/{id}.pem` · `GET /ca/{id}.crt` | Public, no login needed |

A monitoring one-liner, for example:

```bash
curl -s --cookie jar http://ca.home.arpa:8080/api/certs \
  | jq -r '.[] | select(.status=="expiring" or .status=="expired") | "\(.cn) \(.days_left)d"'
```

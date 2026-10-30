# Home* Applications — Design Guidelines

**Version 0.1.1 · 30 October 2026**

**Source:** [HomeTemplate repository](https://git.home.arpa/home.arpa/hometemplate)
**Status:** baseline for new Home* apps; adopt deliberately in existing apps.

Home* applications should feel related without forcing every application into the same workflow. Familiar controls, restrained surfaces, useful information and predictable settings matter more than decoration.

This baseline draws on HomeCaddy, HomeCA, HomeRegistry, HomeApps and HomeDash, with AzerothCore included in the wider design family. The recent HomeDash and HomeCaddy headers and settings establish the current convention. Older applications may still use earlier menu arrangements; they are references, not evidence that every existing screen already follows this document.

The repository contains the canonical Markdown, a backend-independent HomeUI library, an interactive component catalogue, and a runnable FastAPI starter. The BookStack edition is published from this same Markdown. Never edit a published copy independently and leave the source behind.

## 1. Design principles

1. **Lead with the task.** Put the application’s daily work on its main page. Settings should support that work, rather than occupy the main interface.
2. **Keep familiar things in familiar places.** Navigation, administration and personal account controls have different roles and locations.
3. **Make information earn its space.** Names and useful descriptions lead a card. Hostnames, timestamps and technical identifiers are secondary.
4. **Make state truthful.** Empty, pending, offline, failed and stale are different conditions. Never fill an unfinished screen with fabricated operational metrics.
5. **Use one visual vocabulary.** Reuse tokens and components instead of introducing slightly different buttons, menus or dialog layouts in each app.
6. **Keep deployment separate.** Templates contain generic examples, not personal hostnames, credentials, identity-provider clients or live databases.

The requirements below are the baseline. Optional features should appear only when the application needs them. A small app does not need a navigation menu, metrics, API tokens or every settings tab merely because another Home* app has them.

## 2. Visual foundations

### Colour and themes

Use semantic CSS variables. Do not sprinkle app-specific hex values through components.

| Token | Light | Dark | Purpose |
| --- | --- | --- | --- |
| `--bg` | `#f6f7fb` | `#0e0f14` | Page canvas and inset fields |
| `--card` | `#ffffff` | `#171922` | Cards, menus and dialogs |
| `--text` | `#14151a` | `#eceef6` | Primary content |
| `--muted` | `#6b7080` | `#9298ab` | Secondary labels and helper text |
| `--line` | `#e4e6ee` | `#2a2d3a` | Borders and separators |
| `--accent` | `#4f46e5` | `#7c75ff` | Main actions and identity mark |
| `--accent-text` | `#ffffff` | `#0e0f14` | Text on accent surfaces |
| `--hover` | `#f0f1f8` | `#1f2230` | Quiet interaction feedback |

Status tokens are `--ok`, `--warn`, `--bad` and `--off`, with corresponding background tokens. Use status colours for meaning, not decoration. Show an accessible label or another textual cue alongside colour-dependent information.

Both themes must remain readable for links, visited links, disabled controls, placeholders, borders and focus indicators. Accent buttons must explicitly retain `--accent-text` in visited states; generic link colours must not recolour their labels.

### Appearance policy

Every new installation defaults to **Auto**. Auto follows the operating system through `prefers-color-scheme`; it is not an alias for Dark.

An administrator can set **Auto**, **Light** or **Dark** under **Server settings → User Interface → Default appearance**. The server persists this default and applies it to the login and setup pages before the main UI paints. Render the validated default into the initial HTML rather than waiting for an authenticated settings request.

Signed-in users may choose a personal appearance. Personal choices must be scoped to the app and account, not a single `theme` key shared by everyone using that browser. The starter keeps those choices in browser storage. A logout returns to the server default; a personal choice must never recolour the anonymous login page. Offer a way to return to the server default.

For Auto, remove the explicit `data-theme` attribute. For Light or Dark, set `data-theme="light"` or `data-theme="dark"`. CSS handles system changes while Auto is selected.

### Type, spacing and shape

| Element | Baseline |
| --- | --- |
| Body | System font stack, 15 px, line height 1.5 |
| Brand | 22 px, weight 750, slightly tight letter spacing |
| Section heading | 13 px, weight 600, uppercase, restrained tracking |
| Card title | 17 px, weight around 600, line height 1.3 |
| Secondary text | 13 px; hostnames and compact status around 11 px |
| Commands / IDs | System monospace, approximately 12.5 px |
| Spacing | 4, 8, 12, 16, 20, 24 and 32 px |
| Card radius | 12 px |
| Control radius | 8 px |
| Default content width | 960 px, with 16 px side gutters |
| Card padding | 18 px; compact screens may use 16 px |

Use quiet shadows for elevated surfaces. Compact service cards use a fine border with little or no resting shadow. Avoid giant headings, decorative gradients, oversized hero sections and dashboard elements with no operational purpose.

Use one outline icon family with consistent stroke weight. Icons should support the label. Give icon-only buttons accessible names; do not rely on a tooltip as their only name. Commands and fingerprints use monospace, while ordinary names and descriptions use the interface font.

## 3. Header and menu roles

The consistent reading order is:

```text
[☰ when needed]  HomeApp   [expanded section links]           [⚙ if admin] [username ▾]
```

### App navigation

Navigation contains places such as Dashboard, Sites, Certificates, Servers and Issuers. Use visible section links by default when several primary views exist. Mark the current link with `aria-current="page"`.

Put **Navigation style** under **Server settings → User Interface**, following HomeCaddy. It selects **Expanded** or **Compact menu** and is saved per account, even though it appears in the settings dialog. Do not duplicate it in the account dropdown. Both modes use the same header behaviour.

On narrow screens, collapse navigation automatically, even if Expanded is selected. HomeUI uses a 900 px breakpoint. Do not make users change a preference merely to use a phone.

A single-view app needs no hamburger and no fake Dashboard tab. Remove the navigation controls entirely. HomeDash is the reference: its cog opens administration directly.

### Administration

Always put the **settings cog immediately left of the username**. It opens **Server settings**. Show it to administrators only, and enforce the same access restriction in the backend.

The cog does not become a hamburger when more settings tabs are added. The hamburger navigates application views; the cog opens administrative configuration.

Do not put server settings inside the account dropdown. Do not mix settings into a context menu belonging to one service card.

### Account controls

The username menu contains personal controls: appearance, personal layout preferences where relevant, password, personal API tokens if supported, and log out. An API-token entry belongs here only when the tokens genuinely represent the account; global credential administration belongs in server settings.

Hide password-change controls for accounts that cannot use a local password. Keep account menus compact. Clicking outside or pressing Escape closes a dropdown; Escape returns focus to its trigger. Dropdown code must also work when the clicked element is an SVG inside a button.

## 4. Server settings

Use a native modal dialog with a clear heading, a labelled close button and tabs. Use these names and ordering when the capabilities exist:

| Tab | Contents |
| --- | --- |
| **User Interface** | Server appearance default and relevant layout preferences |
| **Trust** | Shared public CA certificates for outbound connections |
| **Access** | Accounts and roles, OAuth / OIDC provider configuration and access-related audit |

Within Access, use clearly labelled Users, OAuth / OIDC and Audit sections when those capabilities exist. Each section keeps its own save actions and error feedback; do not mix the account and provider forms. Group related app-specific settings too: for example, a Models tab contains model-server connection details and model policies.

Keep the top-level tab list compact. Tabs wrap into additional rows at narrow widths rather than hiding options behind horizontal scrolling. The dialog body scrolls vertically for longer forms and grouped sections. Preserve keyboard tab navigation across wrapped rows.

Omit unused tabs and sections. Add an app-specific tab when there is a genuine configuration group, rather than squeezing unrelated settings into User Interface.

Forms save per tab, with specific labels such as **Save interface settings** or **Save OAuth settings**. Keep unsaved values on validation failure, show the error within the form, disable submission while it is running, and give a brief success notification.

### Identity and roles

Support local accounts independently of optional OIDC when using the supplied platform starter. The first administrator is created interactively; never ship a default password.

Show whether an account is local or SSO-only and whether it is an administrator. Authentication does not determine the application’s business-data access model. HomeCaddy accounts administer shared proxy infrastructure; HomeDash users own private resources. The starter does not silently apply either model to new domain data.

An SSO identity must not gain administrator rights merely by matching a display label. The starter trusts a deliberately configured issuer to assert `preferred_username`, links exact matching local accounts, rejects conflicting subject links, and requires explicit allowlisting for unknown identities. Newly created SSO accounts are non-administrators. Preserve the established role and resources of linked accounts.

Protect destructive account actions. A user cannot remove their own account; role changes must not leave the app without an administrator. Do not implement automatic account merges or delete duplicates as a side effect of login.

### OIDC and secrets

Accept either the issuer URL or its full `/.well-known/openid-configuration` URL. Normalize it consistently and show the exact redirect URI required by the identity provider. Explain the difference between saving provider details and enabling the provider.

Keep saved issuer and client ID values visible. Return no saved secret to the browser. Use an empty password input with a masked placeholder and a message such as **Saved; leave blank to keep it**. Blank means retain; clearing or rotating a secret requires an explicit action. Encrypt saved secrets at rest, keep the encryption key out of the repository, and document backups.

When OIDC is enabled, use stacked, equal-width, centred **Log in** and **Log in with SSO** actions. The SSO action can be an anchor styled as a button: it navigates to the login endpoint and must not submit the password form. Hide it when disabled or before initial administrator setup.

### Certificate trust

Where an app makes outbound HTTPS requests, prefer one administrator-managed trust store to repeated certificate textareas in service editors. Support multiple public certificates and bundles, show name, subject, expiry and fingerprint, and reject private keys. Keep public system roots enabled.

A certificate-verification error should identify the action needed: **Ask an administrator to upload the service CA under Server settings → Trust**. Do not replace the error with a raw traceback or quietly turn verification off. Trust-store changes should take effect without a rebuild; invalidate relevant clients or caches deliberately.

Application trust, browser trust and the app’s own inbound HTTPS certificate are different concerns. State that distinction in help text when users need it.

## 5. Cards and operational information

Service cards lead with a 58–64 px icon area, app name and a concise description. Place the hostname in a small footer. Keep **Open** as the main action and put **Edit** and **Remove** in a small **⋯** menu. Long names must wrap; descriptions may clamp visually to two lines while remaining fully editable.

Use links for navigation and buttons for actions. Browser-launch cards open with `target="_blank"` and `rel="noopener noreferrer"`. Remote-desktop app launch is a different operation and belongs to that app’s launch API and helper, not to the generic card component.

A plain availability check needs only a small dot beside the hostname. Provide an accessible Online/Offline/Pending label and expose useful details on hover, focus or activation. Do not allocate a whole metrics section to `HTTP 200`, a large Connected label and a timestamp.

Live integrations may show a small set of meaningful measurements. Label units and stale values. A failed refresh must not make an old measurement look current. For browser checks, prefer **Online** and **Offline** to **Connected** and **Disconnected**.

Adding a service should allow selecting a supported service type and configuring its check in the same form. The GUI should present installed capabilities; declarative integration definitions and code extension belong in maintained files, not an obligatory JSON editor in everyday product flows.

For shared checks, make edits predictable: either clearly explain that all attached services will change or create a service-specific copy. Do not keep polling an unattached check without a visible purpose. Removing a group should not silently delete its service cards.

## 6. Forms, dialogs and feedback

- Give every input a persistent label. Placeholders are examples, not substitutes for labels.
- Keep help close to the relevant field and explain what the user needs to decide.
- Use sensible defaults; collect optional details under a clearly named disclosure only when needed.
- Use monospace for commands and API examples. Autofill must preserve unrelated host, URL and command fields unless changing them is the explicit action.
- Show required versus optional information clearly. Avoid nested forms.
- Use a native `<dialog>` so focus and Escape behaviour work. Keep dialog content within the viewport and scroll the dialog body on small screens.
- Confirm destructive actions with the item’s name and the real consequence. Focus Cancel by default. Never put destructive behaviour on a generic Save button.
- Use brief notifications for successful actions. Errors stay next to the failed action, with user data intact. Never include raw credentials or provider responses in notifications.

For empty states, explain what belongs in the section and give one useful first action. For filtered lists, distinguish **No matching services** from **No services yet**. For slow operations, prevent duplicate submission and show a meaningful busy label.

## 7. Accessibility and responsive behaviour

Use real buttons, links, labels, headings and form controls. Native semantics are preferable to clickable generic elements. Decorative icons have `aria-hidden="true"`; icon-only controls have a meaningful accessible name.

Maintain a visible focus indicator. Tabs use `aria-controls`, `aria-selected` and labelled tab panels; Left/Right, Home and End work from the keyboard. Menus close with Escape and outside clicks. Native dialogs restore focus to their trigger. Announce notifications with status or alert semantics.

Do not rely on hover, colour or drag alone. A card-ordering workflow also needs keyboard-accessible move actions. Keep important errors reachable without a pointer. Respect reduced-motion preferences.

Verify at desktop and narrow widths. Navigation collapses, form rows stack, grids cannot force horizontal scrolling, and tables scroll within their own container. Keep controls comfortably usable; the baseline 36 px icon button and 40 px login action can be enlarged for touch-heavy applications.

## 8. Frontend and backend boundaries

HomeUI provides styles and browser interaction helpers. It does not grant permissions, store credentials, fetch infrastructure APIs, decide who owns a resource, or perform deployment.

Every protected endpoint must enforce authentication, roles and resource ownership. Hiding the cog is presentation, not authorization. Validate URLs and input lengths, retain certificate verification, bound API responses and timeouts, and keep tokens on the server.

Serve UI assets locally and pin their version. Avoid a runtime dependency on another Home* app or a shared external asset host. Make HTML and JavaScript upgrades coherent: version assets or use suitable cache policy so a new cog cannot be paired with old JavaScript that has no click handler.

Backend defaults must be independent of the current deployment. Use configuration for public origins, proxy bindings, storage and optional provider details. Never copy a running app’s database, certificate private key or identity-provider secret into a starter.

## 9. Template and component adoption

The repository layout is:

```text
ui/                         canonical CSS and JavaScript
examples/                   interactive component catalogue
starter/                    working FastAPI platform shell
scripts/new_app.py          generates a separate application
scripts/check.py            runs release checks
docs/design-guidelines.md   this document
docs/component-api.md       helper contracts and markup
VERSION / CHANGELOG.md      version and compatibility notes
```

Create a new application with:

```sh
python3 scripts/new_app.py --name HomeExample --output /path/to/new-app
cd /path/to/new-app
cp .env.example .env
docker compose up -d --build
```

The generated app includes a pinned local `ui/` copy, `HOMEUI_VERSION`, this guideline as `DESIGN.md`, and project conventions in `AGENTS.md`. It contains working local login, optional OIDC, Users, Trust and User Interface settings. Business views are explicitly empty placeholders. Set the exact public origin before deploying behind a reverse proxy.

A different backend can use only `ui/` and follow the same behavioural contracts. The FastAPI starter is an implementation option, not part of the visual identity.

Do not put app-specific styling directly into the pinned library. Add a small app stylesheet loaded afterward. Promote a rule into HomeUI only after it is useful across applications. Upgrades are explicit: review the changelog, replace the vendored UI files, update `HOMEUI_VERSION`, and run both shared and app-specific checks. Existing apps are not automatically rewritten or upgraded by publishing this kit.

## 10. Review checklist and versioning

Before calling an app ready:

- The main task is clear; navigation, administration and account actions are separated.
- The admin cog is immediately left of the username; a single-view app has no redundant hamburger.
- Auto is the fresh-install default. Server Light/Dark affects anonymous login; personal choices do not leak to it.
- Light, Dark and system-following Auto are usable, including visited links and error states.
- Menus, tabs, dialogs and destructive confirmations work with keyboard input.
- Secret retention, role checks and ownership boundaries have meaningful backend tests.
- Empty, busy, failed, offline and stale states are truthful and actionable.
- Narrow layouts work; card density and information hierarchy remain useful.
- No deployment secrets or personal machine configuration are tracked.
- Documentation, screenshots and release notes reflect the delivered behaviour.

Version the design and implementation together. During `0.x`, minor versions may introduce reviewed component changes; document any migration. Patch versions correct compatible defects. Do not silently change meaning under an existing release tag. A component catalogue and starter smoke test should accompany releases.

The canonical source of changes is this repository. After a guideline change, update the BookStack page from the same file and verify that the published Markdown matches it. Keep deployment-specific operating instructions in each app’s own guide rather than in this shared design baseline.

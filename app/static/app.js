const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const lines = (id) => $(id).value.split("\n").map((s) => s.trim()).filter(Boolean);
const fmtDate = (s) => new Date(s).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
const KIND = { root: "Root", intermediate: "Intermediate", leaf: "Leaf" };
let certs = [];

async function api(path, method = "GET", body) {
  const r = await fetch(path, { method, headers: body ? { "Content-Type": "application/json" } : {}, body: body && JSON.stringify(body) });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== "/api/login") return init();
  if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Invalid input");
  return data;
}

// ---------- auth ----------
async function init() {
  const s = await api("/api/state");
  $("app").hidden = !s.logged_in;
  $("auth").hidden = s.logged_in;
  if (s.logged_in) return load();
  $("pw2-row").hidden = !s.setup_needed;
  $("pw2").required = s.setup_needed;
  $("auth-btn").textContent = s.setup_needed ? "Create admin user" : "Log in";
  $("auth-hint").textContent = s.setup_needed
    ? "First run: choose an admin username and a password (12+ characters). Private keys are encrypted separately, with the master key file."
    : "Log in to manage your CA.";
  $("pw").autocomplete = s.setup_needed ? "new-password" : "current-password";
  $("user").focus();
  window.setupNeeded = s.setup_needed;
}

$("auth-form").onsubmit = async (e) => {
  e.preventDefault();
  $("auth-err").textContent = "";
  if (window.setupNeeded && $("pw").value !== $("pw2").value) return ($("auth-err").textContent = "Passwords don't match");
  try {
    await api(window.setupNeeded ? "/api/setup" : "/api/login", "POST", { username: $("user").value, password: $("pw").value });
    $("pw").value = $("pw2").value = "";
    init();
  } catch (err) { $("auth-err").textContent = err.message; }
};
$("pwd-btn").onclick = () => { $("pw-err").textContent = ""; $("pw-form").reset(); $("pwdlg").showModal(); };
$("pw-form").onsubmit = async (e) => {
  e.preventDefault();
  try {
    await api("/api/password", "POST", { current: $("pw-cur").value, new: $("pw-new").value });
    $("pwdlg").close();
  } catch (err) { $("pw-err").textContent = err.message; }
};
$("logout-btn").onclick = async () => { await api("/api/logout", "POST"); init(); };

// ---------- dashboard ----------
async function load() {
  certs = await api("/api/certs");
  const live = certs.filter((c) => c.status !== "revoked" && !c.superseded);
  const count = (st) => live.filter((c) => c.status === st).length;
  $("stats").innerHTML = [
    [certs.filter((c) => c.kind === "root").length, "Root CAs"],
    [certs.filter((c) => c.kind === "intermediate").length, "Intermediates"],
    [live.filter((c) => c.kind === "leaf" && c.status !== "expired").length, "Active leaves"],
    [count("expiring"), "Expiring ≤ 30 d"],
    [count("expired"), "Expired"],
    [certs.filter((c) => c.status === "revoked").length, "Revoked"],
  ].map(([n, l]) => `<div class="stat"><b>${n}</b><span>${l}</span></div>`).join("");

  const attn = live.filter((c) => c.status === "expiring" || c.status === "expired")
    .sort((a, b) => a.days_left - b.days_left);
  renderAcme(await api("/api/acme"));
  $("attention-card").hidden = !attn.length;
  $("attention").innerHTML = attn.map(nodeHtml).join("");

  $("empty").hidden = certs.length > 0;
  $("tree").innerHTML = certs.length ? treeHtml(null) : "";
  document.querySelectorAll(".node").forEach((n) => (n.onclick = () => show(+n.dataset.id)));
}

function renderAcme(a) {
  const inters = certs.filter((c) => c.kind === "intermediate" && c.status === "valid");
  const row = (k, v) => `<dt>${k}</dt><dd>${v}</dd>`;
  const state = a.enabled ? `<span class="badge valid">enabled</span>`
    : `<span class="badge expiring">${a.ca_id ? "no clients allowed" : "off"}</span>`;
  $("acme").innerHTML = `<p>${state} <span class="muted">Let NPM, certbot or Caddy request and renew certificates automatically.</span></p>
    <dl class="kv">
      ${row("Issuing CA", a.ca_id ? esc(a.ca_cn) : `<span class="muted">none. Open an intermediate and choose <b>Use for ACME</b>.</span>`)}
      ${row("Directory", a.directory ? `<code>${esc(a.directory)}</code>` : `<span class="muted">set HOMECA_ACME_HOSTNAME</span>`)}
      ${row("Allowed clients", a.clients.length ? esc(a.clients.join(", ")) : `<span class="muted">none. Set HOMECA_ACME_CLIENTS.</span>`)}
      ${row("Lifetime", `${a.days} days`)}
    </dl>
    ${a.ca_id ? `<button id="acme-off">Turn off</button>` : !inters.length ? `<p class="muted">Create an intermediate CA first.</p>` : ""}`;
  const off = $("acme-off");
  if (off) off.onclick = async () => { await api("/api/acme/ca", "POST", { id: null }); load(); };
}

const badge = (c) => c.status === "valid" ? `<span class="badge valid">valid</span>` : `<span class="badge ${c.status}">${c.status}</span>`;
function nodeHtml(c) {
  const sub = c.status === "revoked" ? "" : c.days_left < 0 ? `expired ${-c.days_left} d ago` : `${c.days_left} d left`;
  return `<li><button class="node ${c.superseded ? "dim" : ""}" data-id="${c.id}">
    <span class="badge kind">${KIND[c.kind]}</span><span class="cn">${esc(c.cn)}</span>
    ${c.self ? `<span class="badge kind" title="HomeCA's own HTTPS certificate (ACME port)">HomeCA TLS</span>` : c.acme ? `<span class="badge kind">ACME</span>` : ""}
    ${c.superseded ? `<span class="badge superseded">superseded</span>` : ""}
    <span class="sub">${esc(sub)}</span>${badge(c)}</button></li>`;
}
function treeHtml(parent) {
  const kids = certs.filter((c) => c.parent_id === parent).sort((a, b) => a.cn.localeCompare(b.cn));
  if (!kids.length) return "";
  return `<ul class="list ${parent === null ? "" : "children"}">` +
    kids.map((c) => nodeHtml(c).replace(/<\/li>$/, treeHtml(c.id) + "</li>")).join("") + "</ul>";
}

// ---------- detail ----------
async function show(id) {
  const d = await api(`/api/certs/${id}`);
  const total = new Date(d.not_after) - new Date(d.not_before);
  const pct = Math.max(0, Math.min(100, 100 - ((new Date(d.not_after) - Date.now()) / total) * 100));
  const dl = (fmt, label) => `<a href="/api/certs/${id}/download?format=${fmt}"><button>${label}</button></a>`;
  const san = (d.params.sans || []).join(", ");
  $("detail").innerHTML = `
    <div class="dlg-head"><h2>${esc(d.subject)}</h2><button class="ghost" data-close>✕</button></div>
    <p><span class="badge kind">${KIND[d.kind]}</span> ${badge(d)}
      ${d.revoked_at ? `<span class="muted">revoked ${fmtDate(d.revoked_at)} (${esc(d.revoke_reason)})</span>` : ""}</p>
    ${d.self ? `<p class="muted">HomeCA's own HTTPS certificate for the ACME port. It renews automatically and is separate from any ACME-issued certificate with the same name.</p>` : ""}
    <div class="bar ${d.status}"><i style="width:${pct}%"></i></div>
    <div class="muted">${fmtDate(d.not_before)} → ${fmtDate(d.not_after)}${d.days_left != null ? ` · ${d.days_left} days left` : ""}</div>
    <dl class="kv">
      <dt>Issuer</dt><dd>${esc(d.issuer)}</dd>
      <dt>Serial</dt><dd class="mono">${esc(d.serial)}</dd>
      <dt>SHA-256</dt><dd class="mono">${esc(d.sha256)}</dd>
      ${san ? `<dt>SANs</dt><dd>${esc(san)}</dd>` : ""}
    </dl>
    <h2>Extensions</h2>
    <table>${d.extensions.map((e) => `<tr><td>${esc(e.name)}${e.critical ? " <small>(critical)</small>" : ""}</td><td class="mono">${esc(e.value)}</td></tr>`).join("")}</table>
    <div class="actions">
      ${dl("pem", "Certificate")}${dl("chain", "Full chain")}${dl("der", "DER")}
      ${d.has_key ? dl("key", "Private key") + `<button id="p12">PKCS#12…</button>` : ""}
      ${d.kind === "leaf" && !d.acme && !d.self ? `<button id="renew">Renew</button>` : ""}
      ${d.kind === "intermediate" && d.status === "valid" ? `<button id="use-acme">Use for ACME</button>` : ""}
      ${d.parent_id && !d.revoked_at ? `<button class="danger" id="revoke">Revoke…</button>` : ""}
      <button class="danger" id="del">Delete</button>
    </div>
    <p class="error" id="detail-err" role="alert"></p>`;
  const act = (btn, fn) => ($("detail").querySelector(btn) || {}).onclick = async () => {
    try { await fn(); } catch (e) { $("detail-err").textContent = e.message; }
  };
  act("#p12", () => {
    const pw = prompt("Password to protect the .p12 file (many importers require one):");
    if (pw !== null) location.href = `/api/certs/${id}/download?format=p12&pw_p12=${encodeURIComponent(pw)}`;
  });
  act("#use-acme", async () => { await api("/api/acme/ca", "POST", { id }); $("detail").close(); load(); });
  act("#renew", async () => { const r = await api(`/api/certs/${id}/renew`, "POST"); await load(); show(r.id); });
  act("#revoke", async () => {
    const reason = prompt("Reason: unspecified, key_compromise, affiliation_changed, superseded, cessation_of_operation", "unspecified");
    if (reason) { await api(`/api/certs/${id}/revoke`, "POST", { reason }); await load(); show(id); }
  });
  act("#del", async () => {
    if (confirm(`Delete "${d.subject}" and its stored key? This can't be undone.`)) {
      await api(`/api/certs/${id}`, "DELETE"); $("detail").close(); load();
    }
  });
  $("detail").showModal();
}

// ---------- new certificate ----------
const DAYS = { root: 3650, intermediate: 1825, leaf: 365, csr: 365 };
let kind = "leaf";

function setKind(k) {
  kind = k;
  $("fields").dataset.kind = k;
  document.querySelectorAll("#tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.kind === k));
  $("f-days").value = DAYS[k];
  $("f-cn").required = k !== "csr";
  const cas = certs.filter((c) => c.kind !== "leaf" && c.status === "valid" || c.kind !== "leaf" && c.status === "expiring");
  const ok = k === "intermediate" ? cas.filter((c) => c.kind === "root" || c.kind === "intermediate") : cas;
  $("f-parent").innerHTML = ok.map((c) => `<option value="${c.id}">${esc(c.cn)} (${KIND[c.kind].toLowerCase()})</option>`).join("");
  // prefer the lowest CA in the hierarchy for leaves
  const inter = ok.filter((c) => c.kind === "intermediate").pop();
  if (k !== "intermediate" && inter) $("f-parent").value = inter.id;
  warnDays();
  warnRoot();
}
function warnRoot() {
  const c = certs.find((c) => c.id === +$("f-parent").value);
  $("root-warn").hidden = !((kind === "leaf" || kind === "csr") && c && c.kind === "root");
}
$("f-parent").onchange = warnRoot;
function warnDays() {
  $("days-warn").hidden = !((kind === "leaf" || kind === "csr") && $("f-usage").value !== "client" && +$("f-days").value > 398);
}
$("f-days").oninput = $("f-usage").onchange = warnDays;
document.querySelectorAll("#tabs button").forEach((b) => (b.onclick = () => setKind(b.dataset.kind)));
$("new-btn").onclick = () => { $("new-err").textContent = ""; setKind(!certs.length ? "root" : certs.some((c) => c.kind === "intermediate") ? "leaf" : "intermediate"); $("new").showModal(); };

$("new-form").onsubmit = async (e) => {
  e.preventDefault();
  $("new-err").textContent = "";
  const base = { days: +$("f-days").value };
  const parent_id = +$("f-parent").value;
  if (kind !== "root" && !parent_id) return ($("new-err").textContent = "Create a CA to issue from first");
  try {
    let r;
    if (kind === "csr") {
      r = await api("/api/certs/sign-csr", "POST", { ...base, parent_id, csr_pem: $("f-csr").value, usage: $("f-usage").value,
        sans: lines("f-sans").length ? lines("f-sans") : null });
    } else {
      const subject = Object.fromEntries(["cn", "o", "ou", "c", "st", "l"].map((k) => [k, $("f-" + k).value]));
      r = await api("/api/certs", "POST", { ...base, kind, parent_id: kind === "root" ? null : parent_id, subject,
        key_type: $("f-key").value, sans: lines("f-sans"), usage: $("f-usage").value,
        permitted: lines("f-permitted"), path_len: +$("f-pathlen").value });
    }
    $("new").close();
    $("new-form").reset();
    await load();
    show(r.id);
  } catch (err) { $("new-err").textContent = err.message; }
};

document.addEventListener("click", (e) => { if (e.target.closest("[data-close]")) e.target.closest("dialog").close(); });
init();

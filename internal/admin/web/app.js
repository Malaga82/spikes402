// Spikes402 admin dashboard. Plain JS, no dependencies, no build step.
// Everything from the server is inserted with textContent, never as HTML:
// paths and bot names come from visitors and must not be trusted.
"use strict";

const $ = (id) => document.getElementById(id);
const state = { key: sessionStorage.getItem("spikes402-key") || "", seq: 0, first: true, recent: [], sprites: [], timers: [] };

// One colour per outcome group: the same four as the numbers on top.
const GROUP = { paid: "paid", "pow-solved": "pow", free: "pow", challenged: "held",
  rejected: "repelled", "rate-limited": "repelled", busy: "repelled", blocked: "repelled" };
const COLOR = { paid: "#ffc83d", pow: "#00e5ff", held: "#9aa3c7", repelled: "#ff4d6d" };
const OUTCOME = { paid: "paid ⚡", "pow-solved": "did the work", free: "let in (policy)", challenged: "stopped (402)",
  rejected: "fake proof", "rate-limited": "too fast (429)", busy: "busy (503)", blocked: "blocked (403)" };

async function api(method, path, body) {
  const res = await fetch(path, {
    method, headers: { Authorization: "Bearer " + state.key, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined, cache: "no-store",
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) { logout("Wrong admin key."); throw new Error("unauthorized"); }
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}
function rows(table, list) {
  table.replaceChildren(...list.map((cells) => { const tr = el("tr"); cells.forEach((c) => tr.append(el("td", c))); return tr; }));
}
const fmt = (n) => (n ?? 0).toLocaleString();
const time = (t) => new Date(t).toLocaleTimeString();
const who = (v) => (v.bot || "unknown") + (v.class === "impostor" ? " (fake)" : "");
const msg = (id, text, cls) => { $(id).className = "msg " + (cls || ""); $(id).textContent = text; };

// --- login and pages ---
async function login() {
  try {
    const me = await api("GET", "/api/whoami");
    sessionStorage.setItem("spikes402-key", state.key);
    $("login").hidden = true; $("nav").hidden = false; $("node").hidden = false;
    $("withdraw").hidden = !me.withdraw_enabled;
    state.role = me.role;
    if (me.role !== "admin") $("login-error").textContent = "This key has the AI role: it can suggest changes; it may apply only those that do not reduce protection.";
    route();
    state.timers.push(setInterval(pollSiege, 1000), setInterval(refresh, 5000),
      setInterval(() => { if (!$("stats").hidden) loadStats(); }, 15000));
    pollSiege(); refresh();
    requestAnimationFrame(frame);
  } catch (e) { $("login-error").textContent = e.message; }
}
function logout(text) {
  sessionStorage.removeItem("spikes402-key"); state.key = "";
  state.timers.forEach(clearInterval); state.timers = [];
  document.querySelectorAll(".page").forEach((s) => (s.hidden = true));
  $("nav").hidden = true; $("node").hidden = true; $("login").hidden = false;
  $("pause-banner").hidden = true; document.body.classList.remove("paused");
  $("login-error").textContent = text || "";
}
function route() {
  if (!state.key) return;
  const page = { "#settings": "settings", "#stats": "stats" }[location.hash] || "siege";
  for (const id of ["siege", "stats", "settings"]) $(id).hidden = id !== page;
  document.querySelectorAll("#nav a").forEach((a) => (a.dataset.page === page ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  if (page === "settings") { loadSettings(); loadProposals(); loadWithdrawals(); }
  if (page === "stats") loadStats();
}
window.addEventListener("hashchange", route);
$("login-form").addEventListener("submit", (e) => { e.preventDefault(); state.key = $("key").value.trim(); $("key").value = ""; login(); });
$("logout").addEventListener("click", () => { location.hash = ""; logout(); });

// --- siege monitor ---
async function pollSiege() {
  let data;
  try { data = await api("GET", "/api/siege?since=" + state.seq); } catch { return; }
  if (data.next < state.seq) state.seq = 0; // server restarted
  const visits = data.visits || [];
  state.seq = Math.max(state.seq, data.next);
  const now = Date.now();
  for (const v of visits) state.recent.push(Date.parse(v.time));
  state.recent = state.recent.filter((t) => now - t < 60000);
  const o = data.counts.by_outcome || {};
  $("s-rate").textContent = fmt(state.recent.length);
  $("s-paid").textContent = fmt(o.paid);
  $("s-pow").textContent = fmt(o["pow-solved"]);
  $("s-repelled").textContent = fmt((o.rejected || 0) + (o["rate-limited"] || 0) + (o.blocked || 0) + (o.busy || 0));
  renderFeed(visits);
  if (!state.first && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
    const show = visits.slice(-12);
    show.forEach((v, i) => setTimeout(() => spawn(v), (i * 1000) / show.length));
  }
  state.first = false;
}

function renderFeed(visits) {
  const feed = $("feed");
  for (const v of visits) {
    const tr = el("tr");
    tr.append(el("td", time(v.time)), el("td", who(v)), el("td", v.path), el("td", OUTCOME[v.outcome] || v.outcome, GROUP[v.outcome]));
    feed.prepend(tr);
  }
  while (feed.rows.length > 10) feed.deleteRow(feed.rows.length - 1);
}

// A visitor walks from the left to the wall, then passes the gate into the
// site or fades at the wall (repelled ones drift back). Names show on hover,
// or next to the dot when only a few are on screen.
const SVGNS = "http://www.w3.org/2000/svg";
const WALL_X = 610, GATE_Y = 205, MAX_SPRITES = 60, LABEL_BELOW = 6;

function spawn(v) {
  if (state.sprites.length >= MAX_SPRITES) state.sprites.shift().g.remove();
  const group = GROUP[v.outcome] || "held";
  const g = document.createElementNS(SVGNS, "g"); g.setAttribute("class", "sprite");
  const c = document.createElementNS(SVGNS, "circle"); c.setAttribute("r", 6); c.setAttribute("fill", COLOR[group]);
  const title = document.createElementNS(SVGNS, "title"); title.textContent = who(v) + " · " + (OUTCOME[v.outcome] || v.outcome);
  const label = document.createElementNS(SVGNS, "text"); label.setAttribute("x", 10); label.setAttribute("y", 4);
  label.textContent = v.bot ? who(v) : "";
  g.append(c, title, label);
  $("sprites").append(g);
  const y0 = 40 + Math.random() * 320;
  state.sprites.push({ g, label, group, t0: performance.now(), x0: 20 + Math.random() * 60, y0, ty: group === "paid" || group === "pow" ? GATE_Y + (Math.random() * 30 - 15) : y0 });
}

const ease = (t) => (t < 0 ? 0 : t > 1 ? 1 : 1 - Math.pow(1 - t, 2));
function frame(now) {
  const few = state.sprites.length <= LABEL_BELOW;
  state.sprites = state.sprites.filter((s) => {
    const t = now - s.t0, walk = 2600, after = t - walk;
    let x, y = s.ty, op = 1;
    if (after < 0) { const k = ease(t / walk); x = s.x0 + (WALL_X - s.x0) * k; y = s.y0 + (s.ty - s.y0) * k; }
    else if (s.group === "paid" || s.group === "pow") {
      const k = ease(after / 1800); x = WALL_X + (860 - WALL_X) * k; y = s.ty + (240 - s.ty) * k; op = 1 - Math.max(0, (after - 1000) / 800);
    } else {
      const k = ease(after / 1500); x = WALL_X - (s.group === "repelled" ? 80 * k : 0); op = 1 - k;
    }
    s.label.style.display = few ? "" : "none";
    s.g.setAttribute("transform", `translate(${x.toFixed(1)},${y.toFixed(1)})`);
    s.g.setAttribute("opacity", Math.max(0, op).toFixed(2));
    if (op <= 0) { s.g.remove(); return false; }
    return true;
  });
  if (state.key) requestAnimationFrame(frame);
}

// --- node indicator and settings page ---
async function refresh() {
  let st;
  try { st = await api("GET", "/api/status"); } catch { return; }
  const n = st.gate.node, s = st.settings;
  const bad = n.breaker_open || st.node_error;
  $("node").className = "node " + (bad ? "bad" : "ok");
  $("node-text").textContent = bad ? "Lightning: problem" : "Lightning OK";
  $("node").title = n.breaker_open ? "Paused after failures until " + time(n.breaker_open_until)
    : st.node_error || n.last_error || (st.node ? fmt(st.node.balance_sat) + " sats, " + st.node.channels + " channels" : s.lightning_backend);
  state.status = st;
  if (!$("settings").hidden) renderCurrent(st);
  if (st.node) $("wd-balance").textContent = fmt(st.node.balance_sat);
  $("wd-dest").textContent = s.withdraw_destination || "";
  $("pause-banner").hidden = !s.paused;
  document.body.classList.toggle("paused", !!s.paused);
}

function formatSurge(live, cfg) {
  if (!(live || []).length) {
    return (cfg && cfg.enabled) ? "on (no groups yet)" : "off (config file only)";
  }
  return live.map((g) => {
    const short = Number(g.demand_per_minute || 0).toFixed(1);
    const base = Number(g.baseline_per_minute || 0).toFixed(1);
    const ratio = g.warmed ? Number(g.ratio || 0).toFixed(2) + "×" : "warming up";
    return `${g.group}: ${g.multiplier}× → ${g.price_sats} sats (short ${short}/min, baseline ${base}/min, ${ratio})`;
  }).join("; ");
}

function renderCurrent(st) {
  const s = st.settings, n = st.gate.node, p = s.current_pow;
  const list = [["Origin", s.origin], ["Paused", s.paused ? "yes (protected paths are free)" : "no"],
    ["Protected", s.protect.join(" ")], ["Price", s.price_sats + " sats"],
    ["Path prices", (s.prices || []).map((r) => r.pattern + " = " + r.price_sats + " sats").join(", ") || "none (default only)"],
    ["Surge", formatSurge(st.gate.surge, s.surge)],
    ["Proof-of-work", `${p.Algorithm} difficulty ${p.Difficulty}` + (p.MemoryMiB ? `, ${p.MemoryMiB} MiB` : "")],
    ["Invoices / min (all)", s.max_invoices_per_minute], ["Bot identification", s.identify_bots ? "on" : "off"],
    ["Visitor IPs in monitor", s.visitor_ips], ["AI may apply changes", s.ai_can_apply ? "yes" : "no (propose only)"],
    ["Lightning backend", s.lightning_backend], ["Invoices created / failed", fmt(n.invoices_created) + " / " + fmt(n.invoice_failures)],
    ["Open invoices", fmt(st.gate.open_invoices)]];
  if (n.last_error) list.push(["Last Lightning error", n.last_error + " (" + time(n.last_error_at) + ")"]);
  rows($("set-current"), list);
}

async function loadSettings() {
  let s;
  try { s = await api("GET", "/api/settings"); } catch { return; }
  fillSettings(s);
  if (state.status) renderCurrent(state.status);
}
const POLICY_CLASSES = ["unknown", "impostor", "verified", "verified-signed"];
const POLICY_ACTIONS = [["pay", "Pay"], ["pow-only", "PoW only"], ["free", "Free"], ["block", "Block"]];

function fillSettings(s) {
  $("f-price").value = s.price_sats; $("f-sps").value = s.pow_seconds_per_sat; $("f-cpm").value = s.challenges_per_minute;
  $("f-pause").checked = !!s.paused;
  $("f-pause").disabled = state.role !== "admin";
  fillProtect(s.protect);
  fillPrices(s.prices);
  fillPolicies(s.bot_policies);
  state.current = s;
}

function fillPolicies(pol) {
  pol = pol || {};
  for (const k of POLICY_CLASSES) {
    const sel = $("pol-" + k);
    if (!sel.options.length) {
      for (const [value, label] of POLICY_ACTIONS) {
        const o = document.createElement("option");
        o.value = value; o.textContent = label;
        sel.append(o);
      }
    }
    sel.value = (pol[k] && pol[k].action) || "pay";
  }
}
function readPolicies() {
  const out = {};
  const cur = (state.current && state.current.bot_policies) || {};
  for (const k of POLICY_CLASSES) {
    const action = $("pol-" + k).value;
    const prev = cur[k] || {};
    const mult = prev.price_multiplier;
    if (action !== "pay") {
      out[k] = { action };
      if (mult && mult !== 1) out[k].price_multiplier = mult;
    } else if (mult && mult !== 1) {
      out[k] = { action: "pay", price_multiplier: mult };
    }
  }
  return out;
}
function classPolicies(pol) {
  const out = {};
  for (const k of POLICY_CLASSES) {
    if (pol && pol[k]) out[k] = pol[k];
  }
  return out;
}

function fillProtect(list) {
  $("f-protect").replaceChildren();
  const paths = list && list.length ? list : [""];
  paths.forEach((p) => $("f-protect").append(protectRow(p)));
}
function protectRow(pattern) {
  const tr = el("tr");
  const pat = document.createElement("input");
  pat.className = "pat"; pat.placeholder = "/premium/**"; pat.value = pattern || "";
  const actions = el("td", null, "actions");
  const up = el("button", "↑"); up.type = "button"; up.title = "Move up";
  const down = el("button", "↓"); down.type = "button"; down.title = "Move down";
  const del = el("button", "Remove"); del.type = "button";
  up.addEventListener("click", () => { const prev = tr.previousElementSibling; if (prev) tr.parentNode.insertBefore(tr, prev); });
  down.addEventListener("click", () => { const next = tr.nextElementSibling; if (next) tr.parentNode.insertBefore(next, tr); });
  del.addEventListener("click", () => { if ($("f-protect").rows.length > 1) tr.remove(); });
  actions.append(up, " ", down, " ", del);
  const tdPat = el("td"); tdPat.append(pat);
  tr.append(tdPat, actions);
  return tr;
}
function readProtect() {
  return [...$("f-protect").rows].map((tr) => tr.querySelector(".pat").value.trim()).filter((p) => p);
}

function fillPrices(list) {
  $("f-prices").replaceChildren();
  (list || []).forEach((r) => $("f-prices").append(priceRow(r.pattern, r.price_sats)));
}
function priceRow(pattern, sats) {
  const tr = el("tr");
  const pat = document.createElement("input");
  pat.className = "pat"; pat.placeholder = "/premium/**"; pat.value = pattern || "";
  const price = document.createElement("input");
  price.className = "sats"; price.type = "number"; price.min = "1"; price.max = "1000000";
  price.value = sats || 1;
  const actions = el("td", null, "actions");
  const up = el("button", "↑"); up.type = "button"; up.title = "Move up";
  const down = el("button", "↓"); down.type = "button"; down.title = "Move down";
  const del = el("button", "Remove"); del.type = "button";
  up.addEventListener("click", () => { const prev = tr.previousElementSibling; if (prev) tr.parentNode.insertBefore(tr, prev); });
  down.addEventListener("click", () => { const next = tr.nextElementSibling; if (next) tr.parentNode.insertBefore(next, tr); });
  del.addEventListener("click", () => tr.remove());
  actions.append(up, " ", down, " ", del);
  const tdPat = el("td"); tdPat.append(pat);
  const tdSats = el("td"); tdSats.append(price);
  tr.append(tdPat, tdSats, actions);
  return tr;
}
function readPrices() {
  return [...$("f-prices").rows].map((tr) => ({
    pattern: tr.querySelector(".pat").value.trim(),
    price_sats: +tr.querySelector(".sats").value,
  }));
}

$("f-price-add").addEventListener("click", () => $("f-prices").append(priceRow("", 1)));
$("f-protect-add").addEventListener("click", () => $("f-protect").append(protectRow("")));

function weakenReasons(cur, ch) {
  const why = [];
  if (ch.paused === true && !cur.paused) why.push("protected paths would be served free (pause)");
  if (ch.paused === false && cur.paused) why.push("protection would start charging again (unpause)");
  if (ch.price_sats != null && ch.price_sats < cur.price_sats) why.push("the default price would fall");
  if (ch.pow_seconds_per_sat != null && ch.pow_seconds_per_sat < cur.pow_seconds_per_sat) why.push("proof-of-work would get easier");
  if (ch.challenges_per_minute != null && ch.challenges_per_minute > cur.challenges_per_minute) why.push("the per-client rate limit would be raised");
  if (ch.protect) {
    const next = new Set(ch.protect);
    for (const p of cur.protect || []) {
      if (!next.has(p)) { why.push("a protect pattern would be removed or narrowed"); break; }
    }
  }
  if (ch.prices) {
    const oldMin = Math.min(cur.price_sats, ...(cur.prices || []).map((r) => r.price_sats));
    const newMin = Math.min(ch.prices.length ? Infinity : cur.price_sats, ...ch.prices.map((r) => r.price_sats));
    if (newMin < oldMin) why.push("a path price would fall");
  }
  if (ch.bot_policies) {
    for (const [k, v] of Object.entries(ch.bot_policies)) {
      if (v && v.action === "free") why.push("a bot policy would be set to free (" + k + ")");
    }
  }
  return why;
}

$("set-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const cur = state.current, ch = {};
  try {
    if ($("f-pause").checked !== !!cur.paused) ch.paused = $("f-pause").checked;
    if (+$("f-price").value !== cur.price_sats) ch.price_sats = +$("f-price").value;
    const protect = readProtect();
    if (JSON.stringify(protect) !== JSON.stringify(cur.protect || [])) ch.protect = protect;
    const prices = readPrices();
    if (JSON.stringify(prices) !== JSON.stringify(cur.prices || [])) ch.prices = prices;
    if (+$("f-sps").value !== cur.pow_seconds_per_sat) ch.pow_seconds_per_sat = +$("f-sps").value;
    if (+$("f-cpm").value !== cur.challenges_per_minute) ch.challenges_per_minute = +$("f-cpm").value;
    const pol = readPolicies();
    if (JSON.stringify(pol) !== JSON.stringify(classPolicies(cur.bot_policies))) ch.bot_policies = pol;
    if (!Object.keys(ch).length) return msg("set-msg", "Nothing changed.");
    const why = weakenReasons(cur, ch);
    if (state.role !== "admin") {
      if (why.length) {
        await api("POST", "/api/proposals", { changes: ch, reason: "would reduce protection: " + why.join("; ") });
        msg("set-msg", "Saved as a suggestion for the human admin (it would reduce protection).", "ok");
        return loadProposals();
      }
    } else if (why.length && !confirm("This would reduce protection:\n\n- " + why.join("\n- ") + "\n\nApply it anyway?")) {
      return;
    }
    fillSettings(await api("PUT", "/api/settings", ch));
    msg("set-msg", "Applied and saved.", "ok");
  } catch (err) {
    if (state.role !== "admin" && /propose it for the human admin/.test(err.message)) {
      try {
        await api("POST", "/api/proposals", { changes: ch, reason: "would reduce protection" });
        msg("set-msg", "Saved as a suggestion for the human admin (it would reduce protection).", "ok");
        return loadProposals();
      } catch (e2) { msg("set-msg", e2.message, "err"); return; }
    }
    msg("set-msg", err.message, "err");
  }
});

async function loadProposals() {
  let list;
  try { list = await api("GET", "/api/proposals"); } catch { return; }
  const box = $("prop-list");
  if (!list.length) return box.replaceChildren(el("p", "None. The AI admin (if you use one) can only suggest; nothing changes until you approve.", "note"));
  box.replaceChildren(...list.map((p) => {
    const d = el("div", null, "proposal");
    d.append(el("p", `${time(p.created)} · ${p.status}` + (p.reason ? " · " + p.reason : "") + (p.result ? " · " + p.result : "")));
    d.append(el("pre", JSON.stringify(p.changes)));
    if (p.status === "pending" && p.risks && p.risks.length) {
      d.append(el("p", "Needs your explicit confirmation: " + p.risks.join("; "), "msg err"));
    }
    if (p.status === "pending") {
      for (const [act, label] of [["approve", "Approve"], ["reject", "Reject"]]) {
        const b = el("button", label);
        b.addEventListener("click", async () => {
          try {
            if (act === "approve") {
              const why = weakenReasons(state.current || {}, p.changes || {});
              if (why.length && !confirm("This proposal would reduce protection:\n\n- " + why.join("\n- ") + "\n\nApprove it anyway?")) return;
              if (p.risks && p.risks.length && !confirm("This proposal could take your site down or cut off search engines:\n\n- " + p.risks.join("\n- ") + "\n\nApprove it anyway?")) return;
            }
            await api("POST", `/api/proposals/${encodeURIComponent(p.id)}/${act}` + (act === "approve" ? "?confirm=1" : ""));
            loadSettings(); loadProposals();
          } catch (err) { alert(err.message); }
        });
        d.append(b, " ");
      }
    }
    return d;
  }));
}

async function loadWithdrawals() {
  if ($("withdraw").hidden) return;
  let w;
  try { w = await api("GET", "/api/withdraw"); } catch { return; }
  const list = (w.history || []).slice(-5).reverse().map((h) => [time(h.time), fmt(h.amount_sat) + " sats", (h.unknown ? "? " : h.ok ? "✓ " : "✗ ") + h.result]);
  $("wd-unknown").hidden = !w.unresolved;
  if (w.locked_until) list.unshift(["Locked", "until " + time(w.locked_until), ""]);
  rows($("wd-history"), list);
}

let prepared = null;
$("wd-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  msg("wd-msg", "");
  try {
    prepared = await api("POST", "/api/withdraw/prepare", { amount_sat: +$("wd-amount").value, password: $("wd-pw").value });
    $("wd-pw").value = "";
    $("wd-c-amount").textContent = fmt(prepared.amount_sat) + (prepared.fee_sat ? " (+ about " + fmt(prepared.fee_sat) + " sats fee)" : "");
    $("wd-c-dest").textContent = prepared.destination;
    $("wd-c-exp").textContent = time(prepared.expires_at);
    $("wd-form").hidden = true; $("wd-confirm").hidden = false;
  } catch (err) { msg("wd-msg", err.message, "err"); }
});
$("wd-cancel").addEventListener("click", () => { prepared = null; $("wd-confirm").hidden = true; $("wd-form").hidden = false; });
$("wd-confirm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const amount = +$("wd-amount2").value;
  if (!prepared || amount !== prepared.amount_sat) return msg("wd-msg", "The amount does not match.", "err");
  if (!confirm(`Last check: send ${fmt(amount)} sats to ${prepared.destination}? This cannot be undone.`)) return;
  try {
    const r = await api("POST", "/api/withdraw/confirm", { confirm_id: prepared.confirm_id, amount_sat: amount, password: $("wd-pw2").value });
    msg("wd-msg", "Sent: " + r.result, "ok");
  } catch (err) { msg("wd-msg", err.message, "err"); }
  $("wd-pw2").value = ""; $("wd-amount2").value = ""; prepared = null;
  $("wd-confirm").hidden = true; $("wd-form").hidden = false; refresh(); loadWithdrawals();
});

async function resolveWithdrawal(sent) {
  if (!confirm(sent ? "You checked the node and the payment WAS sent?" : "You checked the node and the payment was NOT sent?")) return;
  try {
    await api("POST", "/api/withdraw/resolve", { sent, password: $("wd-pw3").value });
    msg("wd-msg", "Recorded.", "ok");
  } catch (err) { msg("wd-msg", err.message, "err"); }
  $("wd-pw3").value = ""; loadWithdrawals();
}
$("wd-sent").addEventListener("click", () => resolveWithdrawal(true));
$("wd-notsent").addEventListener("click", () => resolveWithdrawal(false));

if (state.key) login();

// --- statistics ---
state.range = "24h"; state.clients = [];
const KINDS = [ // order and colour of the kinds of client
  ["human", "People", "#3ddc84"], ["verified-bot", "Verified bots", "#00e5ff"], ["bot", "Bots and scripts", "#9aa3c7"],
  ["impostor", "Impostors", "#ff4d6d"], ["unknown", "Unclassified", "#6b74a0"]];
const KIND_LABEL = Object.fromEntries(KINDS.map(([k, l]) => [k, l]));
const IPMODE = { hash: "visitors are keyed hashes (new ones after a restart)", truncate: "visitors are shown by network (/24, /48)", full: "visitors are shown by full address" };

const avg = (sum, n) => (n ? sum / n : null);
function dur(ms) {
  if (ms === null || ms === undefined) return "–";
  if (ms < 1000) return Math.round(ms) + " ms";
  const s = ms / 1000;
  if (s < 60) return s.toFixed(s < 10 ? 1 : 0) + " s";
  return Math.floor(s / 60) + " min " + Math.round(s % 60) + " s";
}
const pct = (a, b) => (b ? Math.round((100 * a) / b) + "%" : "–");
function cell(text, cls, title) { const td = el("td", text, cls); if (title) td.title = title; return td; }

async function loadStats() {
  let r;
  try { r = await api("GET", "/api/stats?range=" + state.range + "&kind=" + encodeURIComponent($("cl-kind").value)); } catch { return; }
  const t = r.totals;
  $("st-note").textContent = "Collected since " + new Date(r.since).toLocaleString() + " · " + (IPMODE[r.visitor_ips] || IPMODE.hash);
  $("k-req").textContent = fmt(t.requests);
  $("k-views").textContent = fmt(t.page_views);
  $("k-views-split").textContent = fmt(t.human_views) + " people · " + fmt(t.bot_views) + " bots";
  $("k-ch").textContent = fmt(t.challenges);
  $("k-rate").textContent = t.challenges ? Math.round(100 * r.unlock_rate) + "%" : "–";
  $("k-sats").textContent = fmt(t.sats);
  $("k-paid").textContent = fmt(t.paid) + " paid · " + fmt(t.pow) + " by work";
  $("k-solve").textContent = dur(avg(t.solve_ms, t.solve_n));
  $("k-solve90").textContent = "average, from 402 to proof · " + fmt(t.solve_n) + " timed";
  $("k-dwell").textContent = t.dwell_n ? dur((1000 * t.dwell_s) / t.dwell_n) : "–";
  $("k-lat").textContent = dur(avg(t.latency_ms, t.latency_n));

  const day = r.range === "30d";
  bars($("ch-chart"), r.series, day, [
    ["paid ⚡", "#ffc83d", (b) => b.paid], ["did the work", "#00e5ff", (b) => b.pow],
    ["402, not unlocked", "#9aa3c7", (b) => Math.max(0, b.challenges - b.paid - b.pow)], ["repelled", "#ff4d6d", (b) => b.repelled]]);
  bars($("pv-chart"), r.series, day, [
    ["people", "#3ddc84", (b) => b.human_views], ["bots", "#00e5ff", (b) => b.bot_views],
    ["unclassified", "#9aa3c7", (b) => Math.max(0, b.page_views - b.human_views - b.bot_views)]]);
  renderLottery(r.lottery);
  renderKinds(r.kinds || {});
  renderPages(r.pages || []);
  state.clients = r.clients || []; state.clientsTotal = r.clients_total;
  renderClients();
}

// bars draws a stacked bar chart: one bar per hour (or day), a title per bar for hover.
function bars(svg, series, daily, layers) {
  const W = 600, H = 200, L = 40, B = 22, T = 8, pw = W - L - 6, ph = H - B - T;
  const totals = series.map((b) => layers.reduce((s, [, , f]) => s + f(b), 0));
  const max = niceMax(Math.max(1, ...totals));
  const n = series.length, bw = pw / n, gap = n > 60 ? 0.5 : 2;
  const kids = [];
  const svgEl = (tag, attrs, text) => {
    const e = document.createElementNS(SVGNS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (text !== undefined) e.textContent = text;
    return e;
  };
  for (const v of [0, max / 2, max]) {
    const y = T + ph - (v / max) * ph;
    kids.push(svgEl("line", { x1: L, x2: W - 6, y1: y, y2: y, class: "grid" }), svgEl("text", { x: L - 6, y: y + 4, "text-anchor": "end" }, fmt(v)));
  }
  series.forEach((b, i) => {
    const x = L + i * bw;
    let y = T + ph;
    for (const [, color, f] of layers) {
      const h = (f(b) / max) * ph;
      if (h <= 0) continue;
      y -= h;
      kids.push(svgEl("rect", { x: x + gap / 2, y, width: Math.max(0.5, bw - gap), height: Math.max(0.5, h - (h > 3 ? 1 : 0)), fill: color }));
    }
    const d = new Date(b.hour * 1000);
    const lbl = daily ? d.toLocaleDateString() : d.toLocaleString([], { weekday: n > 24 ? "short" : undefined, hour: "2-digit", minute: "2-digit" });
    const hit = svgEl("rect", { x, y: T, width: bw, height: ph, class: "hit" });
    hit.append(svgEl("title", {}, lbl + "\n" + layers.map(([name, , f]) => name + ": " + fmt(f(b))).join("\n")));
    kids.push(hit);
    const every = daily ? 5 : n > 24 ? 24 : 6;
    const at = daily ? i % every === 0 : (n > 24 ? d.getHours() === 0 : i % every === 0);
    if (at) kids.push(svgEl("text", { x: x + bw / 2, y: H - 6, "text-anchor": "middle" },
      daily ? d.toLocaleDateString([], { day: "numeric", month: "short" }) : n > 24 ? d.toLocaleDateString([], { weekday: "short", day: "numeric" }) : d.getHours().toString().padStart(2, "0") + ":00"));
  });
  svg.replaceChildren(...kids);
}
function niceMax(v) {
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function renderKinds(kinds) {
  const total = Object.values(kinds).reduce((s, k) => s + k.requests, 0) || 1;
  $("kinds").replaceChildren(...KINDS.map(([k, label, color]) => {
    const s = kinds[k] || { clients: 0, requests: 0, pages: 0, unlocks: 0, sats: 0 };
    const row = el("div", null, "row");
    const bar = el("div", null, "bar"), fill = el("i");
    fill.style.width = (100 * s.requests) / total + "%"; fill.style.background = color;
    bar.append(fill); bar.title = pct(s.requests, total) + " of requests";
    row.append(el("span", label), bar, el("span", fmt(s.clients) + " clients · " + fmt(s.requests) + " req · " + fmt(s.pages) + " pages · " + fmt(s.unlocks) + " unlocks · " + fmt(s.sats) + " sats", "nums"));
    return row;
  }));
}

function renderPages(pages) {
  const body = $("pages").tBodies[0];
  if (!pages.length) { body.replaceChildren(emptyRow(10, "No pages yet.")); return; }
  body.replaceChildren(...pages.map((p) => {
    const tr = el("tr"), unl = p.paid + p.pow;
    tr.append(cell(p.path, "path", p.path), cell(fmt(p.views), "n"), cell(fmt(p.challenges), "n"),
      cell(fmt(unl), "n", fmt(p.paid) + " paid · " + fmt(p.pow) + " by work"), cell(pct(unl, p.challenges), "n"), cell(fmt(p.sats), "n"),
      cell(dur(avg(p.solve_ms, p.solve_n)), "n"), cell(p.dwell_n ? dur((1000 * p.dwell_s) / p.dwell_n) : "–", "n", p.dwell_n ? p.dwell_n + " measured" : ""),
      cell(dur(avg(p.latency_ms, p.latency_n)), "n"), cell(fmt(p.visitors), "n"));
    return tr;
  }));
}

function renderClients() {
  const q = $("cl-search").value.trim().toLowerCase();
  const list = state.clients.filter((c) => !q || [c.visitor, c.agent, c.bot, c.user_agent, c.last_path].some((v) => (v || "").toLowerCase().includes(q)));
  $("cl-count").textContent = list.length + " shown" + (state.clientsTotal > state.clients.length ? " of the " + state.clients.length + " most recent (" + fmt(state.clientsTotal) + " in all)" : "");
  const body = $("clients").tBodies[0];
  if (!list.length) { body.replaceChildren(emptyRow(11, "No clients.")); return; }
  body.replaceChildren(...list.map((c) => {
    const tr = el("tr");
    const kind = el("td"); kind.append(el("span", KIND_LABEL[c.kind] || c.kind, "tag " + c.kind));
    const agent = c.bot && c.bot.toLowerCase() !== (c.agent || "").toLowerCase() ? c.agent + " (" + c.bot + ")" : c.agent;
    tr.append(cell(c.visitor, "path", c.class ? "class: " + c.class : ""), kind, cell(agent, "path", c.user_agent || "no User-Agent"),
      cell(fmt(c.requests), "n"), cell(fmt(c.pages), "n"), cell(fmt(c.challenges), "n"),
      cell(fmt(c.paid + c.pow), "n", fmt(c.paid) + " paid · " + fmt(c.pow) + " by work"), cell(fmt(c.sats), "n"),
      cell(dur(avg(c.solve_ms, c.solve_n)), "n"), cell(c.last_path, "path", c.last_path), cell(ago(c.last_seen), "", new Date(c.last_seen).toLocaleString()));
    return tr;
  }));
}
function emptyRow(span, text) { const tr = el("tr"), td = el("td", text, "note"); td.colSpan = span; tr.append(td); return tr; }
function ago(t) {
  const s = (Date.now() - Date.parse(t)) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago";
  return new Date(t).toLocaleDateString();
}

document.querySelectorAll("[data-range]").forEach((b) => b.addEventListener("click", () => {
  state.range = b.dataset.range;
  document.querySelectorAll("[data-range]").forEach((x) => x.setAttribute("aria-pressed", x === b));
  loadStats();
}));
$("cl-kind").addEventListener("change", loadStats);
$("cl-search").addEventListener("input", renderClients);

// --- Bitcoin lottery ---
function big(n) {
  if (!n) return "0";
  if (n < 1) return n.toPrecision(2);
  const u = [["E", 1e18], ["P", 1e15], ["T", 1e12], ["G", 1e9], ["M", 1e6], ["k", 1e3]].find(([, v]) => n >= v);
  return u ? (n / u[1]).toFixed(n / u[1] < 10 ? 1 : 0) + " " + u[0] : fmt(n);
}
function renderLottery(l) {
  $("lottery").hidden = !l;
  if (!l) return;
  $("l-hashes").textContent = big(l.hashes);
  $("l-best").textContent = l.best_difficulty ? big(l.best_difficulty) : "–";
  $("l-chance").textContent = l.chance > 0 ? "1 in " + big(1 / l.chance) : "–";
  $("l-blocks").textContent = fmt(l.blocks);
  $("l-shares").textContent = fmt(l.shares_accepted) + " shares accepted of " + fmt(l.shares_submitted);
  $("l-note").textContent = (l.connected ? "Connected to " : "Not connected to ") + l.pool + " · payout " + l.user +
    (l.height ? " · mining block " + fmt(l.height) : "") + (l.network_difficulty ? " · network difficulty " + big(l.network_difficulty) : "") +
    (l.pool_difficulty ? " · pool share difficulty " + big(l.pool_difficulty) : "") + (l.last_error ? " · last error: " + l.last_error : "");
}

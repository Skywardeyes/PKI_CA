const adminInput = document.getElementById("adminToken");
const intlClientNameInput = document.getElementById("intlClientName");
const gmClientNameInput = document.getElementById("gmClientName");
const intlKeepWebCacheInput = document.getElementById("intlKeepWebCache");
const gmKeepWebCacheInput = document.getElementById("gmKeepWebCache");
const gmCapabilityState = document.getElementById("gmCapabilityState");
const themeSelect = document.getElementById("themeSelect");
const intlOut = document.getElementById("intlOut");
const gmOut = document.getElementById("gmOut");
const intlResultCard = document.getElementById("intlResultCard");
const gmResultCard = document.getElementById("gmResultCard");
const intlWrapOutputInput = document.getElementById("intlWrapOutput");
const gmWrapOutputInput = document.getElementById("gmWrapOutput");
const tabLinks = document.querySelectorAll(".tab-link");
const tabPanels = document.querySelectorAll(".tab-panel");
const intlSserverStatusPill = document.getElementById("intlSserverStatusPill");
const gmSserverStatusPill = document.getElementById("gmSserverStatusPill");

function optionalReason(profile) {
  const el = document.getElementById(profile === "gm" ? "gmAuditReason" : "intlAuditReason");
  if (!el) return undefined;
  const s = el.value.trim();
  return s ? s : undefined;
}

function getOutEl(profile) {
  return profile === "gm" ? gmOut : intlOut;
}

function getCardHost(profile) {
  return profile === "gm" ? gmResultCard : intlResultCard;
}

function currentProfileFromTab() {
  const active = document.querySelector(".tab-link.is-active");
  const target = active ? active.getAttribute("data-tab-target") : "";
  return target === "gmSection" ? "gm" : "intl";
}

function log(obj, profile = currentProfileFromTab()) {
  const out = getOutEl(profile);
  out.textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderList(values) {
  if (!Array.isArray(values) || values.length === 0) return "-";
  return values.join("\n");
}

function extractResultMeta(data, profileHint = currentProfileFromTab()) {
  const d = (data && data.data) || {};
  return {
    ok: !!(data && data.ok),
    code: (data && data.code) || "UNKNOWN",
    message: (data && data.message) || "",
    profile: d.profile || profileHint,
    action: d.action || "-",
    duration: typeof d.duration_ms === "number" ? `${d.duration_ms} ms` : "-",
    steps: renderList(d.steps),
    artifacts: renderList(d.artifacts),
  };
}

function clearResultCard(profile) {
  const host = getCardHost(profile);
  if (!host) return;
  host.innerHTML = '<div class="result-empty">暂无结果，执行操作后会显示摘要卡片。</div>';
}

function renderResultCard(meta, profile) {
  const host = getCardHost(profile);
  if (!host) return;
  const okClass = meta.ok ? "ok" : "failed";
  const okText = meta.ok ? "SUCCESS" : "FAILED";
  const profileClass = meta.profile === "gm" ? "profile-gm" : "profile-intl";
  host.innerHTML = `
    <article class="result-card">
      <div class="result-card-head">
        <h4 class="result-card-title">${escapeHtml(meta.message || "执行结果")}</h4>
        <div class="result-badges">
          <span class="result-pill ${okClass}">${okText}</span>
          <span class="result-pill ${profileClass}">${escapeHtml(meta.profile.toUpperCase())}</span>
        </div>
      </div>
      <dl class="result-meta">
        <div class="result-meta-item"><span class="label">Code</span><span class="value">${escapeHtml(meta.code)}</span></div>
        <div class="result-meta-item"><span class="label">Action</span><span class="value">${escapeHtml(meta.action)}</span></div>
        <div class="result-meta-item"><span class="label">Duration</span><span class="value">${escapeHtml(meta.duration)}</span></div>
        <div class="result-meta-item"><span class="label">Steps</span><span class="value value-scroll">${escapeHtml(meta.steps)}</span></div>
        <div class="result-meta-item"><span class="label">Artifacts</span><span class="value value-scroll">${escapeHtml(meta.artifacts)}</span></div>
      </dl>
    </article>
  `;
}

function renderApiResultText(data) {
  const lines = [];
  lines.push(`[${data.ok ? "OK" : "FAILED"}] ${data.code || "UNKNOWN"}: ${data.message || ""}`);
  const d = data.data || {};
  if (d.profile) lines.push(`profile: ${d.profile}`);
  if (d.action) lines.push(`action: ${d.action}`);
  if (typeof d.duration_ms === "number") lines.push(`duration_ms: ${d.duration_ms}`);
  if (Array.isArray(d.steps) && d.steps.length) lines.push(`steps: ${d.steps.join(" -> ")}`);
  if (Array.isArray(d.artifacts) && d.artifacts.length) lines.push(`artifacts: ${d.artifacts.join(", ")}`);
  if (data.logs && typeof data.logs.stdout === "string" && data.logs.stdout.trim()) {
    lines.push("");
    lines.push("stdout:");
    lines.push(data.logs.stdout.trim());
  }
  if (data.logs && typeof data.logs.stderr === "string" && data.logs.stderr.trim()) {
    lines.push("");
    lines.push("stderr:");
    lines.push(data.logs.stderr.trim());
  }
  lines.push("");
  lines.push("raw:");
  lines.push(JSON.stringify(data, null, 2));
  return lines.join("\n");
}

function setTheme(mode) {
  if (mode === "dark" || mode === "light") {
    document.body.setAttribute("data-theme", mode);
  } else {
    document.body.removeAttribute("data-theme");
  }
}

function activateTab(targetId) {
  tabLinks.forEach((btn) => {
    const active = btn.getAttribute("data-tab-target") === targetId;
    btn.classList.toggle("is-active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
  });
  tabPanels.forEach((panel) => {
    const active = panel.id === targetId;
    panel.classList.toggle("is-active", active);
    panel.hidden = !active;
  });
}

function renderApiResult(data, profileHint = currentProfileFromTab()) {
  if (!data || typeof data !== "object" || !("ok" in data)) {
    log(data, profileHint);
    return;
  }
  const targetProfile = (data.data && data.data.profile) || profileHint;
  const out = getOutEl(targetProfile);
  renderResultCard(extractResultMeta(data, targetProfile), targetProfile);
  out.textContent = renderApiResultText(data);
}

function adminTokenValue() {
  return (adminInput.value || localStorage.getItem("pki_admin_token") || "").trim();
}

function apiBase(profile) {
  return profile === "gm" ? "/api/gm" : "/api/intl";
}

function profileClientName(profile) {
  return ((profile === "gm" ? gmClientNameInput : intlClientNameInput).value || "").trim() || (profile === "gm" ? "trainee-gm" : "trainee");
}

function profileP12Password(profile) {
  const id = profile === "gm" ? "gmP12Password" : "intlP12Password";
  const el = document.getElementById(id);
  return el ? el.value : "123456";
}

function headersJson() {
  const h = { "Content-Type": "application/json" };
  const t = adminTokenValue();
  if (t) h["X-Admin-Token"] = t;
  return h;
}

function headersGet() {
  const h = {};
  const t = adminTokenValue();
  if (t) h["X-Admin-Token"] = t;
  return h;
}

document.getElementById("saveToken").addEventListener("click", () => {
  const t = adminInput.value.trim();
  if (t) localStorage.setItem("pki_admin_token", t);
  else localStorage.removeItem("pki_admin_token");
  log(t ? "已保存令牌到 localStorage" : "已清除保存的令牌");
});

window.addEventListener("DOMContentLoaded", () => {
  const saved = localStorage.getItem("pki_admin_token");
  if (saved) adminInput.value = saved;
  const savedTheme = localStorage.getItem("pki_theme_mode") || "system";
  themeSelect.value = savedTheme;
  setTheme(savedTheme);
  const savedIntlWrap = localStorage.getItem("pki_output_wrap_intl");
  const intlWrap = savedIntlWrap === null ? true : savedIntlWrap === "1";
  intlWrapOutputInput.checked = intlWrap;
  intlOut.classList.toggle("wrap", intlWrap);
  const savedGmWrap = localStorage.getItem("pki_output_wrap_gm");
  const gmWrap = savedGmWrap === null ? true : savedGmWrap === "1";
  gmWrapOutputInput.checked = gmWrap;
  gmOut.classList.toggle("wrap", gmWrap);
  clearResultCard("intl");
  clearResultCard("gm");
  refreshIntlSserverStatusPill();
  refreshGmSserverStatusPill();
  window.setInterval(() => {
    refreshIntlSserverStatusPill();
    refreshGmSserverStatusPill();
  }, 5000);
});

themeSelect.addEventListener("change", () => {
  const mode = themeSelect.value || "system";
  localStorage.setItem("pki_theme_mode", mode);
  setTheme(mode);
});

tabLinks.forEach((btn) => {
  btn.addEventListener("click", () => activateTab(btn.getAttribute("data-tab-target")));
});

document.getElementById("btnIntlClearOutput").addEventListener("click", () => {
  intlOut.textContent = "";
  clearResultCard("intl");
});

document.getElementById("btnGmClearOutput").addEventListener("click", () => {
  gmOut.textContent = "";
  clearResultCard("gm");
});

document.getElementById("btnIntlCopyOutput").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(intlOut.textContent || "");
    log("已复制 Intl 输出到剪贴板", "intl");
  } catch {
    log("复制失败：当前环境不允许访问剪贴板", "intl");
  }
});

document.getElementById("btnGmCopyOutput").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(gmOut.textContent || "");
    log("已复制 GM 输出到剪贴板", "gm");
  } catch {
    log("复制失败：当前环境不允许访问剪贴板", "gm");
  }
});

intlWrapOutputInput.addEventListener("change", () => {
  intlOut.classList.toggle("wrap", intlWrapOutputInput.checked);
  localStorage.setItem("pki_output_wrap_intl", intlWrapOutputInput.checked ? "1" : "0");
});

gmWrapOutputInput.addEventListener("change", () => {
  gmOut.classList.toggle("wrap", gmWrapOutputInput.checked);
  localStorage.setItem("pki_output_wrap_gm", gmWrapOutputInput.checked ? "1" : "0");
});

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: headersJson(),
    body: JSON.stringify(body || {}),
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }
  if (!res.ok) {
    const msg = data.detail ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : text;
    throw new Error(msg || `HTTP ${res.status}`);
  }
  return data;
}

async function getJson(url) {
  const res = await fetch(url, { headers: headersGet() });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }
  if (!res.ok) {
    const msg = data.detail ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : text;
    throw new Error(msg || `HTTP ${res.status}`);
  }
  return data;
}

function setSserverPill(el, mode, text) {
  if (!el) return;
  el.classList.remove("running", "stopped", "unknown");
  el.classList.add(mode);
  el.textContent = text;
}

async function refreshIntlSserverStatusPill() {
  try {
    const data = await getJson("/api/intl/browser-mtls/status");
    const running = !!(data && data.data && data.data.running);
    setSserverPill(intlSserverStatusPill, running ? "running" : "stopped", running ? "Intl s_server: 运行中(8443)" : "Intl s_server: 未运行");
  } catch (e) {
    const msg = String((e && e.message) || e || "");
    const unauthorized = msg.includes("401") || msg.includes("Invalid or missing admin token");
    setSserverPill(intlSserverStatusPill, "unknown", unauthorized ? "Intl s_server: 无权限(需令牌)" : "Intl s_server: 状态未知");
  }
}

async function refreshGmSserverStatusPill() {
  try {
    const data = await getJson("/api/gm/browser-mtls/status");
    const running = !!(data && data.data && data.data.running);
    setSserverPill(gmSserverStatusPill, running ? "running" : "stopped", running ? "GM s_server: 运行中(9443)" : "GM s_server: 未运行");
  } catch (e) {
    const msg = String((e && e.message) || e || "");
    const unauthorized = msg.includes("401") || msg.includes("Invalid or missing admin token");
    setSserverPill(gmSserverStatusPill, "unknown", unauthorized ? "GM s_server: 无权限(需令牌)" : "GM s_server: 状态未知");
  }
}

document.querySelectorAll("button[data-action]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const action = btn.getAttribute("data-action");
    const profile = btn.getAttribute("data-profile") || "intl";
    const base = apiBase(profile);
    getOutEl(profile).textContent = "执行中…";
    try {
      let data;
      if (action === "reset-demo") {
        if (!confirm("将清理历史生成物并重建初始目录，确认继续？")) {
          getOutEl(profile).textContent = "已取消";
          return;
        }
        const body = { keepWebCache: !!((profile === "gm" ? gmKeepWebCacheInput : intlKeepWebCacheInput) && (profile === "gm" ? gmKeepWebCacheInput : intlKeepWebCacheInput).checked) };
        const r = optionalReason(profile);
        if (r) body.reason = r;
        data = await postJson(`${base}/reset-demo`, body);
      } else if (action === "init") data = await postJson(`${base}/init`, {});
      else if (action === "build-ca") data = await postJson(`${base}/build-ca`, {});
      else if (action === "issue-server") {
        const body = {};
        const r = optionalReason(profile);
        if (r) body.reason = r;
        data = await postJson(`${base}/issue-server`, body);
      } else if (action === "issue-client") {
        const body = {
          clientName: profileClientName(profile),
          p12Password: profileP12Password(profile),
        };
        const r = optionalReason(profile);
        if (r) body.reason = r;
        data = await postJson(`${base}/issue-client`, body);
      } else if (action === "verify") {
        const body = { clientName: profileClientName(profile) };
        const r = optionalReason(profile);
        if (r) body.reason = r;
        data = await postJson(`${base}/verify`, body);
      } else if (action === "revoke-server") {
        const isGm = profile === "gm";
        if (!confirm(isGm ? "确定吊销当前 GM 服务端证书？该操作会更新 CRL。" : "确定吊销当前服务端证书？该操作会更新 CRL。")) {
          getOutEl(profile).textContent = "已取消";
          return;
        }
        const body = {};
        const r = optionalReason(profile);
        if (r) body.reason = r;
        data = await postJson(`${base}/revoke-server`, body);
      } else if (action === "revoke-client") {
        if (!confirm(profile === "gm" ? "确定吊销该 GM 客户端证书？" : "确定吊销该客户端证书？")) {
          getOutEl(profile).textContent = "已取消";
          return;
        }
        const body = { clientName: profileClientName(profile) };
        const r = optionalReason(profile);
        if (r) body.reason = r;
        data = await postJson(`${base}/revoke-client`, body);
      } else if (action === "server-revocation-check") {
        const body = {};
        const r = optionalReason(profile);
        if (r) body.reason = r;
        data = await postJson(`${base}/server-revocation-check`, body);
      }
      renderApiResult(data, profile);
    } catch (e) {
      log(String(e.message || e), profile);
    }
  });
});

document.getElementById("btnIntlBrowserMtlsStart").addEventListener("click", async () => {
  getOutEl("intl").textContent = "启动中…";
  try {
    const body = {};
    const r = optionalReason("intl");
    if (r) body.reason = r;
    const data = await postJson("/api/intl/browser-mtls/start", body);
    renderApiResult(data, "intl");
    await refreshIntlSserverStatusPill();
  } catch (e) {
    log(String(e.message || e), "intl");
  }
});

document.getElementById("btnIntlBrowserMtlsStop").addEventListener("click", async () => {
  getOutEl("intl").textContent = "关闭中…";
  try {
    const body = {};
    const r = optionalReason("intl");
    if (r) body.reason = r;
    const data = await postJson("/api/intl/browser-mtls/stop", body);
    renderApiResult(data, "intl");
    await refreshIntlSserverStatusPill();
  } catch (e) {
    log(String(e.message || e), "intl");
  }
});

document.getElementById("btnGmBrowserMtlsStart").addEventListener("click", async () => {
  getOutEl("gm").textContent = "启动中…";
  try {
    const body = {};
    const r = optionalReason("gm");
    if (r) body.reason = r;
    const data = await postJson("/api/gm/browser-mtls/start", body);
    renderApiResult(data, "gm");
    await refreshGmSserverStatusPill();
  } catch (e) {
    log(String(e.message || e), "gm");
  }
});

document.getElementById("btnGmBrowserMtlsStop").addEventListener("click", async () => {
  getOutEl("gm").textContent = "关闭中…";
  try {
    const body = {};
    const r = optionalReason("gm");
    if (r) body.reason = r;
    const data = await postJson("/api/gm/browser-mtls/stop", body);
    renderApiResult(data, "gm");
    await refreshGmSserverStatusPill();
  } catch (e) {
    log(String(e.message || e), "gm");
  }
});

document.getElementById("btnGmCapability").addEventListener("click", async () => {
  getOutEl("gm").textContent = "检测中…";
  gmCapabilityState.textContent = "检测中...";
  try {
    const data = await getJson("/api/gm/capability");
    renderApiResult(data, "gm");
    gmCapabilityState.textContent = data.ok ? "可用" : "不可用";
  } catch (e) {
    gmCapabilityState.textContent = "检测失败";
    log(String(e.message || e), "gm");
  }
});

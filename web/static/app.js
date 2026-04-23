const out = document.getElementById("out");
const adminInput = document.getElementById("adminToken");
const clientNameInput = document.getElementById("clientName");

function optionalReason() {
  const el = document.getElementById("auditReason");
  if (!el) return undefined;
  const s = el.value.trim();
  return s ? s : undefined;
}

function log(obj) {
  out.textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
}

function adminTokenValue() {
  return (adminInput.value || localStorage.getItem("pki_admin_token") || "").trim();
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

async function downloadBlob(path, filename) {
  const res = await fetch(path, { headers: headersGet() });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(t || `HTTP ${res.status}`);
  }
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

document.querySelectorAll("button[data-action]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const action = btn.getAttribute("data-action");
    out.textContent = "执行中…";
    try {
      let data;
      if (action === "init") data = await postJson("/api/init", {});
      else if (action === "build-ca") data = await postJson("/api/build-ca", {});
      else if (action === "issue") {
        const body = {
          clientName: clientNameInput.value.trim() || "trainee",
          p12Password: document.getElementById("p12Password").value,
        };
        const r = optionalReason();
        if (r) body.reason = r;
        data = await postJson("/api/issue", body);
      } else if (action === "verify") {
        const body = { clientName: clientNameInput.value.trim() || "trainee" };
        const r = optionalReason();
        if (r) body.reason = r;
        data = await postJson("/api/verify", body);
      } else if (action === "revoke") {
        if (!confirm("确定吊销该客户端证书？")) {
          out.textContent = "已取消";
          return;
        }
        const body = { clientName: clientNameInput.value.trim() || "trainee" };
        const r = optionalReason();
        if (r) body.reason = r;
        data = await postJson("/api/revoke", body);
      }
      log(data);
    } catch (e) {
      log(String(e.message || e));
    }
  });
});

document.getElementById("btnStatus").addEventListener("click", async () => {
  out.textContent = "查询中…";
  try {
    log(await getJson("/api/status"));
  } catch (e) {
    log(String(e.message || e));
  }
});

document.getElementById("btnAudit").addEventListener("click", async () => {
  out.textContent = "加载审计…";
  try {
    log(await getJson("/api/audit/tail?n=80"));
  } catch (e) {
    log(String(e.message || e));
  }
});

document.getElementById("dlP12").addEventListener("click", async () => {
  const name = clientNameInput.value.trim() || "trainee";
  out.textContent = "下载中…";
  try {
    await downloadBlob(`/api/download/p12/${encodeURIComponent(name)}`, `client-${name}.p12`);
    log("下载已开始：client-" + name + ".p12");
  } catch (e) {
    log(String(e.message || e));
  }
});

document.getElementById("dlChain").addEventListener("click", async () => {
  out.textContent = "下载中…";
  try {
    await downloadBlob("/api/download/ca-chain", "ca-chain.cert.pem");
    log("下载已开始：ca-chain.cert.pem");
  } catch (e) {
    log(String(e.message || e));
  }
});

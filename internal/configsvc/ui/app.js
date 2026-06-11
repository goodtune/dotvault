// Thin shell over the /v1/admin API. Everything this UI does is a plain
// fetch against routes a Terraform provider would also use; no state lives
// here beyond the rendered DOM.
"use strict";

const $ = (id) => document.getElementById(id);

// Identity segments (usernames, account names) and layer-key segments may
// legally contain spaces and other URL-reserved characters, so every value
// interpolated into an API path is percent-encoded. Layer keys keep their
// single "/" as a real separator; everything else is one opaque segment.
const encSegment = encodeURIComponent;
const encKey = (key) => key.split("/").map(encodeURIComponent).join("/");

async function api(path, opts = {}) {
  const res = await fetch(path, { credentials: "same-origin", ...opts });
  if (res.status === 401) {
    showLogin();
    throw new Error("authentication required");
  }
  return res;
}

// Mutating requests carry a one-time CSRF token.
async function mutate(path, opts = {}) {
  const tokenRes = await api("/v1/admin/csrf");
  const { token } = await tokenRes.json();
  opts.headers = { ...(opts.headers || {}), "X-CSRF-Token": token };
  return api(path, opts);
}

async function errorText(res) {
  return (await res.text()).trim() || `HTTP ${res.status}`;
}

function setError(id, message) {
  const el = $(id);
  el.textContent = message || "";
  el.hidden = !message;
}

// --- view switching ---

const views = ["login", "layers", "groups", "sa", "preview"];

function show(view) {
  for (const v of views) $(`${v}-view`).hidden = v !== view;
  $("nav").hidden = view === "login";
}

function showLogin() {
  show("login");
}

function route() {
  const hash = location.hash.replace("#", "") || "layers";
  const view = { layers: "layers", groups: "groups", "service-accounts": "sa", preview: "preview" }[hash] || "layers";
  show(view);
  ({ layers: loadLayers, groups: loadGroups, sa: loadServiceAccounts, preview: () => {} })[view]();
}

// --- auth ---

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  setError("login-error", "");
  const res = await fetch("/v1/admin/auth/login", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: $("login-username").value, password: $("login-password").value }),
  });
  if (!res.ok) {
    setError("login-error", await errorText(res));
    return;
  }
  $("login-password").value = "";
  await boot();
});

$("logout").addEventListener("click", async () => {
  try {
    await mutate("/v1/admin/auth/logout", { method: "POST" });
  } finally {
    showLogin();
  }
});

async function boot() {
  const res = await fetch("/v1/admin/whoami", { credentials: "same-origin" });
  if (!res.ok) {
    showLogin();
    return;
  }
  const identity = await res.json();
  $("whoami").textContent = `${identity.name} (${identity.kind})`;
  route();
}

// --- layers ---

async function loadLayers() {
  const res = await api("/v1/admin/layers");
  const { keys } = await res.json();
  const list = $("layer-list");
  list.replaceChildren();
  for (const key of keys) {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.textContent = key;
    a.href = "#layers";
    a.addEventListener("click", () => openLayer(key));
    li.appendChild(a);
    list.appendChild(li);
  }
}

async function openLayer(key, fresh = false) {
  setError("layer-error", "");
  $("layer-edit-form").hidden = false;
  $("layer-edit-key").textContent = key;
  $("layer-edit-form").dataset.key = key;
  if (fresh) {
    $("layer-edit-doc").value = "";
    return;
  }
  const res = await api(`/v1/admin/layers/${encKey(key)}`);
  $("layer-edit-doc").value = res.ok ? await res.text() : "";
}

$("layer-new-form").addEventListener("submit", (e) => {
  e.preventDefault();
  openLayer($("layer-new-key").value.trim(), true);
});

$("layer-edit-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  setError("layer-error", "");
  const key = e.target.dataset.key;
  const res = await mutate(`/v1/admin/layers/${encKey(key)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/yaml" },
    body: $("layer-edit-doc").value,
  });
  if (!res.ok) {
    setError("layer-error", await errorText(res));
    return;
  }
  await loadLayers();
});

$("layer-delete").addEventListener("click", async () => {
  const key = $("layer-edit-form").dataset.key;
  if (!confirm(`Delete layer ${key}?`)) return;
  const res = await mutate(`/v1/admin/layers/${encKey(key)}`, { method: "DELETE" });
  if (!res.ok) {
    setError("layer-error", await errorText(res));
    return;
  }
  $("layer-edit-form").hidden = true;
  await loadLayers();
});

// --- groups ---

async function loadGroups() {
  setError("groups-error", "");
  const res = await api("/v1/admin/groups");
  const { users } = await res.json();
  const rows = $("groups-rows");
  rows.replaceChildren();
  for (const user of users) {
    const detail = await api(`/v1/admin/groups/${encSegment(user)}`);
    const { groups } = await detail.json();
    const tr = document.createElement("tr");

    const userCell = document.createElement("td");
    userCell.textContent = user;

    const groupsCell = document.createElement("td");
    groupsCell.textContent = groups.join(", ");

    const actions = document.createElement("td");
    const edit = document.createElement("button");
    edit.textContent = "Edit";
    edit.addEventListener("click", () => {
      $("groups-user").value = user;
      $("groups-list").value = groups.join(", ");
    });
    const del = document.createElement("button");
    del.textContent = "Delete";
    del.className = "danger";
    del.addEventListener("click", async () => {
      if (!confirm(`Delete membership entry for ${user}?`)) return;
      const dres = await mutate(`/v1/admin/groups/${encSegment(user)}`, { method: "DELETE" });
      if (!dres.ok) setError("groups-error", await errorText(dres));
      await loadGroups();
    });
    actions.append(edit, del);

    tr.append(userCell, groupsCell, actions);
    rows.appendChild(tr);
  }
}

$("groups-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  setError("groups-error", "");
  const user = $("groups-user").value.trim();
  const groups = $("groups-list").value.split(",").map((g) => g.trim()).filter(Boolean);
  const res = await mutate(`/v1/admin/groups/${encSegment(user)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ groups }),
  });
  if (!res.ok) {
    setError("groups-error", await errorText(res));
    return;
  }
  $("groups-user").value = "";
  $("groups-list").value = "";
  await loadGroups();
});

// --- service accounts ---

async function loadServiceAccounts() {
  setError("sa-error", "");
  const res = await api("/v1/admin/service-accounts");
  const { names } = await res.json();
  const rows = $("sa-rows");
  rows.replaceChildren();
  for (const name of names) {
    const detail = await api(`/v1/admin/service-accounts/${encSegment(name)}`);
    const sa = await detail.json();
    const tr = document.createElement("tr");

    const nameCell = document.createElement("td");
    nameCell.textContent = sa.name;
    const descCell = document.createElement("td");
    descCell.textContent = sa.description || "";
    const statusCell = document.createElement("td");
    statusCell.textContent = sa.disabled ? "disabled" : "active";

    const actions = document.createElement("td");
    const toggle = document.createElement("button");
    toggle.textContent = sa.disabled ? "Enable" : "Disable";
    toggle.addEventListener("click", async () => {
      const tres = await mutate(`/v1/admin/service-accounts/${encSegment(sa.name)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: sa.description || "", disabled: !sa.disabled }),
      });
      if (!tres.ok) setError("sa-error", await errorText(tres));
      await loadServiceAccounts();
    });
    const del = document.createElement("button");
    del.textContent = "Delete";
    del.className = "danger";
    del.addEventListener("click", async () => {
      if (!confirm(`Delete service account ${sa.name}?`)) return;
      const dres = await mutate(`/v1/admin/service-accounts/${encSegment(sa.name)}`, { method: "DELETE" });
      if (!dres.ok) setError("sa-error", await errorText(dres));
      await loadServiceAccounts();
    });
    actions.append(toggle, del);

    tr.append(nameCell, descCell, statusCell, actions);
    rows.appendChild(tr);
  }
}

$("sa-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  setError("sa-error", "");
  const name = $("sa-name").value.trim();
  const res = await mutate(`/v1/admin/service-accounts/${encSegment(name)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ description: $("sa-description").value, disabled: false }),
  });
  if (!res.ok) {
    setError("sa-error", await errorText(res));
    return;
  }
  $("sa-name").value = "";
  $("sa-description").value = "";
  await loadServiceAccounts();
});

// --- preview ---

$("preview-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  setError("preview-error", "");
  $("preview-doc").textContent = "";
  $("preview-etag").textContent = "";
  const params = new URLSearchParams({
    os: $("preview-os").value.trim(),
    user: $("preview-user").value.trim(),
  });
  const groups = $("preview-groups").value.trim();
  if (groups) params.set("groups", groups);
  const res = await api(`/v1/admin/preview?${params}`);
  if (!res.ok) {
    setError("preview-error", await errorText(res));
    return;
  }
  $("preview-etag").textContent = `ETag: ${res.headers.get("ETag") || ""}`;
  $("preview-doc").textContent = await res.text();
});

window.addEventListener("hashchange", route);
boot();

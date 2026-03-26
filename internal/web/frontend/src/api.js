let csrfToken = null;

async function fetchJSON(url, opts = {}) {
  const res = await fetch(url, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

export async function getCSRFToken() {
  if (!csrfToken) {
    const data = await fetchJSON('/api/v1/csrf');
    csrfToken = data.token;
  }
  const token = csrfToken;
  csrfToken = null; // One-time use
  return token;
}

export async function getStatus() {
  return fetchJSON('/api/v1/status');
}

export async function getRules() {
  return fetchJSON('/api/v1/rules');
}

export async function listSecrets(path = '') {
  return fetchJSON(`/api/v1/secrets/${path}`);
}

export async function getSecret(path, reveal = false) {
  const url = reveal
    ? `/api/v1/secrets/${path}?reveal=true`
    : `/api/v1/secrets/${path}`;
  return fetchJSON(url);
}

export async function triggerSync() {
  const token = await getCSRFToken();
  return fetchJSON('/api/v1/sync', {
    method: 'POST',
    headers: { 'X-CSRF-Token': token },
  });
}

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

export async function loginLDAP(username, password) {
  const token = await getCSRFToken();
  return fetchJSON('/auth/ldap/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
    },
    body: JSON.stringify({ username, password }),
  });
}

export async function getLDAPStatus(sessionID) {
  return fetchJSON(`/auth/ldap/status?session=${encodeURIComponent(sessionID)}`);
}

export async function submitTOTP(sessionID, passcode) {
  const token = await getCSRFToken();
  return fetchJSON('/auth/ldap/totp', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
    },
    body: JSON.stringify({ session_id: sessionID, passcode }),
  });
}

export async function loginToken(vaultToken) {
  const token = await getCSRFToken();
  return fetchJSON('/auth/token/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
    },
    body: JSON.stringify({ token: vaultToken }),
  });
}

export async function getVaultToken() {
  return fetchJSON('/api/v1/token');
}

export async function startEnrolment(key) {
  const token = await getCSRFToken();
  return fetchJSON(`/api/v1/enrol/${encodeURIComponent(key)}/start`, {
    method: 'POST',
    headers: { 'X-CSRF-Token': token },
  });
}

export async function skipEnrolment(key) {
  const token = await getCSRFToken();
  return fetchJSON(`/api/v1/enrol/${encodeURIComponent(key)}/skip`, {
    method: 'POST',
    headers: { 'X-CSRF-Token': token },
  });
}

export async function resetEnrolment(key) {
  const token = await getCSRFToken();
  return fetchJSON(`/api/v1/enrol/${encodeURIComponent(key)}/reset`, {
    method: 'POST',
    headers: { 'X-CSRF-Token': token },
  });
}

export async function getEnrolmentStatus(key) {
  return fetchJSON(`/api/v1/enrol/${encodeURIComponent(key)}/status`);
}

export async function completeEnrolments() {
  const token = await getCSRFToken();
  return fetchJSON('/api/v1/enrol/complete', {
    method: 'POST',
    headers: { 'X-CSRF-Token': token },
  });
}

export async function getEnrolPrompt() {
  return fetchJSON('/api/v1/enrol/prompt');
}

export async function submitEnrolSecret(value) {
  const token = await getCSRFToken();
  return fetchJSON('/api/v1/enrol/secret', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
    },
    body: JSON.stringify({ value }),
  });
}

let csrfToken = null;

async function fetchJSON(url, opts = {}) {
  const res = await fetch(url, opts);
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    const err = new Error(body.error || res.statusText);
    // Attached so a caller can distinguish "not configured" (503) from an
    // ordinary failure without parsing the message text — the SSH page uses
    // this to show "not configured" rather than an error banner.
    err.status = res.status;
    throw err;
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

export async function getConfig() {
  return fetchJSON('/api/v1/config');
}

// encodeSecretPath percent-encodes each path segment but preserves the "/"
// separators — and any trailing slash, which the server uses to distinguish a
// folder list from a secret read — so a key name with URL-special characters
// can't mis-route the request.
function encodeSecretPath(path) {
  return path.split('/').map(encodeURIComponent).join('/');
}

export async function listSecrets(path = '') {
  return fetchJSON(`/api/v1/secrets/${encodeSecretPath(path)}`);
}

export async function getSecret(path, reveal = false) {
  const encoded = encodeSecretPath(path);
  const url = reveal
    ? `/api/v1/secrets/${encoded}?reveal=true`
    : `/api/v1/secrets/${encoded}`;
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

export async function listSSHRemotes() {
  return fetchJSON('/api/v1/ssh/remotes');
}

// SSHConfirmationRequired mirrors the CLI's sshHostKeyConfirmation
// (cmd/dotvault/ssh_add.go): the daemon dialled the host, found its key
// neither pinned nor CA-signed, and wants the fingerprint confirmed before
// anything is persisted. It carries only what the 409 body carries — never
// the host key itself, which the API deliberately never returns here.
export class SSHConfirmationRequired extends Error {
  constructor(host, fingerprint) {
    super(`host key confirmation required for ${host}`);
    this.name = 'SSHConfirmationRequired';
    this.host = host;
    this.fingerprint = fingerprint;
  }
}

// addSSHRemote posts a candidate remote. A 409 is not a transport failure —
// it's the confirmation gesture above — and its body carries no "error"
// field, only host/fingerprint, so it can't route through fetchJSON's
// generic throw-on-!ok contract. Handled directly and surfaced as a typed
// error the caller branches on.
export async function addSSHRemote(remote) {
  const token = await getCSRFToken();
  const res = await fetch('/api/v1/ssh/remotes', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
    },
    body: JSON.stringify(remote),
  });
  const body = await res.json().catch(() => ({}));
  if (res.status === 409) {
    throw new SSHConfirmationRequired(body.host, body.fingerprint);
  }
  if (!res.ok) {
    const err = new Error(body.error || res.statusText);
    err.status = res.status;
    throw err;
  }
  return body;
}

export async function patchSSHRemote(host, patch) {
  const token = await getCSRFToken();
  return fetchJSON(`/api/v1/ssh/remotes/${encodeURIComponent(host)}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
    },
    body: JSON.stringify(patch),
  });
}

// deleteSSHRemote succeeds with 204 No Content, so — unlike every other
// mutation here — there is no JSON body to decode on the happy path, and it
// can't route through fetchJSON (which always expects one).
export async function deleteSSHRemote(host) {
  const token = await getCSRFToken();
  const res = await fetch(`/api/v1/ssh/remotes/${encodeURIComponent(host)}`, {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': token },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    const err = new Error(body.error || res.statusText);
    err.status = res.status;
    throw err;
  }
}

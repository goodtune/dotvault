import { h } from 'preact';
import { useState, useEffect } from 'preact/hooks';
import {
  listSSHRemotes,
  addSSHRemote,
  patchSSHRemote,
  deleteSSHRemote,
  SSHConfirmationRequired,
} from '../api.js';

// Mirrors internal/sshfwd/state.go's State constants — kept as a lookup
// rather than title-casing the wire value so a future state string doesn't
// silently render in raw kebab-case ("host-key-error") if the styling ever
// needs to diverge from the label.
const STATE_LABELS = {
  connected: 'Connected',
  connecting: 'Connecting',
  reconnecting: 'Reconnecting',
  offline: 'Offline',
  'authentication-error': 'Authentication error',
  'host-key-error': 'Host key error',
  disabled: 'Disabled',
};

function statePillClass(state) {
  switch (state) {
    case 'connected': return 'ssh-pill ssh-pill-ok';
    case 'connecting':
    case 'reconnecting': return 'ssh-pill ssh-pill-info';
    case 'authentication-error':
    case 'host-key-error': return 'ssh-pill ssh-pill-err';
    case 'disabled': return 'ssh-pill ssh-pill-muted';
    default: return 'ssh-pill';
  }
}

export function SSHPage({ status, onUpdate, onClose }) {
  const [remotes, setRemotes] = useState([]);
  const [loading, setLoading] = useState(true);
  // Distinguished from `error` because it isn't a failure to report — a
  // daemon simply run without managed forwards configured is the documented
  // normal case (see the brief: "managed forwards may simply not be
  // configured, and the page should say so rather than showing an error").
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState(null);
  const [showAddForm, setShowAddForm] = useState(false);

  async function refresh() {
    try {
      const data = await listSSHRemotes();
      setRemotes(data.remotes || []);
      setUnavailable(false);
      setError(null);
    } catch (err) {
      if (err.status === 503) {
        setUnavailable(true);
        setError(null);
      } else {
        setError(err.message);
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { refresh(); }, []);

  // Live per-remote state comes entirely from the `status` prop, which is
  // App.jsx's own /api/v1/status poll (30s, the dashboard's existing
  // cadence) — this page adds no poll of its own, per the brief. `remotes`
  // (the configured set) is fetched once on mount and again after any
  // mutation, since add/enable/disable/delete change the config itself, not
  // just its live state.
  const liveByHost = new Map((status?.ssh || []).map(s => [s.host, s]));

  async function afterMutation() {
    await refresh();
    if (onUpdate) onUpdate();
  }

  async function handleToggle(remote) {
    setError(null);
    try {
      await patchSSHRemote(remote.host, { enabled: !remote.enabled });
      await afterMutation();
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleDelete(remote) {
    setError(null);
    try {
      await deleteSSHRemote(remote.host);
      await afterMutation();
    } catch (err) {
      setError(err.message);
    }
  }

  return h('div', { class: 'config-page' },
    h('div', { class: 'config-container' },
      h('div', { class: 'config-header' },
        h('h2', { class: 'config-heading' }, 'SSH Remote Forwards'),
        h('div', { class: 'config-header-actions' },
          !unavailable && h('button', {
            class: 'enrol-btn-primary',
            onClick: () => setShowAddForm(v => !v),
          }, showAddForm ? 'Cancel' : 'Add remote'),
          h('button', { class: 'enrol-btn-secondary', onClick: onClose }, '← Back to Dashboard'),
        ),
      ),
      h('p', { class: 'config-subheading' },
        'Hosts the daemon maintains a persistent SSH remote forward to, exposing its own web API there as a Unix socket.',
      ),
      error && h('div', { class: 'error-banner' }, error),
      unavailable && h('div', { class: 'config-section' },
        h('p', { class: 'config-empty' }, 'Managed SSH forwards are not configured on this daemon.'),
      ),
      !unavailable && showAddForm && h(SSHAddForm, { onAdded: afterMutation }),
      !unavailable && loading && h('p', { class: 'config-loading' }, 'Loading…'),
      !unavailable && !loading && h(SSHTable, {
        remotes,
        liveByHost,
        onToggle: handleToggle,
        onDelete: handleDelete,
      }),
    ),
  );
}

function SSHTable({ remotes, liveByHost, onToggle, onDelete }) {
  if (remotes.length === 0) {
    return h('p', { class: 'config-empty' }, 'No SSH remotes configured yet.');
  }
  return h('table', { class: 'ssh-table' },
    h('thead', null,
      h('tr', null,
        h('th', null, 'Host'),
        h('th', null, 'Port'),
        h('th', null, 'Remote socket'),
        h('th', null, 'State'),
        h('th', null, 'Reconnects'),
        h('th', null, 'Last error'),
        h('th', null, 'Enabled'),
        h('th', null),
      ),
    ),
    h('tbody', null,
      remotes.map(remote => h(SSHRow, {
        key: remote.host,
        remote,
        live: liveByHost.get(remote.host),
        onToggle,
        onDelete,
      })),
    ),
  );
}

function SSHRow({ remote, live, onToggle, onDelete }) {
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [busy, setBusy] = useState(false);

  // No live entry means the daemon hasn't reported a state for this host
  // yet (e.g. just added, or a config not yet reloaded) — distinct from a
  // reported "offline", so fall back on the config's own enabled flag
  // rather than implying a live status that wasn't actually observed.
  const state = live?.state || (remote.enabled ? 'offline' : 'disabled');
  const label = STATE_LABELS[state] || state;

  async function toggle() {
    setBusy(true);
    try {
      await onToggle(remote);
    } finally {
      setBusy(false);
    }
  }

  async function confirmedDelete() {
    setBusy(true);
    try {
      await onDelete(remote);
    } finally {
      setBusy(false);
      setConfirmDelete(false);
    }
  }

  return h('tr', null,
    h('td', null, remote.host),
    h('td', null, remote.port),
    h('td', null, h('code', null, remote.remote_socket || '—')),
    h('td', null, h('span', { class: statePillClass(state) }, label)),
    h('td', null, live ? live.reconnects : '—'),
    h('td', null, live?.last_error
      ? h('span', { class: 'ssh-error-text' }, live.last_error)
      : '—'),
    h('td', null,
      h('button', {
        class: remote.enabled ? 'enrol-btn-secondary' : 'enrol-btn-primary',
        onClick: toggle,
        disabled: busy,
      }, remote.enabled ? 'Disable' : 'Enable'),
    ),
    h('td', null,
      confirmDelete
        ? h('span', { class: 'ssh-row-confirm' },
            h('button', { class: 'enrol-btn-danger', onClick: confirmedDelete, disabled: busy }, 'Confirm'),
            h('button', { class: 'enrol-btn-secondary', onClick: () => setConfirmDelete(false), disabled: busy }, 'Cancel'),
          )
        : h('button', { class: 'enrol-btn-secondary', onClick: () => setConfirmDelete(true), disabled: busy }, 'Delete'),
    ),
  );
}

// SSHAddForm is the security-critical piece: the same host-key confirmation
// protocol `dotvault ssh add` implements over the CLI (cmd/dotvault/ssh_add.go).
// A 409 response means the daemon dialled the host and found a key it has
// not seen before; the fingerprint must be shown and a deliberate action
// taken before the same candidate is re-submitted with accept_fingerprint.
// There is deliberately no "always trust" / "remember this" affordance, and
// dismissing the confirmation (Cancel) clears it without ever re-submitting
// — so a user who walks away or backs out adds nothing.
function SSHAddForm({ onAdded }) {
  const [host, setHost] = useState('');
  const [port, setPort] = useState('');
  const [socket, setSocket] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  // Set only while a 409 is awaiting confirmation; holds exactly the
  // candidate that produced it, so "Trust and add" re-submits precisely
  // what was shown to the user and nothing else.
  const [confirm, setConfirm] = useState(null);

  // parsedPort validates the raw port field against the same range the Go
  // side enforces (ValidateRemote: 0/unset for the default, else 1-65535)
  // and — unlike parseInt, which would silently truncate "22abc" to 22 —
  // rejects any trailing garbage rather than mangling it into a different
  // port with no indication to the user.
  function parsedPort() {
    const trimmed = port.trim();
    if (!trimmed) return { value: undefined, valid: true };
    const n = Number(trimmed);
    if (!Number.isInteger(n) || n <= 0 || n > 65535) return { value: undefined, valid: false };
    return { value: n, valid: true };
  }

  function buildRemote() {
    const remote = { host: host.trim() };
    const { value: portNum } = parsedPort();
    if (portNum !== undefined) remote.port = portNum;
    if (socket.trim()) remote.remote_socket = socket.trim();
    return remote;
  }

  async function submit(remote, acceptFingerprint) {
    setSubmitting(true);
    setError(null);
    try {
      const payload = acceptFingerprint
        ? { ...remote, accept_fingerprint: acceptFingerprint }
        : remote;
      await addSSHRemote(payload);
      setConfirm(null);
      setHost('');
      setPort('');
      setSocket('');
      if (onAdded) await onAdded();
    } catch (err) {
      if (err instanceof SSHConfirmationRequired) {
        setConfirm({ host: err.host, fingerprint: err.fingerprint, remote });
      } else {
        setError(err.message);
        setConfirm(null);
      }
    } finally {
      setSubmitting(false);
    }
  }

  function handleSubmit(e) {
    e.preventDefault();
    if (!host.trim()) {
      setError('host is required');
      return;
    }
    if (!parsedPort().valid) {
      setError('port must be a whole number between 1 and 65535');
      return;
    }
    submit(buildRemote());
  }

  function handleTrust() {
    if (!confirm) return;
    submit(confirm.remote, confirm.fingerprint);
  }

  function handleCancelConfirm() {
    // Nothing is added: the candidate is discarded, not resubmitted.
    setConfirm(null);
  }

  if (confirm) {
    return h('div', { class: 'enrol-card' },
      h('div', { class: 'enrol-warn' },
        h('p', { class: 'enrol-warn-text' },
          `The host key for ${confirm.host} is not yet trusted.`,
        ),
        h('p', { class: 'ssh-fingerprint' }, confirm.fingerprint),
        h('p', { class: 'enrol-warn-text' },
          'Verify this fingerprint out of band before trusting it — accepting the wrong key lets an impersonating host read this daemon’s web API over the forward.',
        ),
        h('div', { class: 'enrol-warn-actions' },
          h('button', {
            class: 'enrol-btn-danger',
            onClick: handleTrust,
            disabled: submitting,
          }, submitting ? 'Adding…' : 'Trust and add'),
          h('button', {
            class: 'enrol-btn-secondary',
            onClick: handleCancelConfirm,
            disabled: submitting,
          }, 'Cancel'),
        ),
        error && h('p', { class: 'enrol-error-text' }, error),
      ),
    );
  }

  return h('div', { class: 'enrol-card' },
    h('form', { class: 'ssh-add-form', onSubmit: handleSubmit },
      h('label', { class: 'enrol-prompt-label', htmlFor: 'ssh-host' }, 'Host'),
      h('input', {
        id: 'ssh-host',
        class: 'enrol-prompt-input',
        value: host,
        onInput: e => setHost(e.target.value),
        placeholder: 'example.com',
        disabled: submitting,
        autofocus: true,
      }),
      h('label', { class: 'enrol-prompt-label', htmlFor: 'ssh-port' }, 'Port (default 22)'),
      h('input', {
        id: 'ssh-port',
        class: 'enrol-prompt-input',
        value: port,
        onInput: e => setPort(e.target.value),
        placeholder: '22',
        inputMode: 'numeric',
        disabled: submitting,
      }),
      h('label', { class: 'enrol-prompt-label', htmlFor: 'ssh-socket' }, 'Remote socket (default ~/.ssh/dotvault.sock)'),
      h('input', {
        id: 'ssh-socket',
        class: 'enrol-prompt-input',
        value: socket,
        onInput: e => setSocket(e.target.value),
        placeholder: '~/.ssh/dotvault.sock',
        disabled: submitting,
      }),
      h('div', { class: 'enrol-prompt-actions' },
        h('button', { type: 'submit', class: 'enrol-btn-primary', disabled: submitting }, submitting ? 'Adding…' : 'Add'),
      ),
      error && h('p', { class: 'enrol-error-text' }, error),
    ),
  );
}

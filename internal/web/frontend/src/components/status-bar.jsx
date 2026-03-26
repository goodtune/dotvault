import { h } from 'preact';
import { useState } from 'preact/hooks';
import { triggerSync } from '../api.js';

export function StatusBar({ status, onSync }) {
  const [syncing, setSyncing] = useState(false);

  async function handleSync() {
    setSyncing(true);
    try {
      await triggerSync();
      if (onSync) await onSync();
    } catch (err) {
      console.error('sync failed:', err);
    } finally {
      setSyncing(false);
    }
  }

  const authStatus = status?.authenticated ? 'Connected' : 'Disconnected';
  const authClass = status?.authenticated ? 'status-ok' : 'status-error';

  return h('header', { class: 'status-bar' },
    h('div', { class: 'status-left' },
      h('span', { class: 'app-title' }, 'dotvault'),
      h('span', { class: `status-indicator ${authClass}` }, authStatus),
    ),
    h('div', { class: 'status-right' },
      status?.time && h('span', { class: 'last-sync' },
        'Updated: ', new Date(status.time).toLocaleTimeString(),
      ),
      h('button', {
        class: 'sync-btn',
        onClick: handleSync,
        disabled: syncing,
      }, syncing ? 'Syncing...' : 'Sync Now'),
    ),
  );
}

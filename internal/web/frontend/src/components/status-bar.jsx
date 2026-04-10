import { h } from 'preact';
import { useState } from 'preact/hooks';
import { triggerSync, getVaultToken } from '../api.js';

export function StatusBar({ status, onSync, pendingEnrolments, onEnrolClick }) {
  const [syncing, setSyncing] = useState(false);
  const [tokenCopied, setTokenCopied] = useState(false);

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

  async function handleCopyToken() {
    try {
      const data = await getVaultToken();
      await navigator.clipboard.writeText(data.token);
      setTokenCopied(true);
      setTimeout(() => setTokenCopied(false), 2000);
    } catch (err) {
      console.error('copy token failed:', err);
    }
  }

  const authStatus = status?.authenticated ? 'Connected' : 'Disconnected';
  const authClass = status?.authenticated ? 'status-ok' : 'status-error';

  const vaultURL = status?.vault_address;
  const safeVaultURL = vaultURL && /^https?:\/\//i.test(vaultURL) ? vaultURL : null;

  return h('header', { class: 'status-bar' },
    h('div', { class: 'status-left' },
      h('span', { class: 'app-title' },
        '.vault',
        status?.version && h('span', { class: 'app-version' }, ' v' + status.version),
      ),
      h('span', { class: `status-indicator ${authClass}` }, authStatus),
      safeVaultURL && h('a', {
        class: 'vault-link',
        href: safeVaultURL,
        target: '_blank',
        rel: 'noopener noreferrer',
      }, 'Vault \u2197'),
      pendingEnrolments > 0 && h('button', {
        class: 'enrol-indicator',
        onClick: onEnrolClick,
      }, pendingEnrolments + ' pending'),
    ),
    h('div', { class: 'status-right' },
      status?.time && h('span', { class: 'last-sync' },
        'Updated: ', new Date(status.time).toLocaleTimeString(),
      ),
      status?.authenticated && h('button', {
        class: 'copy-token-btn' + (tokenCopied ? ' copied' : ''),
        onClick: handleCopyToken,
        title: tokenCopied ? 'Token copied!' : 'Copy Vault token to clipboard',
      }, tokenCopied ? '\u2705' : '\u{1F4CB}'),
      h('button', {
        class: 'sync-btn',
        onClick: handleSync,
        disabled: syncing,
      }, syncing ? 'Syncing...' : 'Sync Now'),
    ),
  );
}

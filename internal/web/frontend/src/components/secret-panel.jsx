import { h } from 'preact';
import { useState, useEffect } from 'preact/hooks';
import { getSecret } from '../api.js';

function buildVaultSecretURL(status, secretPath) {
  const base = status.vault_address.replace(/\/+$/, '');
  return `${base}/ui/vault/secrets/${status.kv_mount}/show/${status.user_prefix}${status.username}/${secretPath}`;
}

export function SecretPanel({ secretPath, status, customText }) {
  const [secret, setSecret] = useState(null);
  const [revealed, setRevealed] = useState({});
  const [copied, setCopied] = useState({});
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!secretPath) {
      setSecret(null);
      return;
    }
    setLoading(true);
    setRevealed({});
    getSecret(secretPath)
      .then(setSecret)
      .catch(() => setSecret(null))
      .finally(() => setLoading(false));
  }, [secretPath]);

  async function toggleReveal(field) {
    if (revealed[field]) {
      setRevealed(prev => {
        const next = { ...prev };
        delete next[field];
        return next;
      });
      return;
    }

    const data = await getSecret(secretPath, true);
    if (data && data.fields) {
      setRevealed(prev => ({ ...prev, [field]: data.fields[field] }));
      // Auto-hide after 30 seconds
      setTimeout(() => {
        setRevealed(prev => {
          const next = { ...prev };
          delete next[field];
          return next;
        });
      }, 30000);
    }
  }

  async function copyField(field) {
    const data = await getSecret(secretPath, true);
    if (data && data.fields) {
      const value = typeof data.fields[field] === 'object'
        ? JSON.stringify(data.fields[field], null, 2)
        : String(data.fields[field]);
      await navigator.clipboard.writeText(value);
      setCopied(prev => ({ ...prev, [field]: true }));
      setTimeout(() => {
        setCopied(prev => {
          const next = { ...prev };
          delete next[field];
          return next;
        });
      }, 2000);
    }
  }

  if (!secretPath) {
    return h('main', { class: 'secret-panel' },
      customText
        ? h('div', { class: 'custom-text', dangerouslySetInnerHTML: { __html: customText } })
        : h('div', { class: 'panel-empty' }, 'Select a secret from the sidebar'),
    );
  }

  if (loading) {
    return h('main', { class: 'secret-panel' },
      h('div', { class: 'panel-loading' }, 'Loading...'),
    );
  }

  if (!secret) {
    return h('main', { class: 'secret-panel' },
      h('div', { class: 'panel-error' }, 'Secret not found'),
    );
  }

  const fields = Array.isArray(secret.fields)
    ? secret.fields
    : Object.keys(secret.fields || {});

  return h('main', { class: 'secret-panel' },
    h('div', { class: 'secret-heading' },
      h('h2', null, secretPath),
      status?.vault_address && h('a', {
        class: 'vault-link',
        href: buildVaultSecretURL(status, secretPath),
        target: '_blank',
        rel: 'noopener noreferrer',
      }, 'View in Vault \u2197'),
    ),
    h('div', { class: 'secret-meta' }, 'Version: ', secret.version),
    h('table', { class: 'field-table' },
      h('thead', null,
        h('tr', null,
          h('th', null, 'Field'),
          h('th', null, 'Value'),
          h('th', null, ''),
        ),
      ),
      h('tbody', null,
        fields.map(field =>
          h('tr', { key: field },
            h('td', { class: 'field-name' }, field),
            h('td', { class: 'field-value' },
              revealed[field]
                ? h('code', null, typeof revealed[field] === 'object'
                    ? JSON.stringify(revealed[field], null, 2)
                    : String(revealed[field]))
                : h('span', { class: 'masked' }, '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022'),
            ),
            h('td', { class: 'field-actions' },
              h('button', {
                class: 'reveal-btn',
                onClick: () => toggleReveal(field),
                title: revealed[field] ? 'Hide' : 'Reveal',
              }, revealed[field] ? '\u{1F441}\u{FE0F}' : '\u{1F441}'),
              h('button', {
                class: 'copy-btn' + (copied[field] ? ' copied' : ''),
                onClick: () => copyField(field),
                title: copied[field] ? 'Copied!' : 'Copy to clipboard',
              }, copied[field] ? '\u2705' : '\u{1F4CB}'),
            ),
          ),
        ),
      ),
    ),
  );
}

import { h } from 'preact';
import { useState, useEffect } from 'preact/hooks';
import { getSecret } from '../api.js';

export function SecretPanel({ secretPath }) {
  const [secret, setSecret] = useState(null);
  const [revealed, setRevealed] = useState({});
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

  if (!secretPath) {
    return h('main', { class: 'secret-panel' },
      h('div', { class: 'panel-empty' }, 'Select a secret from the sidebar'),
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
    h('h2', null, secretPath),
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
                ? h('code', null, String(revealed[field]))
                : h('span', { class: 'masked' }, '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022'),
            ),
            h('td', null,
              h('button', {
                class: 'reveal-btn',
                onClick: () => toggleReveal(field),
                title: revealed[field] ? 'Hide' : 'Reveal',
              }, revealed[field] ? '\u{1F441}\u{FE0F}' : '\u{1F441}'),
            ),
          ),
        ),
      ),
    ),
  );
}

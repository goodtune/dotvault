import { h, Fragment } from 'preact';
import { useState, useEffect } from 'preact/hooks';
import { getConfig } from '../api.js';

export function ConfigPage({ onClose }) {
  const [config, setConfig] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    getConfig()
      .then(setConfig)
      .catch(err => setError(err.message));
  }, []);

  return h('div', { class: 'config-page' },
    h('div', { class: 'config-container' },
      h('div', { class: 'config-header' },
        h('h2', { class: 'config-heading' }, 'Effective Configuration'),
        h('button', {
          class: 'enrol-btn-secondary',
          onClick: onClose,
        }, '← Back to Dashboard'),
      ),
      h('p', { class: 'config-subheading' },
        'Read-only view of the running daemon’s configuration. To change anything, edit the config file and restart the service.',
      ),
      error && h('div', { class: 'error-banner' }, error),
      !config && !error && h('p', { class: 'config-loading' }, 'Loading…'),
      config && h(ConfigBody, { config }),
    ),
  );
}

function ConfigBody({ config }) {
  const { vault, sync, web, rules = [], enrolments = [] } = config;
  return h(Fragment, null,
    h(Section, { title: 'Vault' },
      h(KeyValueTable, {
        rows: [
          ['Address', vault.address || '—'],
          ['KV mount', vault.kv_mount || '—'],
          ['User prefix', vault.user_prefix || '—'],
          ['Auth method', vault.auth_method || '—'],
          ['Auth mount', vault.auth_mount || '—'],
          ['Auth role', vault.auth_role || '—'],
          ['TLS skip verify', formatBool(vault.tls_skip_verify)],
          ['CA certificate', vault.has_ca_cert ? 'Configured' : 'Not configured'],
          ['Token renewal', vault.disable_token_renewal ? 'Disabled' : 'Enabled'],
        ],
      }),
    ),
    h(Section, { title: 'Sync' },
      h(KeyValueTable, {
        rows: [
          ['Interval', sync?.interval || '—'],
        ],
      }),
    ),
    h(Section, { title: 'Web UI' },
      h(KeyValueTable, {
        rows: [
          ['Enabled', formatBool(web?.enabled)],
          ['Listen address', web?.listen || '—'],
        ],
      }),
    ),
    h(Section, {
      title: 'Managed Files',
      count: rules.length,
      empty: rules.length === 0 ? 'No sync rules configured.' : null,
    },
      rules.length > 0 && h('div', { class: 'config-cards' },
        rules.map(rule => h(RuleCard, { key: rule.name, rule })),
      ),
    ),
    h(Section, {
      title: 'Active Enrolments',
      count: enrolments.length,
      empty: enrolments.length === 0 ? 'No enrolments configured.' : null,
    },
      enrolments.length > 0 && h('div', { class: 'config-cards' },
        enrolments.map(e => h(EnrolmentCard, { key: e.key, enrolment: e })),
      ),
    ),
  );
}

function Section({ title, count, empty, children }) {
  return h('section', { class: 'config-section' },
    h('h3', { class: 'config-section-title' },
      title,
      typeof count === 'number' && h('span', { class: 'config-count' }, count),
    ),
    empty
      ? h('p', { class: 'config-empty' }, empty)
      : children,
  );
}

function KeyValueTable({ rows }) {
  return h('table', { class: 'config-kv' },
    h('tbody', null,
      rows.map(([k, v]) =>
        h('tr', { key: k },
          h('th', null, k),
          h('td', null, v),
        ),
      ),
    ),
  );
}

function RuleCard({ rule }) {
  const { name, description, vault_key, target, oauth } = rule;
  return h('div', { class: 'config-card' },
    h('div', { class: 'config-card-title' },
      h('strong', null, name),
      target?.format && h('span', { class: 'config-tag' }, target.format),
      target?.has_template && h('span', { class: 'config-tag config-tag-info' }, 'templated'),
      oauth && h('span', { class: 'config-tag config-tag-warn' }, 'oauth: ' + oauth.provider),
    ),
    description && h('p', { class: 'config-card-desc' }, description),
    h(KeyValueTable, {
      rows: [
        ['Target path', h('code', null, target?.path || '—')],
        ['Format', target?.format || '—'],
        ['Vault key', h('code', null, vault_key)],
        target?.merge ? ['Merge', target.merge] : null,
        oauth?.scopes?.length ? ['OAuth scopes', oauth.scopes.join(', ')] : null,
        oauth?.engine_path ? ['OAuth engine', oauth.engine_path] : null,
      ].filter(Boolean),
    }),
  );
}

function EnrolmentCard({ enrolment }) {
  const { key, engine, engine_name, fields = [], settings, status } = enrolment;
  const settingsRows = settings
    ? Object.entries(settings)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, formatSetting(v)])
    : [];
  return h('div', { class: 'config-card' },
    h('div', { class: 'config-card-title' },
      h('strong', null, key),
      h('span', { class: 'config-tag' }, engine_name || engine),
      status && h('span', { class: 'config-tag ' + statusClass(status) }, status),
    ),
    h(KeyValueTable, {
      rows: [
        ['Engine', engine],
        ['Vault path', h('code', null, key)],
        fields.length ? ['Fields', fields.join(', ')] : null,
      ].filter(Boolean),
    }),
    settingsRows.length > 0 && h('div', { class: 'config-subsection' },
      h('div', { class: 'config-subsection-title' }, 'Settings'),
      h(KeyValueTable, { rows: settingsRows }),
    ),
  );
}

function formatBool(v) {
  if (v === true) return 'Yes';
  if (v === false) return 'No';
  return '—';
}

function formatSetting(v) {
  if (v === null || v === undefined) return '—';
  if (Array.isArray(v)) {
    const hasObjects = v.some(item => item !== null && typeof item === 'object');
    if (!hasObjects) return v.join(', ');
    return h('pre', { class: 'config-json' }, JSON.stringify(v, null, 2));
  }
  if (typeof v === 'object') {
    return h('pre', { class: 'config-json' }, JSON.stringify(v, null, 2));
  }
  return h('code', null, String(v));
}

function statusClass(status) {
  switch (status) {
    case 'complete': return 'config-tag-ok';
    case 'failed': return 'config-tag-err';
    case 'running': return 'config-tag-info';
    case 'skipped': return 'config-tag-muted';
    default: return '';
  }
}

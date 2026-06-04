import { h } from 'preact';
import { useState } from 'preact/hooks';
import { listSecrets } from '../api.js';

export function Sidebar({ keys, selected, onSelect }) {
  if (!keys || keys.length === 0) {
    return h('nav', { class: 'sidebar' },
      h('div', { class: 'sidebar-empty' }, 'No secrets found'),
    );
  }

  return h('nav', { class: 'sidebar' },
    h('div', { class: 'sidebar-header' }, 'Secrets'),
    h('ul', { class: 'key-list' },
      keys.map(entry =>
        h(SecretNode, { key: entry, entry, prefix: '', selected, onSelect }),
      ),
    ),
  );
}

// SecretNode renders one entry from a Vault KVv2 list. Vault marks a nested
// path with a trailing slash ("databricks/"); such entries are folders and
// expand to reveal the keys beneath, while a plain entry ("gh") is a selectable
// secret. `prefix` is the accumulated path of the enclosing folders so a leaf
// resolves to its full relative secret path (e.g. "databricks/prod").
function SecretNode({ entry, prefix, selected, onSelect }) {
  const isFolder = entry.endsWith('/');
  const name = isFolder ? entry.slice(0, -1) : entry;
  const path = prefix + entry;

  if (!isFolder) {
    return h('li', {
      class: `key-item ${path === selected ? 'selected' : ''}`,
      onClick: () => onSelect(path),
    },
      h('span', { class: 'key-icon' }, '\u{1F511}'),
      h('span', { class: 'key-name' }, name),
    );
  }

  return h(SecretFolder, { folder: path, name, selected, onSelect });
}

function SecretFolder({ folder, name, selected, onSelect }) {
  const [expanded, setExpanded] = useState(false);
  const [children, setChildren] = useState(null); // null until first load
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function toggle() {
    const next = !expanded;
    setExpanded(next);
    // Lazy-load the folder's contents the first time it is opened. The result
    // is cached for the component's lifetime; reopening doesn't refetch, so a
    // secret added under the folder after expansion appears on next reload.
    if (next && children === null && !loading) {
      setLoading(true);
      try {
        const data = await listSecrets(folder);
        setChildren(data.keys || []);
        setError(null);
      } catch (err) {
        setError(err.message || 'failed to list');
      } finally {
        setLoading(false);
      }
    }
  }

  return h('li', { class: 'key-folder' },
    h('div', {
      class: 'key-item key-folder-header',
      onClick: toggle,
      'aria-expanded': String(expanded),
    },
      h('span', { class: 'key-chevron' }, expanded ? '▾' : '▸'),
      h('span', { class: 'key-icon' }, '\u{1F4C1}'),
      h('span', { class: 'key-name' }, name),
    ),
    expanded && h('ul', { class: 'key-sublist' },
      loading && h('li', { class: 'key-subnote' }, 'Loading…'),
      error && h('li', { class: 'key-subnote key-suberror' }, error),
      !loading && !error && children && children.length === 0 &&
        h('li', { class: 'key-subnote' }, '(empty)'),
      children && children.map(child =>
        h(SecretNode, { key: child, entry: child, prefix: folder, selected, onSelect }),
      ),
    ),
  );
}

import { h } from 'preact';

export function Sidebar({ keys, selected, onSelect }) {
  if (!keys || keys.length === 0) {
    return h('nav', { class: 'sidebar' },
      h('div', { class: 'sidebar-empty' }, 'No secrets found'),
    );
  }

  return h('nav', { class: 'sidebar' },
    h('div', { class: 'sidebar-header' }, 'Secrets'),
    h('ul', { class: 'key-list' },
      keys.map(key =>
        h('li', {
          key,
          class: `key-item ${key === selected ? 'selected' : ''}`,
          onClick: () => onSelect(key),
        },
          h('span', { class: 'key-icon' }, key.endsWith('/') ? '\u{1F4C1}' : '\u{1F511}'),
          h('span', { class: 'key-name' }, key),
        ),
      ),
    ),
  );
}

import { h } from 'preact';

export function OAuthBanner({ rules }) {
  if (!rules || rules.length === 0) return null;

  return h('div', { class: 'oauth-banners' },
    rules.map(rule =>
      h('div', { key: rule.name, class: 'oauth-banner' },
        h('span', null,
          rule.oauth_provider || rule.name, ' requires authorization',
        ),
        h('a', {
          class: 'oauth-btn',
          href: `/api/v1/oauth/${rule.name}/start`,
        }, 'Authorize'),
      ),
    ),
  );
}

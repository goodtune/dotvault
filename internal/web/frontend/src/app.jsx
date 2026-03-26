import { h, Fragment } from 'preact';
import { useState, useEffect } from 'preact/hooks';
import { StatusBar } from './components/status-bar.jsx';
import { Sidebar } from './components/sidebar.jsx';
import { SecretPanel } from './components/secret-panel.jsx';
import { OAuthBanner } from './components/oauth-banner.jsx';
import { getStatus, getRules, listSecrets } from './api.js';

export function App() {
  const [status, setStatus] = useState(null);
  const [rules, setRules] = useState([]);
  const [keys, setKeys] = useState([]);
  const [selectedKey, setSelectedKey] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  async function loadData() {
    try {
      const [statusData, rulesData, secretsData] = await Promise.all([
        getStatus(),
        getRules(),
        listSecrets(),
      ]);
      setStatus(statusData);
      setRules(rulesData.rules || []);
      setKeys(secretsData.keys || []);
      setError(null);
    } catch (err) {
      setError(err.message);
    }
  }

  const oauthRules = rules.filter(r => r.has_oauth);

  return h(Fragment, null,
    h(StatusBar, { status, onSync: loadData }),
    error && h('div', { class: 'error-banner' }, error),
    oauthRules.length > 0 && h(OAuthBanner, { rules: oauthRules }),
    h('div', { class: 'main-layout' },
      h(Sidebar, { keys, selected: selectedKey, onSelect: setSelectedKey }),
      h(SecretPanel, { secretPath: selectedKey }),
    ),
  );
}

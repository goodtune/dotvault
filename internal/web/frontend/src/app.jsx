import { h, Fragment } from 'preact';
import { useState, useEffect } from 'preact/hooks';
import { StatusBar } from './components/status-bar.jsx';
import { Sidebar } from './components/sidebar.jsx';
import { SecretPanel } from './components/secret-panel.jsx';
import { OAuthBanner } from './components/oauth-banner.jsx';
import { LoginPage } from './components/login-page.jsx';
import { EnrolPage } from './components/enrol-page.jsx';
import { getStatus, getRules, listSecrets } from './api.js';

export function App() {
  const [status, setStatus] = useState(null);
  const [rules, setRules] = useState([]);
  const [keys, setKeys] = useState([]);
  const [selectedKey, setSelectedKey] = useState(null);
  const [error, setError] = useState(null);
  const [enrolDismissed, setEnrolDismissed] = useState(false);
  const [enrolPageOpen, setEnrolPageOpen] = useState(false);

  useEffect(() => {
    loadStatus();
  }, []);

  // Poll for dashboard updates when authenticated.
  useEffect(() => {
    if (!status?.authenticated) return;
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, [status?.authenticated]);

  async function loadStatus() {
    try {
      const statusData = await getStatus();
      setStatus(statusData);
      if (statusData.authenticated) {
        loadData();
      }
    } catch (err) {
      setError(err.message);
    }
  }

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

  // Show login page if not authenticated.
  if (status && !status.authenticated) {
    return h(LoginPage, {
      authMethod: status.auth_method,
      onAuth: loadData,
      customText: status.login_text,
    });
  }

  // Loading state.
  if (!status) {
    return h('div', { class: 'login-container' },
      h('div', { class: 'login-card' },
        h('h1', { class: 'login-title' }, '.vault'),
        error
          ? h('p', { class: 'login-error' }, error)
          : h('p', null, 'Loading...'),
      ),
    );
  }

  // Check for pending enrolments.
  const enrolments = status.enrolments || [];
  const pendingEnrolments = enrolments.filter(
    e => e.status === 'pending' || e.status === 'running' || e.status === 'failed'
  );

  // Show enrolment page if there are pending enrolments (and not dismissed),
  // or if the user explicitly navigated to it via the header button.
  if ((pendingEnrolments.length > 0 && !enrolDismissed) || enrolPageOpen) {
    return h(EnrolPage, {
      enrolments,
      onComplete: () => {
        setEnrolDismissed(true);
        setEnrolPageOpen(false);
        loadData();
      },
      onUpdate: loadStatus,
    });
  }

  const oauthRules = rules.filter(r => r.has_oauth);

  return h(Fragment, null,
    h(StatusBar, {
      status,
      onSync: loadData,
      pendingEnrolments: pendingEnrolments.length,
      hasEnrolments: enrolments.length > 0,
      onEnrolClick: () => {
        setEnrolDismissed(false);
        setEnrolPageOpen(true);
      },
    }),
    error && h('div', { class: 'error-banner' }, error),
    oauthRules.length > 0 && h(OAuthBanner, { rules: oauthRules }),
    h('div', { class: 'main-layout' },
      h(Sidebar, { keys, selected: selectedKey, onSelect: setSelectedKey }),
      h(SecretPanel, { secretPath: selectedKey, status, customText: status.secret_view_text }),
    ),
  );
}

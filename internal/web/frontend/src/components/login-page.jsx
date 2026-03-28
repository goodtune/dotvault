import { h } from 'preact';
import { useState, useEffect, useRef } from 'preact/hooks';
import { loginLDAP, getLDAPStatus, submitTOTP, loginToken } from '../api.js';

export function LoginPage({ authMethod, onAuth }) {
  if (authMethod === 'oidc') return h(OIDCLogin, null);
  if (authMethod === 'ldap') return h(LDAPLogin, { onAuth });
  if (authMethod === 'token') return h(TokenLogin, { onAuth });
  return h('div', { class: 'login-container' },
    h('p', { class: 'login-error' }, `Unknown auth method: ${authMethod}`),
  );
}

function OIDCLogin() {
  return h('div', { class: 'login-container' },
    h('div', { class: 'login-card' },
      h('h1', { class: 'login-title' }, 'dotvault'),
      h('a', { class: 'login-btn', href: '/auth/oidc/start' }, 'Login with OIDC'),
    ),
  );
}

function LDAPLogin({ onAuth }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [phase, setPhase] = useState('form'); // form | polling | totp
  const [mfaMethods, setMfaMethods] = useState([]);
  const [passcode, setPasscode] = useState('');
  const sessionRef = useRef(null);
  const pollRef = useRef(null);

  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  function startPolling(sessionID) {
    pollRef.current = setInterval(async () => {
      try {
        const status = await getLDAPStatus(sessionID);
        if (status.state === 'mfa_required') {
          setMfaMethods(status.mfa_methods || []);
          const usesPasscode = status.mfa_methods &&
            status.mfa_methods.some(m => m.uses_passcode);
          setPhase(usesPasscode ? 'totp' : 'polling');
          if (status.error) setError(status.error);
        } else if (status.state === 'authenticated') {
          clearInterval(pollRef.current);
          if (onAuth) onAuth();
        } else if (status.state === 'failed') {
          clearInterval(pollRef.current);
          setError(status.error || 'Login failed');
          setPhase('form');
        }
      } catch (err) {
        clearInterval(pollRef.current);
        setError(err.message);
        setPhase('form');
      }
    }, 2000);
  }

  async function handleLogin(e) {
    e.preventDefault();
    setError(null);
    setPhase('polling');
    try {
      const resp = await loginLDAP(username, password);
      sessionRef.current = resp.session_id;
      startPolling(resp.session_id);
    } catch (err) {
      setError(err.message);
      setPhase('form');
    }
  }

  async function handleTOTP(e) {
    e.preventDefault();
    setError(null);
    try {
      await submitTOTP(sessionRef.current, passcode);
      setPasscode('');
    } catch (err) {
      setError(err.message);
    }
  }

  if (phase === 'polling' && (!mfaMethods.length || !mfaMethods.some(m => m.uses_passcode))) {
    return h('div', { class: 'login-container' },
      h('div', { class: 'login-card' },
        h('h1', { class: 'login-title' }, 'dotvault'),
        h('p', { class: 'login-mfa-wait' }, 'Waiting for MFA approval...'),
        h('p', { class: 'login-mfa-hint' }, 'Check your device'),
        error && h('p', { class: 'login-error' }, error),
      ),
    );
  }

  if (phase === 'totp') {
    return h('div', { class: 'login-container' },
      h('div', { class: 'login-card' },
        h('h1', { class: 'login-title' }, 'dotvault'),
        h('p', { class: 'login-subtitle' }, 'Enter MFA passcode'),
        error && h('p', { class: 'login-error' }, error),
        h('form', { onSubmit: handleTOTP },
          h('input', {
            type: 'text',
            class: 'login-input',
            placeholder: 'Passcode',
            value: passcode,
            onInput: e => setPasscode(e.target.value),
            autocomplete: 'one-time-code',
            inputMode: 'numeric',
            autofocus: true,
          }),
          h('button', { type: 'submit', class: 'login-btn', disabled: !passcode }, 'Verify'),
        ),
      ),
    );
  }

  return h('div', { class: 'login-container' },
    h('div', { class: 'login-card' },
      h('h1', { class: 'login-title' }, 'dotvault'),
      error && h('p', { class: 'login-error' }, error),
      h('form', { onSubmit: handleLogin },
        h('input', {
          type: 'text',
          class: 'login-input',
          placeholder: 'Username',
          value: username,
          onInput: e => setUsername(e.target.value),
          autocomplete: 'username',
          autofocus: true,
        }),
        h('input', {
          type: 'password',
          class: 'login-input',
          placeholder: 'Password',
          value: password,
          onInput: e => setPassword(e.target.value),
          autocomplete: 'current-password',
        }),
        h('button', {
          type: 'submit',
          class: 'login-btn',
          disabled: !username || !password,
        }, 'Login'),
      ),
    ),
  );
}

function TokenLogin({ onAuth }) {
  const [token, setToken] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await loginToken(token);
      if (onAuth) onAuth();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return h('div', { class: 'login-container' },
    h('div', { class: 'login-card' },
      h('h1', { class: 'login-title' }, 'dotvault'),
      error && h('p', { class: 'login-error' }, error),
      h('form', { onSubmit: handleSubmit },
        h('input', {
          type: 'password',
          class: 'login-input',
          placeholder: 'Vault Token',
          value: token,
          onInput: e => setToken(e.target.value),
          autofocus: true,
        }),
        h('button', {
          type: 'submit',
          class: 'login-btn',
          disabled: !token || loading,
        }, loading ? 'Validating...' : 'Login'),
      ),
    ),
  );
}

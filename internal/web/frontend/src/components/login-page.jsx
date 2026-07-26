import { h } from 'preact';
import { useState, useEffect, useRef } from 'preact/hooks';
import { loginLDAP, getLDAPStatus, submitTOTP, loginToken, getStatus } from '../api.js';

export function LoginPage({ authMethod, onAuth, customText, bootstrap, onRefresh }) {
  if (authMethod === 'oidc') return h(OIDCLogin, { customText });
  if (authMethod === 'ldap') return h(LDAPLogin, { onAuth, customText });
  if (authMethod === 'token') return h(TokenLogin, { onAuth, customText });
  // auth.BaseMethod collapses mtls, mtls+tpm and mtls+os to "mtls". Certificate
  // auth normally needs no browser interaction at all — the only interactive
  // moment is the one-time bootstrap that mints the first certificate, which
  // runs whichever credential flow vault.mtls.bootstrap_method names.
  if (authMethod === 'mtls') return h(MTLSLogin, { bootstrap, onAuth, customText, onRefresh });
  return h('div', { class: 'login-container' },
    h('p', { class: 'login-error' }, `Unknown auth method: ${authMethod}`),
  );
}

// bootstrapNotice frames the reused LDAP/OIDC card: the credential prompt below
// it is a one-time certificate enrolment, not a recurring sign-in. It is passed
// through the existing customText slot (already an HTML sink) so the bootstrap
// path reuses OIDCLogin / LDAPLogin verbatim rather than forking them.
const bootstrapNotice =
  '<h2>One-time certificate enrolment</h2>' +
  '<p>This host signs in to Vault with a client certificate. Authenticate ' +
  'once now so dotvault can issue that certificate — after this, sign-in is ' +
  'automatic and you will not be asked for a credential again.</p>';

// The bootstrap login returning a token is not the end of the flow: the daemon
// still has to generate a key, call pki/sign, install the certificate, persist
// the envelope and then perform the real cert-auth login. Nothing pushes that
// completion to the browser, and the SPA otherwise fetches status exactly once
// on cold boot — so an OIDC callback that lands mid-issuance would strand the
// user on a stale login card. Poll status for the whole mtls branch instead, at
// the same 2s cadence as the LDAP poll.
const statusPollInterval = 2000;

// A single failed fetch is a blip; a run of them means the daemon is gone. On a
// failed issuance the daemon exits, so the poll is also how a failed bootstrap
// surfaces at all — but tolerate a couple of misses before replacing a card the
// user may be typing into.
const statusPollFailureThreshold = 3;

function useStatusPoll(onAuthenticated) {
  const [error, setError] = useState(null);
  const cbRef = useRef(onAuthenticated);
  cbRef.current = onAuthenticated;
  const pollRef = useRef(null);
  const failuresRef = useRef(0);

  useEffect(() => {
    pollRef.current = setInterval(async () => {
      try {
        const status = await getStatus();
        failuresRef.current = 0;
        setError(null);
        if (status.authenticated) {
          clearInterval(pollRef.current);
          if (cbRef.current) cbRef.current();
        }
      } catch (err) {
        failuresRef.current += 1;
        if (failuresRef.current >= statusPollFailureThreshold) setError(err.message);
      }
    }, statusPollInterval);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  return error;
}

function MTLSLogin({ bootstrap, onAuth, customText, onRefresh }) {
  // Set once the bootstrap credential flow has succeeded, so the wait for
  // certificate issuance doesn't fall back to the credential prompt: LDAPLogin
  // fires onAuth as soon as Vault authenticates, which is the start of issuance,
  // not the end of it.
  const [issuing, setIssuing] = useState(false);
  const pollError = useStatusPoll(onRefresh || onAuth);

  if (pollError) {
    return h('div', { class: 'login-container' },
      h('div', { class: 'login-card' },
        h('h1', { class: 'login-title' }, '.vault'),
        h('p', { class: 'login-error' }, pollError),
        h('p', { class: 'login-mfa-hint' },
          'The dotvault daemon stopped responding. Certificate issuance may have failed — check the daemon logs, then restart it and reload this page.'),
      ),
    );
  }

  if (!issuing && bootstrap && bootstrap.active) {
    const framed = bootstrapNotice + (customText || '');
    if (bootstrap.method === 'oidc') return h(OIDCLogin, { customText: framed });
    if (bootstrap.method === 'ldap') {
      return h(LDAPLogin, { onAuth: () => setIssuing(true), customText: framed });
    }
  }

  // Either the bootstrap credential flow is done and issuance is in flight, or
  // no bootstrap is pending at all — both are states where there is nothing for
  // the user to do and the poll above drives the transition.
  return h(MTLSWaiting, { customText: issuing ? null : customText, issuing });
}

function MTLSWaiting({ customText, issuing }) {
  return h('div', { class: 'login-container' },
    h('div', { class: 'login-card' },
      h('h1', { class: 'login-title' }, '.vault'),
      customText && h('div', { class: 'custom-text', dangerouslySetInnerHTML: { __html: customText } }),
      h('p', { class: 'login-mfa-wait' },
        issuing ? 'Issuing your certificate...' : 'Signing in with your client certificate...'),
      h('p', { class: 'login-mfa-hint' },
        issuing
          ? 'Signed in. dotvault is now enrolling this host’s certificate — this only happens once. You will not need to sign in again.'
          : 'Certificate authentication needs no credential. This page updates automatically once the daemon holds a Vault token.'),
    ),
  );
}

function OIDCLogin({ customText }) {
  return h('div', { class: 'login-container' },
    h('div', { class: 'login-card' },
      h('h1', { class: 'login-title' }, '.vault'),
      customText && h('div', { class: 'custom-text', dangerouslySetInnerHTML: { __html: customText } }),
      h('a', { class: 'login-btn', href: '/auth/oidc/start' }, 'Login with OIDC'),
    ),
  );
}

function LDAPLogin({ onAuth, customText }) {
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
    if (pollRef.current) clearInterval(pollRef.current);
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
        h('h1', { class: 'login-title' }, '.vault'),
        h('p', { class: 'login-mfa-wait' }, 'Waiting for MFA approval...'),
        h('p', { class: 'login-mfa-hint' }, 'Check your device'),
        error && h('p', { class: 'login-error' }, error),
      ),
    );
  }

  if (phase === 'totp') {
    return h('div', { class: 'login-container' },
      h('div', { class: 'login-card' },
        h('h1', { class: 'login-title' }, '.vault'),
        h('p', { class: 'login-subtitle' }, 'Enter MFA passcode'),
        error && h('p', { class: 'login-error' }, error),
        h('form', { onSubmit: handleTOTP },
          h('input', {
            type: 'text',
            class: 'login-input',
            placeholder: 'Passcode',
            'aria-label': 'MFA Passcode',
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
      h('h1', { class: 'login-title' }, '.vault'),
      customText && h('div', { class: 'custom-text', dangerouslySetInnerHTML: { __html: customText } }),
      error && h('p', { class: 'login-error' }, error),
      h('form', { onSubmit: handleLogin },
        h('input', {
          type: 'text',
          class: 'login-input',
          placeholder: 'Username',
          'aria-label': 'Username',
          value: username,
          onInput: e => setUsername(e.target.value),
          autocomplete: 'username',
          autofocus: true,
        }),
        h('input', {
          type: 'password',
          class: 'login-input',
          placeholder: 'Password',
          'aria-label': 'Password',
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

function TokenLogin({ onAuth, customText }) {
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
      h('h1', { class: 'login-title' }, '.vault'),
      customText && h('div', { class: 'custom-text', dangerouslySetInnerHTML: { __html: customText } }),
      error && h('p', { class: 'login-error' }, error),
      h('form', { onSubmit: handleSubmit },
        h('input', {
          type: 'password',
          class: 'login-input',
          placeholder: 'Vault Token',
          'aria-label': 'Vault Token',
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

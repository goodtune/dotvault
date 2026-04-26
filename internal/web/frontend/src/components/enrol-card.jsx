import { h } from 'preact';
import { useState, useEffect, useRef } from 'preact/hooks';
import { startEnrolment, skipEnrolment, resetEnrolment, getEnrolmentStatus, getEnrolPrompt, submitEnrolSecret } from '../api.js';
import { copyText } from '../clipboard.js';

export function EnrolCard({ enrolment, onUpdate, anyRunning }) {
  const [localStatus, setLocalStatus] = useState(enrolment.status);
  const [output, setOutput] = useState(enrolment.output || []);
  const [error, setError] = useState(enrolment.error || null);
  const [promptLabel, setPromptLabel] = useState(null);
  const [secretValue, setSecretValue] = useState('');
  const [confirmReset, setConfirmReset] = useState(false);
  const [resetting, setResetting] = useState(false);
  const pollRef = useRef(null);

  useEffect(() => {
    setLocalStatus(enrolment.status);
    setError(enrolment.error || null);
    if (enrolment.output) setOutput(enrolment.output);
  }, [enrolment.status, enrolment.error, enrolment.output]);

  // Start polling if the enrolment is already running (e.g. page reload).
  useEffect(() => {
    if (localStatus === 'running' && !pollRef.current) {
      startPolling();
    }
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [localStatus]);

  function startPolling() {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    // Only engines that block on interactive terminal input (ssh's passphrase)
    // need the /enrol/prompt poll. github and jfrog are fully browser-driven.
    const needsPrompt = enrolment.engine === 'ssh';
    pollRef.current = setInterval(async () => {
      try {
        const statusData = await getEnrolmentStatus(enrolment.key);
        setOutput(statusData.output || []);

        if (needsPrompt) {
          const promptData = await getEnrolPrompt();
          if (promptData.pending) {
            setPromptLabel(promptData.label);
          } else {
            setPromptLabel(null);
          }
        }

        if (statusData.status !== 'running') {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setLocalStatus(statusData.status);
          setError(statusData.error || null);
          setPromptLabel(null);
          setSecretValue('');
          if (onUpdate) onUpdate();
        }
      } catch (err) {
        console.error('poll error:', err);
      }
    }, 2000);
  }

  async function handleStart() {
    try {
      await startEnrolment(enrolment.key);
      setLocalStatus('running');
      setOutput([]);
      setError(null);
      setSecretValue('');
      setPromptLabel(null);
      if (onUpdate) onUpdate();
      startPolling();
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleSkip() {
    try {
      await skipEnrolment(enrolment.key);
      setLocalStatus('skipped');
      if (onUpdate) onUpdate();
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleResetConfirm() {
    setResetting(true);
    setError(null);
    try {
      await resetEnrolment(enrolment.key);
      setConfirmReset(false);
      setResetting(false);
      setLocalStatus('pending');
      setOutput([]);
      setSecretValue('');
      setPromptLabel(null);
      if (onUpdate) onUpdate();
    } catch (err) {
      setResetting(false);
      setError(err.message);
    }
  }

  async function handleSecretSubmit(e) {
    e.preventDefault();
    try {
      await submitEnrolSecret(secretValue);
      setSecretValue('');
      setPromptLabel(null);
    } catch (err) {
      setError(err.message);
    }
  }

  // Parse device code and verification URL from the engine's line-oriented
  // output. Both github and jfrog emit a "! First, copy your one-time code: X"
  // line; jfrog then emits "✓ Opened https://... in browser", github emits
  // "- Press Enter to open https://... in your browser...". Either shape
  // contains an https URL we can link to.
  const deviceCode = output.reduce((found, line) => {
    const match = line.match(/one-time code:\s*(\S+)/);
    return match ? match[1] : found;
  }, null);

  const verificationURL = output.reduce((found, line) => {
    const match = line.match(/(https?:\/\/\S+)/);
    // Strip trailing punctuation that terminates a prose sentence but isn't
    // part of the URL (e.g. "...browser." or "manually." in our own copy).
    return match ? match[1].replace(/[.,;:]+$/, '') : found;
  }, null);

  // Latest spinner/progress line ("⠼ Waiting for authentication...",
  // "⠼ Minting dotvault-owned access token...") gives the user a live hint
  // about which step the engine is on.
  let progressLine = null;
  for (let i = output.length - 1; i >= 0; i--) {
    const trimmed = output[i].trim();
    if (trimmed.startsWith('⠼')) {
      progressLine = trimmed.replace(/^⠼\s*/, '');
      break;
    }
  }

  const hasDeviceFlow = Boolean(deviceCode && verificationURL);
  // Once the engine has moved past "waiting for authentication" into a
  // server-to-server exchange (e.g. jfrog's mint step), the code is no
  // longer actionable — collapse the code UI and show just the progress.
  const codeNoLongerActionable = Boolean(progressLine && /minting/i.test(progressLine));
  const startDisabled = anyRunning && localStatus !== 'running';

  if (localStatus === 'complete') {
    const overwriteDisabled = anyRunning || resetting;
    return h('div', { class: 'enrol-card enrol-complete' },
      h('div', { class: 'enrol-card-header' },
        h('div', null,
          h('span', { class: 'enrol-check' }, '\u2713'),
          h('strong', null, enrolment.name),
        ),
        h('div', { class: 'enrol-card-actions' },
          h('span', { class: 'enrol-status-text enrol-status-complete' }, 'Enrolled successfully'),
          !confirmReset && h('button', {
            class: 'enrol-btn-secondary',
            onClick: () => setConfirmReset(true),
            disabled: anyRunning,
          }, 'Re-enrol'),
        ),
      ),
      confirmReset && h('div', { class: 'enrol-warn' },
        h('p', { class: 'enrol-warn-text' },
          'This will overwrite your existing credentials. Are you sure?',
        ),
        h('div', { class: 'enrol-warn-actions' },
          h('button', {
            class: 'enrol-btn-danger',
            onClick: handleResetConfirm,
            disabled: overwriteDisabled,
          }, resetting ? 'Overwriting\u2026' : 'Overwrite credentials'),
          h('button', {
            class: 'enrol-btn-secondary',
            onClick: () => setConfirmReset(false),
            disabled: resetting,
          }, 'Cancel'),
        ),
        error && h('p', { class: 'enrol-error-text' }, error),
      ),
    );
  }

  if (localStatus === 'skipped') {
    return h('div', { class: 'enrol-card enrol-skipped' },
      h('div', { class: 'enrol-card-header' },
        h('div', null,
          h('strong', null, enrolment.name),
          h('span', { class: 'enrol-badge' }, 'SKIPPED'),
        ),
        h('span', { class: 'enrol-engine-desc' }, engineDescription(enrolment.engine)),
      ),
    );
  }

  if (localStatus === 'running') {
    return h('div', { class: 'enrol-card enrol-running' },
      h('div', { class: 'enrol-card-header' },
        h('div', null,
          h('strong', null, enrolment.name),
          h('span', { class: 'enrol-badge enrol-badge-running' }, 'RUNNING'),
        ),
      ),
      // Active device-code step — show the code + a link to the service.
      hasDeviceFlow && !codeNoLongerActionable && h('div', { class: 'enrol-device-flow' },
        h('p', { class: 'enrol-device-label' }, `Enter this code on ${enrolment.name}:`),
        h('div', { class: 'enrol-device-code' }, deviceCode),
        h('div', { class: 'enrol-device-actions' },
          h('button', {
            class: 'enrol-btn-secondary',
            onClick: () => copyText(deviceCode),
          }, 'Copy Code'),
          h('a', {
            class: 'enrol-btn-secondary',
            href: verificationURL,
            target: '_blank',
            rel: 'noopener noreferrer',
          }, `Open ${enrolment.name} \u2192`),
        ),
        h('p', { class: 'enrol-device-waiting' }, progressLine || 'Waiting for approval\u2026'),
      ),
      // Post-authentication server-to-server step (e.g. jfrog's token mint).
      hasDeviceFlow && codeNoLongerActionable && h('div', { class: 'enrol-device-flow' },
        h('p', { class: 'enrol-device-label' }, `\u2713 Signed in to ${enrolment.name}`),
        h('p', { class: 'enrol-device-waiting' }, progressLine),
      ),
      // Passphrase prompt (ssh).
      promptLabel && !hasDeviceFlow && h('form', { class: 'enrol-prompt-form', onSubmit: handleSecretSubmit },
        h('label', { class: 'enrol-prompt-label', htmlFor: 'enrol-secret' }, promptLabel),
        h('input', {
          type: 'password',
          id: 'enrol-secret',
          class: 'enrol-prompt-input',
          value: secretValue,
          onInput: e => setSecretValue(e.target.value),
          placeholder: 'Enter passphrase',
          autofocus: true,
        }),
        h('div', { class: 'enrol-prompt-actions' },
          h('button', { type: 'submit', class: 'enrol-btn-primary' }, 'Submit'),
        ),
      ),
      // Fallback for engines that don't match the device-flow or prompt
      // shapes — show whatever the engine has emitted so the user isn't
      // left staring at a silent spinner.
      !hasDeviceFlow && !promptLabel && output.length > 0 && h('div', { class: 'enrol-output' },
        output.map((line, i) => h('div', { key: i }, line)),
      ),
    );
  }

  if (localStatus === 'failed') {
    return h('div', { class: 'enrol-card enrol-failed' },
      h('div', { class: 'enrol-card-header' },
        h('div', null,
          h('strong', null, enrolment.name),
          h('span', { class: 'enrol-engine-desc' }, engineDescription(enrolment.engine)),
        ),
        h('div', { class: 'enrol-card-actions' },
          h('button', { class: 'enrol-btn-primary', onClick: handleStart, disabled: startDisabled }, 'Retry'),
          h('button', { class: 'enrol-btn-secondary', onClick: handleSkip, disabled: startDisabled }, 'Skip'),
        ),
      ),
      h('p', { class: 'enrol-error-text' }, error),
    );
  }

  // Pending
  return h('div', { class: 'enrol-card' },
    h('div', { class: 'enrol-card-header' },
      h('div', null,
        h('strong', null, enrolment.name),
        h('span', { class: 'enrol-engine-desc' }, engineDescription(enrolment.engine)),
      ),
      h('div', { class: 'enrol-card-actions' },
        h('button', { class: 'enrol-btn-primary', onClick: handleStart, disabled: startDisabled }, 'Start'),
        h('button', { class: 'enrol-btn-secondary', onClick: handleSkip, disabled: startDisabled }, 'Skip'),
      ),
    ),
    error && h('p', { class: 'enrol-error-text' }, error),
  );
}

function engineDescription(engine) {
  switch (engine) {
    case 'github': return 'OAuth token via device flow';
    case 'jfrog': return 'Refreshable access token via web login';
    case 'ssh': return 'Ed25519 key generation';
    default: return engine;
  }
}

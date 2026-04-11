import { h } from 'preact';
import { useState, useEffect, useRef } from 'preact/hooks';
import { startEnrolment, skipEnrolment, getEnrolmentStatus, getEnrolPrompt, submitEnrolSecret } from '../api.js';
import { copyText } from '../clipboard.js';

export function EnrolCard({ enrolment, onUpdate, anyRunning }) {
  const [localStatus, setLocalStatus] = useState(enrolment.status);
  const [output, setOutput] = useState(enrolment.output || []);
  const [error, setError] = useState(enrolment.error || null);
  const [promptLabel, setPromptLabel] = useState(null);
  const [secretValue, setSecretValue] = useState('');
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
    const needsPrompt = enrolment.engine !== 'github';
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

  // Parse device code and verification URL from GitHub engine output.
  const deviceCode = output.reduce((found, line) => {
    const match = line.match(/one-time code: (\S+)/);
    return match ? match[1] : found;
  }, null);

  const verificationURL = output.reduce((found, line) => {
    const match = line.match(/open (https?:\/\/\S+)/);
    return match ? match[1] : found;
  }, null);

  const isGitHub = enrolment.engine === 'github';
  const startDisabled = anyRunning && localStatus !== 'running';

  if (localStatus === 'complete') {
    return h('div', { class: 'enrol-card enrol-complete' },
      h('div', { class: 'enrol-card-header' },
        h('div', null,
          h('span', { class: 'enrol-check' }, '\u2713'),
          h('strong', null, enrolment.name),
        ),
        h('span', { class: 'enrol-status-text enrol-status-complete' }, 'Enrolled successfully'),
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
      // GitHub device flow UI
      isGitHub && deviceCode && h('div', { class: 'enrol-device-flow' },
        h('p', { class: 'enrol-device-label' }, 'Enter this code on GitHub:'),
        h('div', { class: 'enrol-device-code' }, deviceCode),
        h('div', { class: 'enrol-device-actions' },
          h('button', {
            class: 'enrol-btn-secondary',
            onClick: () => copyText(deviceCode),
          }, 'Copy Code'),
          verificationURL && h('a', {
            class: 'enrol-btn-secondary',
            href: verificationURL,
            target: '_blank',
            rel: 'noopener noreferrer',
          }, 'Open GitHub \u2192'),
        ),
        h('p', { class: 'enrol-device-waiting' }, 'Waiting for approval...'),
      ),
      // Passphrase prompt UI
      promptLabel && !isGitHub && h('form', { class: 'enrol-prompt-form', onSubmit: handleSecretSubmit },
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
      // Generic output fallback
      !isGitHub && !promptLabel && output.length > 0 && h('div', { class: 'enrol-output' },
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
    case 'ssh': return 'Ed25519 key generation';
    default: return engine;
  }
}

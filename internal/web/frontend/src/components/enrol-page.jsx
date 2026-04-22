import { h } from 'preact';
import { EnrolCard } from './enrol-card.jsx';
import { completeEnrolments } from '../api.js';

export function EnrolPage({ enrolments, onComplete, onUpdate }) {
  const allAddressed = enrolments.every(
    e => e.status === 'complete' || e.status === 'skipped'
  );
  const anyPending = enrolments.some(
    e => e.status === 'pending' || e.status === 'failed'
  );
  const anyRunning = enrolments.some(e => e.status === 'running');
  const isReEnrolMode = allAddressed && !anyPending;

  async function handleContinue() {
    try {
      await completeEnrolments();
      if (onComplete) onComplete();
    } catch (err) {
      console.error('complete error:', err);
    }
  }

  return h('div', { class: 'enrol-page' },
    h('div', { class: 'enrol-container' },
      h('h2', { class: 'enrol-heading' },
        isReEnrolMode ? 'Manage credentials' : 'Complete your setup',
      ),
      h('p', { class: 'enrol-subheading' },
        isReEnrolMode
          ? 'Re-enrol to replace existing credentials for any service.'
          : 'The following credentials need to be configured before syncing can begin.',
      ),
      h('div', { class: 'enrol-list' },
        enrolments.map(e =>
          h(EnrolCard, { key: e.key, enrolment: e, onUpdate, anyRunning })
        ),
      ),
      h('div', { class: 'enrol-footer' },
        h('button', {
          class: 'enrol-continue-btn',
          onClick: handleContinue,
          disabled: anyRunning,
        }, isReEnrolMode
          ? '\u2190 Back to Dashboard'
          : allAddressed ? 'Continue to Dashboard \u2192' : 'Skip remaining and continue \u2192',
        ),
      ),
    ),
  );
}

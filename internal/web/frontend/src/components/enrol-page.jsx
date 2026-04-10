import { h } from 'preact';
import { EnrolCard } from './enrol-card.jsx';
import { completeEnrolments } from '../api.js';

export function EnrolPage({ enrolments, onComplete, onUpdate }) {
  const allAddressed = enrolments.every(
    e => e.status === 'complete' || e.status === 'skipped'
  );

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
      h('h2', { class: 'enrol-heading' }, 'Complete your setup'),
      h('p', { class: 'enrol-subheading' },
        'The following credentials need to be configured before syncing can begin.',
      ),
      h('div', { class: 'enrol-list' },
        enrolments.map(e =>
          h(EnrolCard, { key: e.key, enrolment: e, onUpdate })
        ),
      ),
      h('div', { class: 'enrol-footer' },
        h('button', {
          class: 'enrol-continue-btn',
          onClick: handleContinue,
        }, allAddressed ? 'Continue to Dashboard \u2192' : 'Skip remaining and continue \u2192'),
      ),
    ),
  );
}

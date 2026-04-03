import { h } from 'preact';
import { useState, useEffect, useRef } from 'preact/hooks';
import { getEnrolments, startEnrolment, getEnrolmentStatus } from '../api.js';

export function EnrolmentBanner({ onEnrolled }) {
  const [enrolments, setEnrolments] = useState([]);
  const [active, setActive] = useState(null); // { key, status }
  const pollRef = useRef(null);

  useEffect(() => {
    loadEnrolments();
  }, []);

  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  async function loadEnrolments() {
    try {
      const data = await getEnrolments();
      setEnrolments(data.enrolments || []);
    } catch (err) {
      // Enrolments endpoint may not exist if no enrolments configured.
    }
  }

  async function handleStart(key) {
    try {
      await startEnrolment(key);
      setActive({ key, state: 'running' });
      pollRef.current = setInterval(() => pollStatus(key), 2000);
    } catch (err) {
      setActive({ key, state: 'failed', error: err.message });
    }
  }

  async function pollStatus(key) {
    try {
      const status = await getEnrolmentStatus(key);
      setActive({ key, ...status });

      if (status.state === 'complete') {
        clearInterval(pollRef.current);
        pollRef.current = null;
        if (onEnrolled) onEnrolled();
        // Refresh the list after a brief delay.
        setTimeout(() => {
          setActive(null);
          loadEnrolments();
        }, 2000);
      } else if (status.state === 'failed') {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    } catch (err) {
      // Status endpoint returns 404 once cleared; stop polling.
      clearInterval(pollRef.current);
      pollRef.current = null;
      setActive(null);
      loadEnrolments();
    }
  }

  if (!enrolments || enrolments.length === 0) return null;

  return h('div', { class: 'enrolment-banners' },
    enrolments.map(e => {
      const isActive = active && active.key === e.key;
      const state = isActive ? active.state : e.status;

      return h('div', { key: e.key, class: 'enrolment-banner' },
        h('div', { class: 'enrolment-info' },
          h('span', { class: 'enrolment-name' }, e.engine_name),
          h('span', { class: 'enrolment-key' }, ' (', e.key, ')'),
          state === 'pending' && h('span', { class: 'enrolment-status' }, ' \u2014 credentials missing'),
        ),

        // Device code display
        isActive && active.state === 'awaiting_user' && active.device_code &&
          h('div', { class: 'device-code-panel' },
            h('p', null, 'Enter this code on the provider:'),
            h('code', { class: 'device-code' }, active.device_code.user_code),
            h('a', {
              class: 'device-code-link',
              href: active.device_code.verification_uri,
              target: '_blank',
              rel: 'noopener noreferrer',
            }, 'Open verification page \u2197'),
          ),

        // Running / polling state
        isActive && active.state === 'running' &&
          h('span', { class: 'enrolment-progress' }, 'Starting...'),

        // Complete
        isActive && active.state === 'complete' &&
          h('span', { class: 'enrolment-success' }, 'Credentials acquired'),

        // Failed
        isActive && active.state === 'failed' &&
          h('span', { class: 'enrolment-error' }, 'Failed: ', active.error),

        // Start button (only when idle/pending)
        (!isActive || active.state === 'failed') && state !== 'complete' &&
          h('button', {
            class: 'enrolment-btn',
            onClick: () => handleStart(e.key),
          }, 'Set up'),
      );
    }),
  );
}

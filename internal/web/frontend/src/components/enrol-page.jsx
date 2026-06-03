import { h } from 'preact';
import { useState } from 'preact/hooks';
import { EnrolCard } from './enrol-card.jsx';
import { completeEnrolments } from '../api.js';

// buildEnrolTree partitions the flat enrolment list into an ordered render
// tree of plain items and one-level groups. A key like "databricks/prod" joins
// the "databricks" group (leaf "prod"); a flat key like "gh" stays a top-level
// item. Groups appear in first-seen order, which (because the backend sorts by
// key) clusters a group's members together.
function buildEnrolTree(enrolments) {
  const tree = [];
  const groupIndex = {};
  for (const e of enrolments) {
    const slash = e.key.indexOf('/');
    if (slash === -1) {
      tree.push({ type: 'item', enrolment: e });
      continue;
    }
    const groupName = e.key.slice(0, slash);
    const leaf = e.key.slice(slash + 1);
    if (groupIndex[groupName] === undefined) {
      groupIndex[groupName] = tree.length;
      tree.push({ type: 'group', name: groupName, items: [] });
    }
    tree[groupIndex[groupName]].items.push({ enrolment: e, leaf });
  }
  return tree;
}

function EnrolGroup({ group, onUpdate, anyRunning }) {
  const done = group.items.filter(
    m => m.enrolment.status === 'complete' || m.enrolment.status === 'skipped'
  ).length;
  const total = group.items.length;
  // Collapse a fully-addressed group by default so attention lands on the
  // groups that still need action; expand otherwise.
  const [expanded, setExpanded] = useState(done < total);

  return h('div', { class: 'enrol-group' },
    h('button', {
      class: 'enrol-group-header',
      onClick: () => setExpanded(!expanded),
      'aria-expanded': String(expanded),
    },
      h('span', { class: 'enrol-group-chevron' }, expanded ? '▾' : '▸'),
      h('span', { class: 'enrol-group-name' }, group.name),
      h('span', { class: 'enrol-group-count' }, `${done}/${total}`),
    ),
    expanded && h('div', { class: 'enrol-group-items' },
      group.items.map(m =>
        h(EnrolCard, {
          key: m.enrolment.key,
          enrolment: m.enrolment,
          displayName: m.leaf,
          onUpdate,
          anyRunning,
        })
      ),
    ),
  );
}

export function EnrolPage({ enrolments, onComplete, onUpdate }) {
  const allAddressed = enrolments.every(
    e => e.status === 'complete' || e.status === 'skipped'
  );
  const anyRunning = enrolments.some(e => e.status === 'running');
  const isReEnrolMode = allAddressed;
  const tree = buildEnrolTree(enrolments);

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
        tree.map(node =>
          node.type === 'group'
            ? h(EnrolGroup, { key: `group:${node.name}`, group: node, onUpdate, anyRunning })
            : h(EnrolCard, { key: node.enrolment.key, enrolment: node.enrolment, onUpdate, anyRunning })
        ),
      ),
      h('div', { class: 'enrol-footer' },
        h('button', {
          class: 'enrol-continue-btn',
          onClick: handleContinue,
          disabled: anyRunning,
        }, isReEnrolMode
          ? '← Back to Dashboard'
          : allAddressed ? 'Continue to Dashboard →' : 'Skip remaining and continue →',
        ),
      ),
    ),
  );
}

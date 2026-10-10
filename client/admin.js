import { api, $, h, fmt, showError } from './common.js';

let overview = null;
const loadedResults = {}; // label -> results (fetched once complete)

// Buttons that need a second click instead of a blocking confirm() dialog.
function confirmButton(text, cls, action) {
  const b = h('button', { class: cls }, text);
  let armed = false;
  b.addEventListener('click', async () => {
    if (!armed) {
      armed = true;
      b.textContent = 'Click again to confirm';
      setTimeout(() => {
        armed = false;
        b.textContent = text;
      }, 4000);
      return;
    }
    try {
      await action();
      await refresh();
    } catch (e) {
      showError($('#panel-error'), e);
    }
  });
  return b;
}

$('#login-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    await api('POST', '/api/admin/login', { password: ev.target.password.value });
    await refresh();
  } catch (e) {
    showError($('#login-error'), e);
  }
});

$('#logout').addEventListener('click', async () => {
  await api('POST', '/api/admin/logout');
  location.reload();
});

$('#reg-lock').addEventListener('change', async (ev) => {
  await api('POST', '/api/admin/settings', { registrationLocked: ev.target.checked });
  await refresh();
});

$('#clear-lists').replaceWith(
  confirmButton('Clear all lists (restart the run)', 'danger small', async () => {
    await api('POST', '/api/admin/clear-lists');
    for (const k of Object.keys(loadedResults)) delete loadedResults[k];
  })
);

function renderPrograms() {
  const wrap = $('#programs');
  wrap.replaceChildren(
    h(
      'table',
      {},
      h('tr', {}, h('th', {}, 'Program'), h('th', {}, 'Contact'), h('th', {}, 'Key'), h('th', {}, 'Registered'), h('th', {}, '')),
      overview.programs.map((p) =>
        h(
          'tr',
          {},
          h('td', {}, p.name),
          h('td', {}, p.contact || ''),
          h('td', {}, p.hasKey ? '✓' : h('span', { class: 'warn' }, 'no key yet')),
          h('td', { class: 'small muted' }, p.createdAt),
          h(
            'td',
            {},
            p.removable
              ? confirmButton('Remove', 'danger small', () => api('DELETE', `/api/admin/programs/${p.id}`))
              : h('span', { class: 'small muted', title: 'Key already applied to other lists' }, 'locked in')
          )
        )
      )
    )
  );
  $('#reg-lock').checked = overview.registrationLocked;
}

function renderLists() {
  const wrap = $('#lists');
  const n = overview.programs.length;
  const nameOf = new Map(overview.programs.map((p) => [p.id, p.name]));
  if (!overview.lists.length) return wrap.replaceChildren(h('p', { class: 'muted' }, 'No lists yet.'));
  wrap.replaceChildren(
    h(
      'div',
      { class: 'scroll' },
      h(
        'table',
        {},
        h('tr', {}, h('th', {}, 'Owner'), h('th', {}, 'Type'), h('th', {}, 'Names'), h('th', {}, 'Progress'), h('th', {}, 'Still waiting on'), h('th', {}, '')),
        overview.lists.map((l) => {
          const waiting = overview.programs.filter((p) => !l.touched.includes(p.id)).map((p) => p.name);
          return h(
            'tr',
            {},
            h('td', {}, l.program),
            h('td', {}, l.label),
            h('td', {}, fmt(l.nUnique)),
            h('td', {}, `${l.touched.length}/${n}`, l.claimedBy ? h('span', { class: 'small muted' }, ` (${nameOf.get(l.claimedBy)} working)`) : ''),
            h('td', { class: 'small' }, waiting.join(', ') || h('span', { class: 'ok' }, 'complete')),
            h('td', {}, confirmButton('Delete', 'danger small', () => api('DELETE', `/api/admin/lists/${l.id}`)))
          );
        })
      )
    )
  );
}

async function renderResults() {
  const wrap = $('#results');
  wrap.replaceChildren();
  for (const st of overview.labelStatus) {
    const sec = h('div', { class: 'list-card' }, h('h3', {}, st.label));
    wrap.append(sec);
    if (!st.complete) {
      sec.append(
        h('p', { class: 'muted' }, st.lists < 2 ? `${st.lists} list(s) uploaded; need at least two.` : 'Waiting for every program to process every list.')
      );
      continue;
    }
    if (!loadedResults[st.label]) {
      try {
        loadedResults[st.label] = await api('GET', `/api/admin/results?label=${encodeURIComponent(st.label)}`);
      } catch (e) {
        sec.append(h('p', { class: 'error' }, e.message));
        continue;
      }
    }
    sec.append(renderOneResult(st.label, loadedResults[st.label]));
  }
}

function renderOneResult(label, r) {
  const names = r.programs.map((p) => p.name);
  const out = h('div');
  const pct = (a, b) => (b ? `${Math.round((100 * a) / b)}%` : '—');

  out.append(
    h(
      'div',
      { class: 'stats' },
      stat(fmt(r.union), 'distinct names across all programs'),
      stat(r.estimatedPeople != null ? `≈ ${fmt(r.estimatedPeople)}` : '—', 'estimated distinct people'),
      stat(fmt(r.totalEntries), 'total (program, name) entries'),
      stat(r.meanProgramsPerName.toFixed(2), 'programs per applicant (mean)')
    ),
    h(
      'p',
      { class: 'small muted' },
      `Name-collision rate C₂ = ${r.c2.toExponential(2)} (pooled from within-program duplicate names). ` +
        'Estimated people solves N ≈ U + C(N,2)·C₂.'
    ),
    h(
      'div',
      { class: 'row' },
      h('a', { href: `/api/admin/results.csv?label=${encodeURIComponent(label)}` }, 'Download membership CSV'),
      h(
        'button',
        {
          class: 'link',
          onclick: () => {
            const blob = new Blob([JSON.stringify({ label, ...r }, null, 2)], { type: 'application/json' });
            const a = h('a', { href: URL.createObjectURL(blob), download: `overlap-${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.json` });
            document.body.append(a);
            a.click();
            a.remove();
          },
        },
        'Download summary JSON'
      )
    )
  );

  // Per-program table
  out.append(
    h('h4', {}, 'Per program'),
    h(
      'div',
      { class: 'scroll' },
      h(
        'table',
        { class: 'num' },
        h('tr', {}, h('th', {}, 'Program'), h('th', {}, 'Names pasted'), h('th', {}, 'Distinct'), h('th', {}, 'Only here'), h('th', {}, 'Only here %'), h('th', {}, 'Within-list duplicates')),
        r.programs.map((p) =>
          h(
            'tr',
            {},
            h('td', {}, p.name),
            h('td', {}, fmt(p.nRows)),
            h('td', {}, fmt(p.nUnique)),
            h('td', {}, fmt(p.exclusive)),
            h('td', {}, pct(p.exclusive, p.nUnique)),
            h(
              'td',
              { class: 'small' },
              Object.entries(p.spectrum)
                .filter(([m]) => Number(m) > 1)
                .map(([m, c]) => `${c}×${m}`)
                .join(', ') || '—'
            )
          )
        )
      )
    )
  );

  // Pairwise matrix
  out.append(
    h('h4', {}, 'Pairwise overlap'),
    h('p', { class: 'small muted' }, 'Cell = names on both lists. Hover for the share of the row program’s list.'),
    h(
      'div',
      { class: 'scroll' },
      h(
        'table',
        { class: 'num heat' },
        h('tr', {}, h('th', {}, ''), names.map((n) => h('th', { class: 'small' }, n))),
        r.pairwise.map((row, i) =>
          h(
            'tr',
            {},
            h('th', { class: 'small' }, names[i]),
            row.map((v, j) => {
              const share = row[i] ? v / row[i] : 0;
              return h(
                'td',
                {
                  class: 'hv',
                  title: `${pct(v, row[i])} of ${names[i]}’s list also applied to ${names[j]}`,
                  style: i === j ? 'font-weight:700' : `background: color-mix(in srgb, var(--accent) ${Math.round(share * 60)}%, transparent)`,
                },
                fmt(v)
              );
            })
          )
        )
      )
    )
  );

  // Histogram of number of programs
  const maxC = Math.max(...Object.values(r.byCount));
  out.append(
    h('h4', {}, 'How many programs each name applied to'),
    h(
      'table',
      { class: 'num' },
      h('tr', {}, h('th', {}, '# programs'), h('th', {}, 'Names'), h('th', {}, '%'), h('th', {}, '')),
      Object.entries(r.byCount).map(([k, v]) =>
        h(
          'tr',
          {},
          h('td', {}, k),
          h('td', {}, fmt(v)),
          h('td', {}, pct(v, r.union)),
          h('td', { style: 'min-width:160px' }, h('div', { style: `height:10px;border-radius:3px;background:var(--accent);width:${(100 * v) / maxC}%` }))
        )
      )
    )
  );

  // Combination patterns
  out.append(
    h('h4', {}, 'Exact combinations'),
    h(
      'details',
      {},
      h('summary', {}, `${r.patterns.length} distinct combinations`),
      h(
        'table',
        { class: 'num' },
        h('tr', {}, h('th', {}, 'Programs'), h('th', {}, 'Names')),
        r.patterns.map((p) => h('tr', {}, h('td', {}, p.programs.join(' + ')), h('td', {}, fmt(p.count))))
      )
    )
  );
  return out;
}

function stat(v, k) {
  return h('div', { class: 'stat' }, h('div', { class: 'v' }, v), h('div', { class: 'k' }, k));
}

async function refresh() {
  try {
    overview = await api('GET', '/api/admin/overview');
  } catch (e) {
    if (e.status === 401) {
      $('#login').hidden = false;
      $('#panel').hidden = true;
      return;
    }
    return showError($('#panel-error'), e);
  }
  $('#login').hidden = true;
  $('#panel').hidden = false;
  $('#logout').hidden = false;
  showError($('#panel-error'), null);
  renderPrograms();
  renderLists();
  // Re-render results only when their status changes, so open <details> stay open.
  const sig = JSON.stringify(overview.labelStatus);
  if (sig !== resultsSig) {
    resultsSig = sig;
    for (const k of Object.keys(loadedResults)) delete loadedResults[k];
    await renderResults();
  }
}

let resultsSig = null;

setInterval(() => {
  if (!$('#panel').hidden) refresh();
}, 5000);
refresh();

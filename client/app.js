import { processList, generateSecret, secretToHex, secretFromHex, publicKeyHex } from '../shared/psi-core.js';
import { api, $, h, bytesToBase64, base64ToBytes, fmt, showError } from './common.js';

// ---------------------------------------------------------------------------
// Worker plumbing
// ---------------------------------------------------------------------------

const worker = new Worker('/build/worker.js');
let nextJob = 1;
const jobs = new Map();
worker.onmessage = (ev) => {
  const job = jobs.get(ev.data.id);
  if (!job) return;
  if (ev.data.progress != null) job.onProgress?.(ev.data.progress);
  else {
    jobs.delete(ev.data.id);
    if (ev.data.error) job.reject(new Error(ev.data.error));
    else job.resolve(ev.data.points);
  }
};
function runWorker(msg, onProgress, transfer = []) {
  const id = nextJob++;
  return new Promise((resolve, reject) => {
    jobs.set(id, { resolve, reject, onProgress });
    worker.postMessage({ id, ...msg }, transfer);
  });
}

// ---------------------------------------------------------------------------
// Key storage (browser only — the secret never goes to the server)
// ---------------------------------------------------------------------------

const keyStorageName = (programId) => `psi-key-${location.host}-${programId}`;

function loadLocalKey(programId) {
  try {
    const raw = localStorage.getItem(keyStorageName(programId));
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function saveLocalKey(programId, record) {
  try {
    localStorage.setItem(keyStorageName(programId), JSON.stringify(record));
    return true;
  } catch {
    return false;
  }
}

function downloadKeyFile(record) {
  const blob = new Blob([JSON.stringify(record, null, 2)], { type: 'application/json' });
  const a = h('a', {
    href: URL.createObjectURL(blob),
    download: `psi-key-${record.programName.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}.json`,
  });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let me = null; // response of /api/me
let key = null; // { secretHex, pubkey, programId, programName }
let config = null;
const drafts = {}; // label -> { text, result, replacing }
let listsSig = null;
let uploading = false;

// ---------------------------------------------------------------------------
// Auth screens
// ---------------------------------------------------------------------------

function renderAuth() {
  $('#auth').hidden = false;
  $('#main').hidden = true;
  $('#whoami').hidden = true;
  $('#join-code-row').hidden = !config.requiresJoinCode;
  $('#register-closed').hidden = !config.registrationLocked;
  $('#register-form').hidden = config.registrationLocked;
}

$('#login-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  try {
    await api('POST', '/api/login', { name: f.name.value, password: f.password.value });
    await refresh();
  } catch (e) {
    showError($('#login-error'), e);
  }
});

$('#register-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  if (f.password.value !== f.password2.value) return showError($('#register-error'), new Error('Passwords do not match.'));
  try {
    await api('POST', '/api/register', {
      name: f.name.value,
      contact: f.contact.value,
      password: f.password.value,
      joinCode: f.joinCode?.value,
    });
    await refresh();
  } catch (e) {
    showError($('#register-error'), e);
  }
});

$('#logout').addEventListener('click', async () => {
  stopAuto();
  await api('POST', '/api/logout');
  me = null;
  key = null;
  keySig = listsSig = null;
  renderAuth();
});

// ---------------------------------------------------------------------------
// Step 1: key
// ---------------------------------------------------------------------------

let keySig = null;

function renderKey() {
  const box = $('#key-body');
  const p = me.program;
  const local = loadLocalKey(p.id);

  // Fall back to the in-memory copy if this browser refuses localStorage.
  if (local && p.pubkey && local.pubkey === p.pubkey) key = local;
  else if (!(key && p.pubkey && key.pubkey === p.pubkey && key.programId === p.id)) key = null;

  const sig = JSON.stringify([p.id, p.pubkey, !!key]);
  if (sig === keySig) return;
  keySig = sig;
  box.replaceChildren();

  $('#step-key').classList.toggle('done', !!key);

  if (key) {
    box.append(
      h('p', { class: 'ok' }, '✓ Your secret key is loaded in this browser.'),
      h('p', { class: 'muted' }, `Key fingerprint: ${key.pubkey.slice(0, 16)}…`),
      h('p', {}, h('button', { class: 'secondary', onclick: () => downloadKeyFile(key) }, 'Download backup copy of key')),
      h(
        'p',
        { class: 'muted small' },
        'Keep the backup until the whole exercise is over; you need the same key for every step. ' +
          'Do not share it with anyone — not even the organizers.'
      )
    );
    return;
  }

  if (!p.pubkey) {
    box.append(
      h(
        'p',
        {},
        'First, this browser generates a random secret key for ' + p.name + '. ' +
          'The key never leaves your computer; the server only learns a public fingerprint of it.'
      ),
      h(
        'button',
        {
          onclick: async (ev) => {
            ev.target.disabled = true;
            const k = generateSecret();
            const record = {
              programId: p.id,
              programName: p.name,
              secretHex: secretToHex(k),
              pubkey: publicKeyHex(k),
              createdAt: new Date().toISOString(),
              note: 'Secret key for the summer math programs private set intersection. Do not share.',
            };
            try {
              await api('POST', '/api/me/pubkey', { pubkey: record.pubkey });
              if (!saveLocalKey(p.id, record))
                alertBox('This browser would not save the key, so download the backup and keep it handy.');
              downloadKeyFile(record);
              await refresh();
            } catch (e) {
              ev.target.disabled = false;
              showError($('#key-error'), e);
            }
          },
        },
        'Generate my key'
      )
    );
    return;
  }

  // Server has a pubkey but this browser doesn't have the matching secret.
  const input = h('input', { type: 'file', accept: '.json,application/json' });
  input.addEventListener('change', async () => {
    try {
      const rec = JSON.parse(await input.files[0].text());
      const k = secretFromHex(rec.secretHex);
      if (publicKeyHex(k) !== p.pubkey) throw new Error('That key file is not the key registered for ' + p.name + '.');
      rec.pubkey = p.pubkey;
      rec.programId = p.id;
      saveLocalKey(p.id, rec);
      key = rec;
      await refresh();
    } catch (e) {
      showError($('#key-error'), e);
    }
  });
  box.append(
    h('p', { class: 'warn' }, `${p.name} already has a key, but it isn't in this browser.`),
    h('p', {}, 'Load the backup key file you downloaded when the key was created:'),
    h('p', {}, input)
  );
}

function alertBox(msg) {
  const el = $('#key-error');
  el.textContent = msg;
  el.hidden = false;
}

// ---------------------------------------------------------------------------
// Step 2: lists
// ---------------------------------------------------------------------------

function renderLists() {
  const wrap = $('#lists-body');
  wrap.replaceChildren();
  const myLists = me.lists.filter((l) => l.programId === me.program.id);
  $('#step-lists').classList.toggle('done', myLists.length > 0);
  $('#step-lists').classList.toggle('disabled', !key);

  for (const label of me.labels) {
    const existing = myLists.find((l) => l.label === label);
    const card = h('div', { class: 'list-card' }, h('h3', {}, label));
    wrap.append(card);

    if (existing && !drafts[label]?.replacing) {
      card.append(
        h(
          'p',
          { class: 'ok' },
          `✓ Uploaded: ${fmt(existing.nUnique)} distinct names, processed by ${existing.touched.length} of ${me.programs.length} programs.`
        ),
        h(
          'button',
          {
            class: 'secondary small',
            onclick: () => {
              drafts[label] = { replacing: true };
              listsSig = null;
              refresh();
            },
          },
          'Replace this list'
        )
      );
      continue;
    }

    const ta = h('textarea', {
      rows: 8,
      spellcheck: 'false',
      placeholder: 'One applicant per line, e.g.\nJustin Lee\nSophia Chen\nLee, Justin',
      disabled: !key,
    });
    const preview = h('div', { class: 'preview' });
    const err = h('p', { class: 'error', hidden: true });
    const uploadBtn = h('button', { disabled: true }, 'Encrypt and upload');
    const progress = h('progress', { max: 1, value: 0, hidden: true });

    const check = () => {
      const r = processList(ta.value);
      drafts[label] = { ...drafts[label], text: ta.value, result: r };
      renderPreview(preview, r);
      uploadBtn.disabled = r.nUnique === 0;
    };
    if (drafts[label]?.text) {
      ta.value = drafts[label].text;
      check();
    }
    let t;
    ta.addEventListener('input', () => {
      clearTimeout(t);
      t = setTimeout(check, 250);
    });

    uploadBtn.addEventListener('click', async () => {
      const r = drafts[label]?.result;
      if (!r || !r.nUnique) return;
      uploadBtn.disabled = true;
      ta.disabled = true;
      progress.hidden = false;
      uploading = true;
      showError(err, null);
      try {
        const points = await runWorker(
          { op: 'encrypt', keys: r.keys, secretHex: key.secretHex },
          (p) => (progress.value = p)
        );
        await api('POST', '/api/lists', {
          label,
          nRows: r.nRows,
          nUnique: r.nUnique,
          spectrum: r.spectrum,
          points: bytesToBase64(points),
          replace: !!existing,
        });
        delete drafts[label];
        uploading = false;
        await refresh();
      } catch (e) {
        uploading = false;
        showError(err, e);
        uploadBtn.disabled = false;
        ta.disabled = false;
        progress.hidden = true;
      }
    });

    card.append(
      h(
        'p',
        { class: 'small muted' },
        'Paste legal names, one per line. Leave duplicate names in — the page counts them. ' +
          'Order of first/last name does not matter. Nothing you paste here is sent anywhere; ' +
          'only encrypted values are uploaded.'
      ),
      ta,
      preview,
      h('div', { class: 'row' }, uploadBtn, progress),
      err
    );
    if (existing)
      card.append(
        h('button', { class: 'link', onclick: () => (delete drafts[label], refresh()) }, 'Cancel replacing')
      );
  }
}

function renderPreview(el, r) {
  el.replaceChildren();
  if (!r.rows.length) return;
  const dupNames = Object.entries(r.spectrum)
    .filter(([m]) => Number(m) > 1)
    .map(([m, c]) => `${c} name${c > 1 ? 's' : ''} appearing ${m}×`)
    .join(', ');
  el.append(
    h(
      'p',
      {},
      `${fmt(r.nRows)} names → ${fmt(r.nUnique)} distinct after normalizing.`,
      dupNames ? ` (${dupNames}.)` : ''
    )
  );
  const flagged = r.rows.filter((row) => row.warnings.length);
  const sample = r.rows.slice(0, 5);
  const table = (rows) =>
    h(
      'table',
      { class: 'small' },
      h('tr', {}, h('th', {}, 'Line'), h('th', {}, 'You pasted'), h('th', {}, 'Becomes'), h('th', {}, 'Note')),
      rows.map((row) =>
        h(
          'tr',
          { class: row.warnings.length ? 'flag' : '' },
          h('td', {}, row.line),
          h('td', {}, row.raw),
          h('td', { class: 'mono' }, row.key ?? '—'),
          h('td', {}, row.warnings.join('; '))
        )
      )
    );
  el.append(h('details', {}, h('summary', {}, 'How names are normalized (first 5 rows)'), table(sample)));
  if (flagged.length) {
    el.append(
      h(
        'details',
        { open: true, class: 'warnbox' },
        h('summary', {}, `${flagged.length} row${flagged.length > 1 ? 's' : ''} look unusual — please check`),
        table(flagged.slice(0, 200)),
        flagged.length > 200 ? h('p', { class: 'small' }, `…and ${flagged.length - 200} more`) : null
      )
    );
  }
}

// ---------------------------------------------------------------------------
// Step 3: process everyone else's lists
// ---------------------------------------------------------------------------

let autoOn = false;
let busy = false;

function renderWork() {
  $('#step-work').classList.toggle('disabled', !key);
  const pending = me.pending;
  $('#pending-count').textContent =
    pending === 0
      ? 'Nothing waiting for you right now.'
      : `${pending} list${pending > 1 ? 's' : ''} still need${pending > 1 ? '' : 's'} your key.`;
  $('#auto-toggle').disabled = !key;
  $('#auto-toggle').textContent = autoOn ? 'Pause' : 'Start processing';
  $('#auto-status').textContent = autoOn
    ? 'Running. Leave this tab open; new lists are processed automatically as they arrive.'
    : '';
}

function log(msg) {
  const li = h('li', {}, `${new Date().toLocaleTimeString()} — ${msg}`);
  $('#work-log').prepend(li);
  while ($('#work-log').children.length > 50) $('#work-log').lastChild.remove();
}

async function workOnce() {
  const { work, waiting } = await api('POST', '/api/work/claim');
  if (!work) return waiting ? 'waiting' : 'idle';
  const bar = $('#work-progress');
  bar.hidden = false;
  bar.value = 0;
  $('#work-current').textContent = `Applying your key to ${work.program}'s “${work.label}” list (${fmt(work.nUnique)} entries)…`;
  try {
    const input = base64ToBytes(work.points);
    const out = await runWorker(
      { op: 'reencrypt', points: input, secretHex: key.secretHex },
      (p) => (bar.value = p),
      [input.buffer]
    );
    await api('POST', `/api/work/${work.id}/submit`, { version: work.version, points: bytesToBase64(out) });
    log(`Processed ${work.program} — ${work.label}`);
  } catch (e) {
    if (e.status === 409) log(`Skipped ${work.program} — ${work.label}: ${e.message}`);
    else {
      api('POST', `/api/work/${work.id}/release`).catch(() => {});
      throw e;
    }
  } finally {
    bar.hidden = true;
    $('#work-current').textContent = '';
  }
  return 'worked';
}

async function autoLoop() {
  if (busy) return;
  busy = true;
  try {
    while (autoOn) {
      let r;
      try {
        r = await workOnce();
        showError($('#work-error'), null);
      } catch (e) {
        showError($('#work-error'), e);
        r = 'error';
      }
      await refresh(true);
      if (r !== 'worked') await new Promise((res) => setTimeout(res, r === 'error' ? 8000 : 4000));
    }
  } finally {
    busy = false;
  }
}

function stopAuto() {
  autoOn = false;
}

$('#auto-toggle').addEventListener('click', () => {
  autoOn = !autoOn;
  renderWork();
  if (autoOn) autoLoop();
});

// ---------------------------------------------------------------------------
// Status board
// ---------------------------------------------------------------------------

function renderBoard() {
  const wrap = $('#board');
  wrap.replaceChildren();
  const programs = me.programs;
  const missingKeys = programs.filter((p) => !p.hasKey);

  const summary = me.labelStatus
    .map((s) => `${s.label}: ${s.complete ? 'complete ✓' : `${s.lists} list${s.lists === 1 ? '' : 's'} uploaded`}`)
    .join(' · ');
  wrap.append(h('p', {}, `${programs.length} programs registered. ${summary}`));
  if (missingKeys.length)
    wrap.append(h('p', { class: 'warn small' }, 'Still need to generate a key: ' + missingKeys.map((p) => p.name).join(', ')));

  if (!me.lists.length) {
    wrap.append(h('p', { class: 'muted' }, 'No lists uploaded yet.'));
    return;
  }
  const table = h(
    'table',
    { class: 'board' },
    h(
      'tr',
      {},
      h('th', {}, 'List'),
      programs.map((p) =>
        h('th', { class: 'rot', title: p.name }, h('span', {}, p.name + (p.id === me.program.id ? ' (you)' : '')))
      ),
      h('th', {}, 'Done')
    ),
    me.lists.map((l) =>
      h(
        'tr',
        {},
        h('td', {}, `${l.program} — ${l.label}`),
        programs.map((p) => {
          const done = l.touched.includes(p.id);
          const working = l.claimedBy === p.id;
          return h(
            'td',
            { class: done ? 'cell done' : working ? 'cell working' : 'cell', title: p.name },
            done ? '✓' : working ? '…' : ''
          );
        }),
        h('td', {}, `${l.touched.length}/${programs.length}`)
      )
    )
  );
  wrap.append(h('div', { class: 'scroll' }, table));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function refresh(quiet = false) {
  try {
    me = await api('GET', '/api/me');
  } catch (e) {
    if (e.status === 401) {
      config = await api('GET', '/api/config');
      return renderAuth();
    }
    if (!quiet) throw e;
    return;
  }
  $('#auth').hidden = true;
  $('#main').hidden = false;
  $('#whoami').hidden = false;
  $('#whoami-name').textContent = me.program.name;
  renderKey();
  // Only rebuild the list editors when something about them changed, so the
  // periodic refresh never clobbers a list being pasted or uploaded.
  const sig = JSON.stringify([
    !!key,
    me.programs.length,
    me.lists.filter((l) => l.programId === me.program.id).map((l) => [l.id, l.touched.length]),
    Object.keys(drafts).map((k) => [k, !!drafts[k].replacing]),
  ]);
  if (sig !== listsSig && !uploading) {
    listsSig = sig;
    renderLists();
  }
  renderWork();
  renderBoard();
}

setInterval(() => {
  if (me && !busy) refresh(true);
}, 5000);

config = await api('GET', '/api/config');
await refresh();

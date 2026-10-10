import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openDatabase } from '../server/db.js';
import { createApp } from '../server/app.js';
import {
  normalizeName,
  processList,
  generateSecret,
  secretToHex,
  publicKeyHex,
  encryptKeys,
  reencrypt,
} from '../shared/psi-core.js';

// ---------------------------------------------------------------------------
// normalization
// ---------------------------------------------------------------------------

test('normalization agrees with the scheme from the email thread', () => {
  const k = (s) => normalizeName(s).key;
  assert.equal(k('Jim Jordan'), 'JIM|JORDAN');
  assert.equal(k('Joe Jameson'), 'JAMESON|JOE');
  assert.equal(k('Lee, Justin'), k('Justin Lee'));
  assert.equal(k('Justin Lee (1 of 2)'), 'JUSTIN|LEE');
  assert.equal(k('Ann-Marie Dubois'), 'ANNMARIE|DUBOIS');
  assert.equal(k('Matthew A. Husen'), 'HUSEN|MATTHEW');
  assert.equal(k('José  Núñez'), 'JOSE|NUNEZ');
  assert.equal(k("Liam O'Brien Jr."), 'LIAM|OBRIEN');
  assert.equal(k('Robert "Bobby" Smith'), 'ROBERT|SMITH');
  assert.equal(k('Justin\tLee'), 'JUSTIN|LEE');
  assert.deepEqual(normalizeName('Justin Lee (1 of 2)').warnings, []);
  assert.ok(normalizeName('jlee@example.com').warnings.length > 0);
  assert.ok(normalizeName('Madonna').warnings.includes('only one name'));
});

test('processList computes the multiplicity spectrum', () => {
  const r = processList('Justin Lee\nLee, Justin\nSophia Chen\n\nSunny Zhu\nJustin Lee (3 of 3)\nSunny Zhu\n');
  assert.equal(r.nRows, 6);
  assert.equal(r.nUnique, 3);
  assert.deepEqual(r.spectrum, { 1: 1, 2: 1, 3: 1 });
});

// ---------------------------------------------------------------------------
// end-to-end protocol through the HTTP API
// ---------------------------------------------------------------------------

async function startServer() {
  const db = openDatabase(':memory:');
  const app = createApp(db, { adminPassword: 'admin-pw', joinCode: 'join', labels: ['Completed', 'All'] });
  const server = await new Promise((res) => {
    const s = app.listen(0, () => res(s));
  });
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

function client(base) {
  let cookie = '';
  return async (method, path, body) => {
    const res = await fetch(base + path, {
      method,
      headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), cookie },
      body: body ? JSON.stringify(body) : undefined,
    });
    const set = res.headers.getSetCookie();
    if (set.length) cookie = set.map((c) => c.split(';')[0]).join('; ');
    const text = await res.text();
    const data = res.headers.get('content-type')?.includes('json') ? JSON.parse(text) : text;
    if (!res.ok) {
      const e = new Error(data.error || res.status);
      e.status = res.status;
      throw e;
    }
    return data;
  };
}

const b64 = (u8) => Buffer.from(u8).toString('base64');
const fromB64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));

test('full run: overlaps match plaintext set intersections', async () => {
  const { server, base } = await startServer();
  try {
    // A pool of names; each program samples from it, with some in-list duplicates.
    const pool = Array.from({ length: 300 }, (_, i) => `First${i} Last${i}`);
    const pick = (lo, hi) => pool.slice(lo, hi);
    const plain = {
      Ross: [...pick(0, 120), 'First5 Last5'], // one duplicate name
      PROMYS: pick(60, 180),
      MathILy: [...pick(100, 160), ...pick(250, 300)],
      Mathcamp: pick(150, 260),
    };

    const programs = {};
    for (const name of Object.keys(plain)) {
      const api = client(base);
      await api('POST', '/api/register', { name, password: 'password123', joinCode: 'join' });
      const k = generateSecret();
      await api('POST', '/api/me/pubkey', { pubkey: publicKeyHex(k) });
      programs[name] = { api, k };
    }

    // Bad join code is rejected.
    await assert.rejects(
      client(base)('POST', '/api/register', { name: 'Evil', password: 'password123', joinCode: 'nope' }),
      /join code/
    );

    // Everyone uploads.
    for (const [name, { api, k }] of Object.entries(programs)) {
      const r = processList(plain[name].join('\n'));
      await api('POST', '/api/lists', {
        label: 'Completed',
        nRows: r.nRows,
        nUnique: r.nUnique,
        spectrum: r.spectrum,
        points: b64(encryptKeys(r.keys, k)),
      });
    }

    // Results aren't available yet.
    const admin = client(base);
    await admin('POST', '/api/admin/login', { password: 'admin-pw' });
    await assert.rejects(admin('GET', '/api/admin/results?label=Completed'), /Not every list/);

    // Simulate a lost update: two claims for the same version, second submit must fail.
    {
      const a = programs.Ross;
      const { work } = await a.api('POST', '/api/work/claim');
      assert.notEqual(work.program, 'Ross', 'a program never receives its own list');
      const out = b64(reencrypt(fromB64(work.points), a.k));
      await a.api('POST', `/api/work/${work.id}/submit`, { version: work.version, points: out });
      await assert.rejects(a.api('POST', `/api/work/${work.id}/submit`, { version: work.version, points: out }), /already processed/);
    }

    // Everyone processes until nothing is left.
    for (let round = 0; round < 20; round++) {
      let did = 0;
      for (const { api, k } of Object.values(programs)) {
        for (;;) {
          const { work } = await api('POST', '/api/work/claim');
          if (!work) break;
          const out = reencrypt(fromB64(work.points), k);
          await api('POST', `/api/work/${work.id}/submit`, { version: work.version, points: b64(out) });
          did++;
        }
      }
      if (!did) break;
    }

    const res = await admin('GET', '/api/admin/results?label=Completed');
    const names = res.programs.map((p) => p.name);
    const sets = Object.fromEntries(Object.entries(plain).map(([n, l]) => [n, new Set(l)]));
    for (let i = 0; i < names.length; i++)
      for (let j = 0; j < names.length; j++) {
        const expected = [...sets[names[i]]].filter((x) => sets[names[j]].has(x)).length;
        assert.equal(res.pairwise[i][j], expected, `${names[i]} ∩ ${names[j]}`);
      }
    const union = new Set(Object.values(plain).flat());
    assert.equal(res.union, union.size);
    const ross = res.programs.find((p) => p.name === 'Ross');
    assert.deepEqual(ross.spectrum, { 1: 119, 2: 1 });
    assert.ok(res.estimatedPeople >= res.union);

    const csv = await admin('GET', '/api/admin/results.csv?label=Completed');
    assert.equal(csv.trim().split('\n').length, union.size + 1);

    // A program whose key is in use can't be removed.
    const ov = await admin('GET', '/api/admin/overview');
    await assert.rejects(admin('DELETE', `/api/admin/programs/${ov.programs[0].id}`), /key has already been applied/);
  } finally {
    server.close();
  }
});

test('server rejects malformed uploads', async () => {
  const { server, base } = await startServer();
  try {
    const api = client(base);
    await api('POST', '/api/register', { name: 'Program X', password: 'password123', joinCode: 'join' });
    const k = generateSecret();
    await assert.rejects(api('POST', '/api/lists', {}), /Generate your key/);
    await api('POST', '/api/me/pubkey', { pubkey: publicKeyHex(k) });
    const r = processList('A B\nC D');
    const pts = encryptKeys(r.keys, k);
    const good = { label: 'All', nRows: 2, nUnique: 2, spectrum: r.spectrum, points: b64(pts) };
    // wrong count
    await assert.rejects(api('POST', '/api/lists', { ...good, nUnique: 3, nRows: 3, spectrum: { 1: 3 } }), /expected 3/);
    // duplicate point
    const dup = new Uint8Array(64);
    dup.set(pts.subarray(0, 32), 0);
    dup.set(pts.subarray(0, 32), 32);
    await assert.rejects(api('POST', '/api/lists', { ...good, points: b64(dup) }), /duplicate/);
    // garbage bytes
    await assert.rejects(api('POST', '/api/lists', { ...good, points: b64(new Uint8Array(64).fill(255)) }), /invalid group element/);
    // spectrum inconsistent
    await assert.rejects(api('POST', '/api/lists', { ...good, spectrum: { 2: 1 } }), /spectrum/);
    await api('POST', '/api/lists', good);
    await assert.rejects(api('POST', '/api/lists', good), /already uploaded/);
    assert.equal(secretToHex(k).length, 64);
  } finally {
    server.close();
  }
});

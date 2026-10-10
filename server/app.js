import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getSetting, setSetting } from './db.js';
import { analyzeLabel, membershipCsv } from './analysis.js';
import { decodePoint, POINT_BYTES } from '../shared/psi-core.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const SESSION_MS = 1000 * 60 * 60 * 24 * 14;
const CLAIM_MS = 1000 * 60 * 5;
const MAX_POINTS = 200_000;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 32);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

function checkPassword(pw, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const hash = crypto.scryptSync(pw, Buffer.from(saltHex, 'hex'), 32);
  return crypto.timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// Validate a packed blob of ristretto points: right length, canonical
// encodings, all distinct.  Returns a Buffer.
function validatePoints(b64, expectedCount) {
  if (typeof b64 !== 'string') throw new HttpError(400, 'points must be a base64 string');
  const buf = Buffer.from(b64, 'base64');
  if (buf.length === 0 || buf.length % POINT_BYTES !== 0) throw new HttpError(400, 'bad points length');
  const count = buf.length / POINT_BYTES;
  if (count > MAX_POINTS) throw new HttpError(400, 'too many points');
  if (expectedCount != null && count !== expectedCount)
    throw new HttpError(400, `expected ${expectedCount} points but got ${count}`);
  const seen = new Set();
  for (let i = 0; i < buf.length; i += POINT_BYTES) {
    const slice = buf.subarray(i, i + POINT_BYTES);
    try {
      decodePoint(new Uint8Array(slice));
    } catch {
      throw new HttpError(400, `invalid group element at position ${i / POINT_BYTES}`);
    }
    const k = slice.toString('hex');
    if (seen.has(k)) throw new HttpError(400, 'duplicate points in upload');
    seen.add(k);
  }
  return buf;
}

function validateSpectrum(spectrum, nRows, nUnique) {
  if (!spectrum || typeof spectrum !== 'object') throw new HttpError(400, 'missing spectrum');
  let rows = 0;
  let uniq = 0;
  const clean = {};
  for (const [m, c] of Object.entries(spectrum)) {
    const mm = Number(m);
    if (!Number.isInteger(mm) || mm < 1 || !Number.isInteger(c) || c < 0)
      throw new HttpError(400, 'bad spectrum entry');
    if (c === 0) continue;
    clean[mm] = c;
    rows += mm * c;
    uniq += c;
  }
  if (rows !== nRows || uniq !== nUnique) throw new HttpError(400, 'spectrum does not match counts');
  return clean;
}

// ---------------------------------------------------------------------------
// app
// ---------------------------------------------------------------------------

export function createApp(db, config) {
  const { adminPassword, joinCode, labels } = config;
  const app = express();
  if (config.trustProxy) app.set('trust proxy', config.trustProxy);
  app.use(express.json({ limit: '25mb' }));

  const q = {
    programById: db.prepare('SELECT * FROM programs WHERE id = ?'),
    programByName: db.prepare('SELECT * FROM programs WHERE name = ?'),
    allPrograms: db.prepare('SELECT id, name, contact, pubkey, created_at FROM programs ORDER BY id'),
    allListsMeta: db.prepare(
      `SELECT l.id, l.program_id, p.name AS program, l.label, l.n_rows, l.n_unique, l.touched,
              l.version, l.claimed_by, l.claimed_until, l.updated_at
       FROM lists l JOIN programs p ON p.id = l.program_id ORDER BY l.id`
    ),
    listById: db.prepare('SELECT * FROM lists WHERE id = ?'),
    session: db.prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > ?'),
    insertSession: db.prepare('INSERT INTO sessions (token, program_id, is_admin, expires_at) VALUES (?, ?, ?, ?)'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
  };

  // --- sessions -------------------------------------------------------------

  function startSession(req, res, cookieName, programId, isAdmin) {
    const token = crypto.randomBytes(32).toString('base64url');
    q.insertSession.run(token, programId, isAdmin ? 1 : 0, Date.now() + SESSION_MS);
    res.cookie(cookieName, token, {
      httpOnly: true,
      sameSite: 'strict',
      secure: req.secure,
      maxAge: SESSION_MS,
      path: '/',
    });
  }

  function endSession(req, res, cookieName) {
    const token = parseCookies(req)[cookieName];
    if (token) q.deleteSession.run(token);
    res.clearCookie(cookieName, { path: '/' });
  }

  function requireProgram(req, res, next) {
    const token = parseCookies(req).psi_session;
    const s = token && q.session.get(token, Date.now());
    if (!s || !s.program_id) return res.status(401).json({ error: 'Please log in.' });
    const program = q.programById.get(s.program_id);
    if (!program) return res.status(401).json({ error: 'Please log in.' });
    req.program = program;
    next();
  }

  function requireAdmin(req, res, next) {
    const token = parseCookies(req).psi_admin;
    const s = token && q.session.get(token, Date.now());
    if (!s || !s.is_admin) return res.status(401).json({ error: 'Admin login required.' });
    next();
  }

  const wrap = (fn) => (req, res, next) => {
    try {
      const out = fn(req, res);
      if (out !== undefined && !res.headersSent) res.json(out);
    } catch (e) {
      next(e);
    }
  };

  // --- protocol state -------------------------------------------------------

  function state() {
    const programs = q.allPrograms.all();
    const ids = programs.map((p) => p.id);
    const lists = q.allListsMeta.all().map((l) => {
      const touched = JSON.parse(l.touched);
      return {
        id: l.id,
        programId: l.program_id,
        program: l.program,
        label: l.label,
        nUnique: l.n_unique,
        touched,
        version: l.version,
        claimedBy: l.claimed_until > Date.now() ? l.claimed_by : null,
        complete: ids.every((id) => touched.includes(id)),
        updatedAt: l.updated_at,
      };
    });
    const allKeyed = programs.length > 0 && programs.every((p) => p.pubkey);
    const labelStatus = labels.map((label) => {
      const ls = lists.filter((l) => l.label === label);
      return {
        label,
        lists: ls.length,
        complete: allKeyed && ls.length >= 2 && ls.every((l) => l.complete),
      };
    });
    return { programs, lists, labelStatus, allKeyed };
  }

  function publicState() {
    const s = state();
    return {
      labels,
      registrationLocked: getSetting(db, 'registrationLocked', false),
      programs: s.programs.map((p) => ({ id: p.id, name: p.name, hasKey: !!p.pubkey })),
      lists: s.lists,
      labelStatus: s.labelStatus,
    };
  }

  // --- public API -----------------------------------------------------------

  app.get('/api/config', wrap(() => ({
    labels,
    requiresJoinCode: !!joinCode,
    registrationLocked: getSetting(db, 'registrationLocked', false),
  })));

  app.post('/api/register', wrap((req, res) => {
    if (getSetting(db, 'registrationLocked', false))
      throw new HttpError(403, 'Registration is closed. Ask the organizer to reopen it.');
    const { name, password, contact, joinCode: code } = req.body || {};
    if (joinCode && !safeEqual(code || '', joinCode)) throw new HttpError(403, 'Incorrect join code.');
    const cleanName = String(name || '').trim().replace(/\s+/g, ' ');
    if (cleanName.length < 2 || cleanName.length > 80) throw new HttpError(400, 'Program name must be 2–80 characters.');
    if (String(password || '').length < 8) throw new HttpError(400, 'Password must be at least 8 characters.');
    if (q.programByName.get(cleanName)) throw new HttpError(409, 'A program with that name is already registered. Log in instead.');
    const info = db
      .prepare('INSERT INTO programs (name, contact, password_hash) VALUES (?, ?, ?)')
      .run(cleanName, String(contact || '').slice(0, 200), hashPassword(String(password)));
    startSession(req, res, 'psi_session', info.lastInsertRowid, false);
    return { ok: true };
  }));

  app.post('/api/login', wrap((req, res) => {
    const { name, password } = req.body || {};
    const p = q.programByName.get(String(name || '').trim().replace(/\s+/g, ' '));
    if (!p || !checkPassword(String(password || ''), p.password_hash))
      throw new HttpError(401, 'Unknown program name or wrong password.');
    startSession(req, res, 'psi_session', p.id, false);
    return { ok: true };
  }));

  app.post('/api/logout', wrap((req, res) => {
    endSession(req, res, 'psi_session');
    return { ok: true };
  }));

  app.get('/api/me', requireProgram, wrap((req) => {
    const s = publicState();
    const me = req.program;
    return {
      program: { id: me.id, name: me.name, contact: me.contact, pubkey: me.pubkey },
      pending: s.lists.filter((l) => !l.touched.includes(me.id)).length,
      ...s,
    };
  }));

  app.post('/api/me/pubkey', requireProgram, wrap((req) => {
    const { pubkey } = req.body || {};
    if (req.program.pubkey) throw new HttpError(409, 'This program already has a key registered.');
    if (!/^[0-9a-f]{64}$/.test(pubkey || '')) throw new HttpError(400, 'Bad public key.');
    try {
      decodePoint(Buffer.from(pubkey, 'hex'));
    } catch {
      throw new HttpError(400, 'Bad public key.');
    }
    db.prepare('UPDATE programs SET pubkey = ? WHERE id = ?').run(pubkey, req.program.id);
    return { ok: true };
  }));

  // Upload a program's own list (already hashed, blinded with its key, shuffled).
  app.post('/api/lists', requireProgram, wrap((req) => {
    const me = req.program;
    if (!me.pubkey) throw new HttpError(400, 'Generate your key first.');
    const { label, nRows, nUnique, spectrum, points, replace } = req.body || {};
    if (!labels.includes(label)) throw new HttpError(400, 'Unknown list type.');
    if (!Number.isInteger(nRows) || !Number.isInteger(nUnique) || nUnique < 1 || nRows < nUnique)
      throw new HttpError(400, 'Bad counts.');
    const spec = validateSpectrum(spectrum, nRows, nUnique);
    const buf = validatePoints(points, nUnique);

    return db.transaction(() => {
      const existing = db.prepare('SELECT id FROM lists WHERE program_id = ? AND label = ?').get(me.id, label);
      if (existing) {
        if (!replace) throw new HttpError(409, `You already uploaded a "${label}" list.`);
        db.prepare('DELETE FROM lists WHERE id = ?').run(existing.id);
      }
      const info = db
        .prepare(
          `INSERT INTO lists (program_id, label, n_rows, n_unique, spectrum, points, touched)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(me.id, label, nRows, nUnique, JSON.stringify(spec), buf, JSON.stringify([me.id]));
      return { ok: true, id: info.lastInsertRowid };
    })();
  }));

  app.delete('/api/lists/:id', requireProgram, wrap((req) => {
    const l = q.listById.get(Number(req.params.id));
    if (!l || l.program_id !== req.program.id) throw new HttpError(404, 'No such list.');
    db.prepare('DELETE FROM lists WHERE id = ?').run(l.id);
    return { ok: true };
  }));

  // Hand this program one list it still needs to apply its key to.
  //
  // A program may only ever download lists it has NOT yet touched, and never
  // its own list after creation.  This keeps it from comparing its own names
  // against another program's list at the same stage of encryption.
  app.post('/api/work/claim', requireProgram, wrap((req) => {
    const me = req.program;
    if (!me.pubkey) throw new HttpError(400, 'Generate your key first.');
    return db.transaction(() => {
      const now = Date.now();
      const candidates = db
        .prepare('SELECT id, touched, claimed_by, claimed_until FROM lists')
        .all()
        .filter((l) => !JSON.parse(l.touched).includes(me.id))
        .filter((l) => !l.claimed_by || l.claimed_until < now || l.claimed_by === me.id);
      if (candidates.length === 0) {
        const anyPending = db
          .prepare('SELECT touched FROM lists')
          .all()
          .some((l) => !JSON.parse(l.touched).includes(me.id));
        return { work: null, waiting: anyPending };
      }
      // Random choice spreads programs across lists, reducing contention.
      const pick = candidates[crypto.randomInt(candidates.length)];
      db.prepare('UPDATE lists SET claimed_by = ?, claimed_until = ? WHERE id = ?').run(me.id, now + CLAIM_MS, pick.id);
      const l = q.listById.get(pick.id);
      return {
        work: {
          id: l.id,
          version: l.version,
          label: l.label,
          program: q.programById.get(l.program_id).name,
          nUnique: l.n_unique,
          points: l.points.toString('base64'),
        },
      };
    })();
  }));

  app.post('/api/work/:id/submit', requireProgram, wrap((req) => {
    const me = req.program;
    const { version, points } = req.body || {};
    const id = Number(req.params.id);
    const pre = q.listById.get(id);
    if (!pre) throw new HttpError(404, 'That list was deleted.');
    const buf = validatePoints(points, pre.n_unique);
    return db.transaction(() => {
      const l = q.listById.get(id);
      if (!l) throw new HttpError(404, 'That list was deleted.');
      const touched = JSON.parse(l.touched);
      if (touched.includes(me.id)) throw new HttpError(409, 'You already processed this list.');
      if (l.version !== version)
        throw new HttpError(409, 'Someone else updated this list while you were working; it will be retried.');
      if (l.claimed_by && l.claimed_by !== me.id && l.claimed_until > Date.now())
        throw new HttpError(409, 'Another program is working on this list; it will be retried.');
      touched.push(me.id);
      db.prepare(
        `UPDATE lists SET points = ?, touched = ?, version = version + 1, claimed_by = NULL,
                claimed_until = NULL, updated_at = datetime('now') WHERE id = ?`
      ).run(buf, JSON.stringify(touched), id);
      db.prepare('INSERT INTO contributions (list_id, program_id) VALUES (?, ?)').run(id, me.id);
      return { ok: true };
    })();
  }));

  app.post('/api/work/:id/release', requireProgram, wrap((req) => {
    db.prepare('UPDATE lists SET claimed_by = NULL, claimed_until = NULL WHERE id = ? AND claimed_by = ?').run(
      Number(req.params.id),
      req.program.id
    );
    return { ok: true };
  }));

  // --- admin API ------------------------------------------------------------

  app.post('/api/admin/login', wrap((req, res) => {
    if (!safeEqual((req.body || {}).password || '', adminPassword)) throw new HttpError(401, 'Wrong admin password.');
    startSession(req, res, 'psi_admin', null, true);
    return { ok: true };
  }));

  app.post('/api/admin/logout', wrap((req, res) => {
    endSession(req, res, 'psi_admin');
    return { ok: true };
  }));

  app.get('/api/admin/overview', requireAdmin, wrap(() => {
    const s = state();
    const contributed = new Set(db.prepare('SELECT DISTINCT program_id FROM contributions').all().map((r) => r.program_id));
    return {
      labels,
      registrationLocked: getSetting(db, 'registrationLocked', false),
      programs: s.programs.map((p) => ({
        id: p.id,
        name: p.name,
        contact: p.contact,
        hasKey: !!p.pubkey,
        createdAt: p.created_at,
        removable: !contributed.has(p.id),
      })),
      lists: s.lists,
      labelStatus: s.labelStatus,
    };
  }));

  app.post('/api/admin/settings', requireAdmin, wrap((req) => {
    const { registrationLocked } = req.body || {};
    if (typeof registrationLocked === 'boolean') setSetting(db, 'registrationLocked', registrationLocked);
    return { ok: true };
  }));

  app.delete('/api/admin/programs/:id', requireAdmin, wrap((req) => {
    const id = Number(req.params.id);
    const used = db.prepare('SELECT COUNT(*) AS n FROM contributions WHERE program_id = ?').get(id).n;
    if (used > 0)
      throw new HttpError(
        409,
        "This program's key has already been applied to other lists, so removing it would make those lists " +
          "incomparable. Use “Clear all lists” to restart the run instead."
      );
    db.prepare('DELETE FROM programs WHERE id = ?').run(id);
    return { ok: true };
  }));

  app.delete('/api/admin/lists/:id', requireAdmin, wrap((req) => {
    db.prepare('DELETE FROM lists WHERE id = ?').run(Number(req.params.id));
    return { ok: true };
  }));

  // Start the encryption run over (e.g. after a practice round).  Programs and
  // their keys stay; everyone re-uploads their lists.
  app.post('/api/admin/clear-lists', requireAdmin, wrap(() => {
    db.transaction(() => {
      db.prepare('DELETE FROM lists').run();
      db.prepare('DELETE FROM contributions').run();
    })();
    return { ok: true };
  }));

  function computeResults(label) {
    const s = state();
    const st = s.labelStatus.find((x) => x.label === label);
    if (!st) throw new HttpError(404, 'Unknown label.');
    if (!st.complete) throw new HttpError(409, 'Not every list has been processed by every program yet.');
    const rows = db
      .prepare(
        `SELECT p.name AS program, l.n_rows, l.n_unique, l.spectrum, l.points
         FROM lists l JOIN programs p ON p.id = l.program_id WHERE l.label = ? ORDER BY p.name COLLATE NOCASE`
      )
      .all(label);
    return analyzeLabel(
      rows.map((r) => ({
        program: r.program,
        nRows: r.n_rows,
        nUnique: r.n_unique,
        spectrum: JSON.parse(r.spectrum),
        points: r.points,
      }))
    );
  }

  app.get('/api/admin/results', requireAdmin, wrap((req) => {
    const { membership, ...rest } = computeResults(String(req.query.label || ''));
    return rest;
  }));

  app.get('/api/admin/results.csv', requireAdmin, (req, res, next) => {
    try {
      const label = String(req.query.label || '');
      const csv = membershipCsv(label, computeResults(label));
      const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, '-');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="overlap-${slug}.csv"`);
      res.send(csv);
    } catch (e) {
      next(e);
    }
  });

  // --- static ---------------------------------------------------------------

  app.use(express.static(PUBLIC_DIR, { extensions: ['html'] }));

  app.use((err, req, res, _next) => {
    const status = err.status || (err.type === 'entity.too.large' ? 413 : 500);
    if (status >= 500) console.error(err);
    res.status(status).json({ error: status >= 500 ? 'Server error.' : err.message });
  });

  return app;
}

import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

export function openDatabase(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS programs (
      id            INTEGER PRIMARY KEY,
      name          TEXT NOT NULL UNIQUE COLLATE NOCASE,
      contact       TEXT,
      password_hash TEXT NOT NULL,
      pubkey        TEXT,            -- hex k*G, set once the browser generates a key
      created_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- A "list" is one program's encrypted applicant list for one label
    -- (e.g. "Completed applications").  Its points get re-encrypted in place as
    -- every other program contributes; "touched" records whose keys are applied.
    CREATE TABLE IF NOT EXISTS lists (
      id            INTEGER PRIMARY KEY,
      program_id    INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
      label         TEXT NOT NULL,
      n_rows        INTEGER NOT NULL,  -- names pasted (with duplicates)
      n_unique      INTEGER NOT NULL,  -- distinct normalized names = number of points
      spectrum      TEXT NOT NULL,     -- JSON {multiplicity: count}
      points        BLOB NOT NULL,     -- n_unique * 32 bytes
      touched       TEXT NOT NULL,     -- JSON array of program ids
      version       INTEGER NOT NULL DEFAULT 1,
      claimed_by    INTEGER,
      claimed_until INTEGER,           -- unix ms
      created_at    TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE (program_id, label)
    );

    CREATE TABLE IF NOT EXISTS contributions (
      id         INTEGER PRIMARY KEY,
      list_id    INTEGER NOT NULL,
      program_id INTEGER NOT NULL,
      at         TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token      TEXT PRIMARY KEY,
      program_id INTEGER REFERENCES programs(id) ON DELETE CASCADE, -- NULL for admin
      is_admin   INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS settings (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);
  return db;
}

export function getSetting(db, key, fallback = null) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? JSON.parse(row.value) : fallback;
}

export function setSetting(db, key, value) {
  db.prepare(
    'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
  ).run(key, JSON.stringify(value));
}

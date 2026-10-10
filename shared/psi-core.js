// Shared cryptographic core for the private set intersection protocol.
//
// Used by the browser (bundled into public/build/psi-worker.js), by the
// server (to validate uploaded points), and by the test suite.
//
// The protocol is the classic Meadows / Huberman-Franklin-Hogg commutative
// encryption PSI, instantiated in the ristretto255 prime-order group:
//
//   1. Every program picks a secret scalar k_i.
//   2. Each normalized name x is hashed to a group element H(x).
//   3. A program publishes k_i * H(x) for each of its (deduplicated) names,
//      shuffled.
//   4. Every other program j multiplies each element of that list by k_j and
//      reshuffles.  Because scalar multiplication commutes, once every program
//      has touched every list, each name x has become (k_1 k_2 ... k_n) * H(x)
//      no matter which program submitted it, so equal names collide while no
//      party (nor the server) can invert the mapping.

import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';

const Point = ristretto255.Point;
const ORDER = Point.Fn.ORDER;

export const POINT_BYTES = 32;
export const DST = 'summer-math-programs-psi-v1';

// ---------------------------------------------------------------------------
// Name normalization
// ---------------------------------------------------------------------------

const SUFFIXES = new Set(['JR', 'SR', 'II', 'III', 'IV', 'V', 'JNR', 'SNR']);

// Turn one pasted line into a canonical key, plus warnings for the human.
//
// "Justin Lee (1 of 2)" -> "JUSTIN LEE"... then sorted -> "JUSTIN|LEE"
// "Lee, Justin"         -> "JUSTIN|LEE"   (word order doesn't matter)
// "sarah-marie belcastro" -> "BELCASTRO|SARAHMARIE"
// "Matthew A. Husen"    -> "HUSEN|MATTHEW" (middle names/initials dropped)
export function normalizeName(line) {
  const warnings = [];
  let s = String(line ?? '');

  if (/@/.test(s)) warnings.push('looks like an email address');
  // Drop parenthetical/bracketed asides like "(1 of 2)" or "[nickname]".
  s = s.replace(/\([^)]*\)|\[[^\]]*\]|\{[^}]*\}/g, ' ');
  // Strip quoted nicknames: Robert "Bobby" Smith
  s = s.replace(/"[^"]*"|“[^”]*”/g, ' ');
  if (/\d/.test(s)) warnings.push('contains digits');

  // Unicode: decompose accents, then drop combining marks (José -> Jose).
  s = s.normalize('NFKD').replace(/\p{M}+/gu, '');

  // Commas, tabs, semicolons, slashes act as word separators
  // (so "Lee, Justin" and spreadsheet "Justin<TAB>Lee" both work).
  s = s.replace(/[,\t;/|]+/g, ' ');

  let words = s
    .split(/\s+/)
    .map((w) => w.toUpperCase().replace(/[^\p{L}\p{N}]/gu, '')) // hyphens, apostrophes, periods vanish
    .filter((w) => w.length > 0);

  // Drop generational suffixes from the end.
  while (words.length > 2 && SUFFIXES.has(words[words.length - 1])) words.pop();

  if (words.length === 0) return { key: null, warnings: ['empty'] };
  if (words.length === 1) warnings.push('only one name');
  if (words.length > 4) warnings.push(`${words.length} words`);

  const first = words[0];
  const last = words[words.length - 1];
  const pair = words.length === 1 ? [first] : [first, last].sort();
  return { key: pair.join('|'), warnings };
}

// Normalize a whole pasted list.  Returns per-row info, the deduplicated keys,
// and the multiplicity spectrum: spectrum[m] = number of keys that appear
// exactly m times in this list.
export function processList(text) {
  const rows = [];
  const counts = new Map();
  const lines = String(text ?? '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (raw.trim() === '') continue;
    const { key, warnings } = normalizeName(raw);
    rows.push({ line: i + 1, raw, key, warnings });
    if (key) counts.set(key, (counts.get(key) || 0) + 1);
  }
  const spectrum = {};
  for (const m of counts.values()) spectrum[m] = (spectrum[m] || 0) + 1;
  return {
    rows,
    keys: [...counts.keys()],
    nRows: rows.filter((r) => r.key).length,
    nUnique: counts.size,
    spectrum,
  };
}

// ---------------------------------------------------------------------------
// Group operations
// ---------------------------------------------------------------------------

export function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(h) {
  if (!/^([0-9a-f]{2})*$/i.test(h)) throw new Error('bad hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

function bytesToBigInt(b) {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

// A fresh secret scalar, uniform in [1, ORDER).
export function generateSecret() {
  for (;;) {
    // 64 bytes reduced mod ORDER gives negligible bias.
    const k = bytesToBigInt(randomBytes(64)) % ORDER;
    if (k !== 0n) return k;
  }
}

export function secretToHex(k) {
  return k.toString(16).padStart(64, '0');
}

export function secretFromHex(h) {
  const k = BigInt('0x' + h);
  if (k <= 0n || k >= ORDER) throw new Error('secret out of range');
  return k;
}

// The public "fingerprint" of a secret: k * G.  The server stores this so the
// browser can confirm it is using the same key it registered with.
export function publicKeyHex(k) {
  return bytesToHex(Point.BASE.multiply(k).toBytes());
}

export function hashName(key) {
  return ristretto255_hasher.hashToCurve(new TextEncoder().encode(key), { DST });
}

export function decodePoint(bytes) {
  return Point.fromBytes(bytes); // throws on non-canonical / invalid encodings
}

// Pack an array of 32-byte encodings into one Uint8Array, and back.
export function packPoints(list) {
  const out = new Uint8Array(list.length * POINT_BYTES);
  list.forEach((b, i) => out.set(b, i * POINT_BYTES));
  return out;
}

export function unpackPoints(buf) {
  if (buf.length % POINT_BYTES !== 0) throw new Error('blob length is not a multiple of 32');
  const out = [];
  for (let i = 0; i < buf.length; i += POINT_BYTES) out.push(buf.subarray(i, i + POINT_BYTES));
  return out;
}

// Unbiased Fisher-Yates shuffle using the CSPRNG.
export function shuffle(arr) {
  const buf = new Uint32Array(1);
  for (let i = arr.length - 1; i > 0; i--) {
    const bound = i + 1;
    const limit = Math.floor(0x100000000 / bound) * bound;
    let r;
    do {
      globalThis.crypto.getRandomValues(buf);
      r = buf[0];
    } while (r >= limit);
    const j = r % bound;
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// First step for a program's own list: hash, blind with k, shuffle.
export function encryptKeys(keys, k, onProgress) {
  const out = [];
  for (let i = 0; i < keys.length; i++) {
    out.push(hashName(keys[i]).multiply(k).toBytes());
    if (onProgress && (i & 63) === 0) onProgress(i, keys.length);
  }
  return packPoints(shuffle(out));
}

// Every later step: multiply each element by k, shuffle.
export function reencrypt(packed, k, onProgress) {
  const pts = unpackPoints(packed);
  const out = [];
  for (let i = 0; i < pts.length; i++) {
    out.push(decodePoint(pts[i]).multiply(k).toBytes());
    if (onProgress && (i & 63) === 0) onProgress(i, pts.length);
  }
  return packPoints(shuffle(out));
}

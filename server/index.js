import crypto from 'node:crypto';
import { openDatabase } from './db.js';
import { createApp } from './app.js';

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || undefined; // e.g. 127.0.0.1 behind a reverse proxy
const dbFile = process.env.DATABASE || 'data/psi.sqlite';

let adminPassword = process.env.ADMIN_PASSWORD;
if (!adminPassword) {
  adminPassword = crypto.randomBytes(9).toString('base64url');
  console.log(`ADMIN_PASSWORD not set; using a one-time admin password: ${adminPassword}`);
}

const joinCode = process.env.JOIN_CODE || '';
if (!joinCode) console.log('JOIN_CODE not set; anyone who can reach the site can register a program.');

const labels = (process.env.LIST_LABELS || 'Completed applications,All applicants')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const db = openDatabase(dbFile);
const app = createApp(db, { adminPassword, joinCode, labels, trustProxy: process.env.TRUST_PROXY });

app.listen(port, host, () => {
  console.log(`PSI server listening on http://${host || 'localhost'}:${port}  (database: ${dbFile})`);
});

// Runs the expensive elliptic-curve work off the main thread.
import { encryptKeys, reencrypt, secretFromHex } from '../shared/psi-core.js';

self.onmessage = (ev) => {
  const { id, op, secretHex } = ev.data;
  const progress = (i, n) => self.postMessage({ id, progress: n ? i / n : 1 });
  try {
    const k = secretFromHex(secretHex);
    let points;
    if (op === 'encrypt') points = encryptKeys(ev.data.keys, k, progress);
    else if (op === 'reencrypt') points = reencrypt(ev.data.points, k, progress);
    else throw new Error(`unknown op ${op}`);
    self.postMessage({ id, done: true, points }, [points.buffer]);
  } catch (e) {
    self.postMessage({ id, error: String(e.message || e) });
  }
};

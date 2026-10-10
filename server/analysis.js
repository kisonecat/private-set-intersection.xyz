// Turn fully-encrypted lists into overlap statistics.
//
// Once every program has applied its key to every list, two entries are equal
// exactly when the underlying normalized names are equal.  So we can treat each
// distinct 32-byte value as an opaque "name" and record which programs have it.

function bufToKey(buf, i) {
  return buf.subarray(i, i + 32).toString('base64');
}

// lists: [{ program, nRows, nUnique, spectrum, points: Buffer }] all with the same label.
export function analyzeLabel(lists) {
  const programs = lists.map((l) => l.program);
  const membership = new Map(); // opaque name -> array of program indices

  lists.forEach((l, idx) => {
    for (let i = 0; i < l.points.length; i += 32) {
      const k = bufToKey(l.points, i);
      let arr = membership.get(k);
      if (!arr) membership.set(k, (arr = []));
      arr.push(idx);
    }
  });

  const n = programs.length;
  const union = membership.size;

  // Pairwise intersection sizes.
  const pairwise = Array.from({ length: n }, () => new Array(n).fill(0));
  // Distribution of "number of programs applied to".
  const byCount = {};
  // Exact combination patterns.
  const patterns = new Map();

  for (const arr of membership.values()) {
    byCount[arr.length] = (byCount[arr.length] || 0) + 1;
    const pkey = arr.join(',');
    patterns.set(pkey, (patterns.get(pkey) || 0) + 1);
    for (const a of arr) for (const b of arr) pairwise[a][b]++;
  }

  const totalEntries = lists.reduce((s, l) => s + l.nUnique, 0);

  // Estimate C2 = P(two distinct applicants share a normalized name) from the
  // within-program multiplicity spectra, pooled across programs.
  let samePairs = 0;
  let allPairs = 0;
  for (const l of lists) {
    for (const [m, count] of Object.entries(l.spectrum)) {
      const mm = Number(m);
      samePairs += (count * mm * (mm - 1)) / 2;
    }
    allPairs += (l.nRows * (l.nRows - 1)) / 2;
  }
  const c2 = allPairs > 0 ? samePairs / allPairs : 0;

  // E[U] ~= N - C(N,2) C2, so iterate N <- U + C(N,2) C2.
  let est = union;
  for (let i = 0; i < 100; i++) est = union + (est * (est - 1) * c2) / 2;

  return {
    programs: lists.map((l) => ({
      name: l.program,
      nRows: l.nRows,
      nUnique: l.nUnique,
      spectrum: l.spectrum,
      exclusive: patterns.get(String(lists.indexOf(l))) || 0,
    })),
    union,
    totalEntries,
    meanProgramsPerName: union ? totalEntries / union : 0,
    pairwise,
    byCount,
    patterns: [...patterns.entries()]
      .map(([k, count]) => ({ programs: k.split(',').map((i) => programs[Number(i)]), count }))
      .sort((a, b) => b.count - a.count || a.programs.length - b.programs.length),
    c2,
    estimatedPeople: Number.isFinite(est) ? Math.round(est) : null,
    membership, // used for CSV export; stripped before JSON
  };
}

export function membershipCsv(label, result) {
  const header = ['id', 'label', ...result.programs.map((p) => p.name), 'num_programs'];
  const esc = (s) => (/[",\n]/.test(s) ? `"${String(s).replace(/"/g, '""')}"` : String(s));
  const lines = [header.map(esc).join(',')];
  // Sort by the opaque value so row order carries no information about input order.
  const keys = [...result.membership.keys()].sort();
  keys.forEach((k, i) => {
    const arr = result.membership.get(k);
    const row = result.programs.map((_, idx) => (arr.includes(idx) ? 1 : 0));
    lines.push([i + 1, esc(label), ...row, arr.length].join(','));
  });
  return lines.join('\n') + '\n';
}

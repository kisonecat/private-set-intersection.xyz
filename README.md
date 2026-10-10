# private-set-intersection.xyz

Counting overlap between summer math programs’ applicant pools — without sharing names.

📄 **Documentation (PDF):** https://kisonecat.github.io/private-set-intersection.xyz/private-set-intersection.pdf
(source in [`docs/psi.tex`](docs/psi.tex), rebuilt by GitHub Actions on every push).

This site lets Consortium programs measure how much their applicant pools overlap without anyone
sharing a list of names: not with each other, and not with the server.

## How it works

The protocol is the standard Diffie–Hellman (Meadows / Huberman–Franklin–Hogg)
[private set intersection](https://en.wikipedia.org/wiki/Private_set_intersection), run in
the ristretto255 elliptic-curve group (via [`@noble/curves`](https://github.com/paulmillr/noble-curves)).

1. **Key.** Each program's browser generates a random secret scalar `k`. Only the public
   fingerprint `k·G` goes to the server, so the page can detect when someone loads the wrong key file.
2. **Normalize.** Pasted names are normalized in the browser. The rules:
   - Drop parentheticals ("Justin Lee (1 of 2)") and quoted nicknames.
   - Strip accents and punctuation, so "Ann-Marie" becomes `ANNMARIE`.
   - Keep the first and last words, dropping middle names/initials and Jr/III.
   - Sort those two words alphabetically. "Jim Jordan" becomes `JIM|JORDAN`, and "Lee, Justin" becomes the same key as "Justin Lee".

   The page counts duplicate names to build the program's *multiplicity spectrum*, then deduplicates the list.
3. **Upload.** Each name `x` is hashed to a curve point `H(x)`, multiplied by `k`, shuffled, and uploaded.
4. **Process.** Every other program multiplies each point in that list by its own key and reshuffles.
   Scalar multiplication commutes, so once every program has touched every list, a name has become
   `(k₁k₂…kₙ)·H(x)` no matter who submitted it. Equal names collide, but nobody can invert the values.
5. **Analyze.** The server compares the fully encrypted values and reports:
   - the size of the union
   - the pairwise overlap matrix
   - how many programs each name applied to
   - exact combination counts
   - an estimate of distinct *people*, using the pooled name-collision rate C₂ from the spectra: N ≈ U + C(N,2)·C₂

   It can also export a de-identified membership CSV.

All cryptography runs in the browser. The bundle in `public/build/` is deliberately not minified,
so anyone can "view source". A program can only download lists it hasn't processed yet, and it
never sees its own list again after uploading it. That stops a program from comparing its own
names against another program's list at the same stage of encryption.

### Coordination

There are no fixed rounds or "circle". After uploading, each program clicks **Start processing** and
leaves the tab open. The page keeps claiming lists that still need its key, processes them in a Web
Worker, and uploads them. Two programs working at the same moment is safe: the server uses
short claims plus a version check, so a conflicting update is rejected and retried. The progress
board shows every list × program cell, so it's obvious who is holding things up.

### Threat model / limitations

- This assumes *honest-but-curious* participants. Nothing proves that a program really applied its key.
  A program that deliberately skips that step, or registers fake "programs" with the join code, could
  learn more than it should. Use a join code, close registration once everyone has joined, and
  check the program list.
- Results (who overlaps with whom) are visible only on the organizer page.
- Matching is by normalized name, so different people with the same name merge and nickname
  variants split. The spectrum-based estimate corrects the first effect, not the second.

## Running

```sh
npm install
ADMIN_PASSWORD=... JOIN_CODE=... npm start     # builds the client, serves on :3000
npm test
```

| Variable         | Default                                   | Meaning                                    |
|------------------|-------------------------------------------|--------------------------------------------|
| `PORT`           | `3000`                                    |                                            |
| `DATABASE`       | `data/psi.sqlite`                         | SQLite file                                |
| `ADMIN_PASSWORD` | random, printed at startup                | for `/admin`                               |
| `JOIN_CODE`      | none (open registration)                  | code programs need in order to register    |
| `LIST_LABELS`    | `Completed applications,All applicants`   | comma-separated list types; one list per type per program |
| `TRUST_PROXY`    | unset                                     | Express `trust proxy` setting when behind HTTPS |

Serve it over HTTPS in production. Browsers need a secure context for `crypto.getRandomValues`
on non-localhost origins, and cookies should be marked `secure`.

## Organizer page (`/admin`)

From the organizer page you can:

- Watch progress.
- Close registration.
- Remove a program that registered by mistake. This only works before its key has been applied to anyone else's list.
- Delete individual lists.
- **Clear all lists.** This keeps programs and keys, which is handy after a practice run.
- View and download results once a list type is complete.

## Instructions to send participants in advance

- Bring a plain list of applicant **legal names**, one per line (first and last name; order doesn't matter).
- Leave duplicate names in. Don't add "(1 of 2)" markers. If they're already there, that's fine.
- Optionally prepare a second list for "All applicants" in addition to "Completed applications".
- Use a laptop with a current Chrome, Firefox, or Safari. Keep the downloaded key file until the exercise is over.

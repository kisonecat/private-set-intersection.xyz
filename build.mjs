// Bundle the browser code.  Output is deliberately NOT minified so that
// participants can read exactly what runs on their machine.
import * as esbuild from 'esbuild';

await esbuild.build({
  entryPoints: ['client/app.js', 'client/admin.js', 'client/worker.js'],
  outdir: 'public/build',
  bundle: true,
  format: 'esm',
  target: 'es2022',
  minify: false,
  legalComments: 'inline',
  logLevel: 'info',
});

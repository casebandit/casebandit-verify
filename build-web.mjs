#!/usr/bin/env node
/**
 * Build the single-file offline `verify.html`:
 *   1. esbuild --bundle --format=iife the keyless web core (web/web-entry.ts);
 *   2. inline the IIFE + a tiny bootstrap UI into ONE self-contained HTML file
 *      that opens from `file://` under CSP `default-src 'none'` (so the script
 *      MUST be inline — an external <script src> would be blocked).
 *
 * CSP note: `default-src 'none'` blocks everything; we add the minimal
 * `script-src 'unsafe-inline'` + `style-src 'unsafe-inline'` so the inline
 * bundle + the inline UI bootstrap run, and NOTHING else (no network, no
 * external fetch, no eval). The bundle itself makes zero network calls.
 *
 * Prints the SHA-256 of the produced verify.html so the README pin can be
 * reproduced: `node build-web.mjs` → diff the printed hash against the README.
 */
import { build } from 'esbuild';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));

const result = await build({
  entryPoints: [join(HERE, 'web', 'web-entry.ts')],
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: 'es2020',
  write: false,
  legalComments: 'none',
  minify: false,
});

const bundleJs = result.outputFiles[0].text;

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>casebandit-verify — offline keyless verifier</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.5 system-ui, sans-serif; margin: 0; padding: 1.5rem; max-width: 56rem; }
  h1 { font-size: 1.25rem; }
  textarea { width: 100%; min-height: 12rem; font-family: ui-monospace, monospace; font-size: 12px; box-sizing: border-box; }
  button { font: inherit; padding: .4rem .9rem; cursor: pointer; margin: .5rem 0; }
  pre { background: rgba(127,127,127,.12); padding: 1rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  .muted { opacity: .75; }
  .v { color: #1a7f37; font-weight: 600; }
  .u { color: #9a6700; font-weight: 600; }
  .f { color: #cf222e; font-weight: 600; }
</style>
</head>
<body>
<h1>casebandit-verify — offline keyless verifier</h1>
<p class="muted">
  Runs entirely offline in your browser (no network). It recomputes the audit-ledger
  chain tip and checks any embedded RFC&nbsp;3161 token <em>contains</em> that tip's
  message imprint (a containment check — NOT a full signature/CA validation).
  <strong>For full RFC&nbsp;3161 signature / CA-chain / genTime validation run the CLI.</strong>
</p>
<p class="muted">Paste the exported JSON ({ rows | auditLedger, tsaTokenBase64 }) below:</p>
<textarea id="in" placeholder='{ "rows": [...], "tsaTokenBase64": "..." }'></textarea>
<button id="go" type="button">Verify (offline)</button>
<pre id="out" aria-live="polite">awaiting input…</pre>

<script>${bundleJs}</script>
<script>
(function () {
  var out = document.getElementById('out');
  var verify = window.casebanditVerify.verifyKeylessWeb;
  function cls(s) { return s === 'attests-tip' ? 'v' : s === 'unstamped' ? 'u' : 'f'; }
  // Build output with textContent only (no innerHTML) so no computed value can
  // ever be interpreted as markup — defensive even though every field is a
  // hex digest / fixed enum / number, never user HTML.
  function render(r) {
    out.textContent = '';
    out.appendChild(document.createTextNode('chain_tip: ' + r.chainTip + '\\nrows: ' + r.rowCount + '\\ntsa_containment: '));
    var span = document.createElement('span');
    span.className = cls(r.tsaContainment);
    span.textContent = r.tsaContainment;
    out.appendChild(span);
    out.appendChild(document.createTextNode('\\n\\n' + r.note));
  }
  document.getElementById('go').addEventListener('click', function () {
    var raw;
    try { raw = JSON.parse(document.getElementById('in').value); }
    catch (e) { out.textContent = 'invalid JSON: ' + e.message; return; }
    var rows = Array.isArray(raw.rows) ? raw.rows : Array.isArray(raw.auditLedger) ? raw.auditLedger : [];
    var token = raw.tsaTokenBase64 == null ? null : raw.tsaTokenBase64;
    verify({ rows: rows, tsaTokenBase64: token }).then(render).catch(function (e) { out.textContent = 'error: ' + e.message; });
  });
})();
</script>
</body>
</html>
`;

const outPath = join(HERE, 'verify.html');
writeFileSync(outPath, html);
const sha = createHash('sha256').update(readFileSync(outPath)).digest('hex');
console.log('built verify.html');
console.log('sha256: ' + sha);
console.log('bytes:  ' + Buffer.byteLength(html));

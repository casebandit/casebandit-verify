#!/usr/bin/env node
/**
 * Verify the vendored-leaf content-hash pins recorded in each vendored file's
 * header against a sibling `casenotes-saas` checkout (if present). Prints a
 * PASS/FAIL table. Exit 1 on any drift. NO network.
 *
 *   node verify-pins.mjs [--app <path-to-casenotes-saas>]
 *
 * Default app path: ../casenotes-saas (sibling of this repo).
 */
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : def;
}
const APP = arg('--app', join(HERE, '..', 'casenotes-saas'));

// vendored file -> { upstream relative path, pin, hasHeaderPin }
// `hasHeaderPin` is false for raw binary assets (the CA bundle) that carry no
// source-comment header — they're checked by the upstream-match pass only.
const PINS = [
  ['src/vendored-frozen/chain-tip.ts', 'apps/web/lib/chain-tip.ts', 'f8108a80ada9728d697914e947dd8a21520f818c9c46610589fe1b5927aacb62', true],
  ['src/vendored-frozen/ledger-sort.ts', 'apps/web/lib/ledger-sort.ts', 'c8c6ac1461df58a659c1e2c71aab6bf685b3de037b1d3ae9988d86a2bef824ba', true],
  ['src/vendored-frozen/tsa-token.ts', 'apps/web/lib/tsa-token.ts', '367a456153e3df437d538ad86919df0e2010368169d42924876e4893dc9794a3', true],
  ['src/vendored-mutable/ledger-hmac.ts', 'apps/web/lib/ledger-hmac.ts', '12927308a76ab729198cb8e670bf8614e5886ea9a6846b639c154717d12f6acd', true],
  ['src/vendored-mutable/canonical-json.ts', 'apps/web/lib/canonical-json.ts', 'a91824d9b62c5f7e7057c0b702e31f599a607d2c2a4576036754e2949387b0ea', true],
  ['ca/sectigo-tsa-ca-bundle.pem', 'tools/ca/sectigo-tsa-ca-bundle.pem', '2e75187bb6ad3d3bb613f96712af23bfe747d0de2014c202c448c54f31f5e6da', false],
];

function sha256File(p) {
  return createHash('sha256').update(readFileSync(p)).digest('hex');
}

// 1) Every vendored SOURCE file's header must literally contain its recorded pin.
let fail = false;
console.log('=== header-pin presence (source leaves) ===');
for (const [vendored, , pin, hasHeaderPin] of PINS) {
  if (!hasHeaderPin) continue;
  const txt = readFileSync(join(HERE, vendored), 'utf8');
  const ok = txt.includes(pin);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${vendored}  header pins ${pin.slice(0, 12)}…`);
  if (!ok) fail = true;
}
// The CA bundle's pin is its own content-hash; verify the committed copy matches.
{
  const [vendored, , pin] = PINS.find(([v]) => v.endsWith('.pem'));
  const live = sha256File(join(HERE, vendored));
  const ok = live === pin;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${vendored}  committed copy sha256 == pin`);
  if (!ok) fail = true;
}

// 2) If a sibling app checkout exists, the pin must equal the live upstream hash.
if (existsSync(APP)) {
  console.log(`\n=== upstream match vs ${APP} ===`);
  for (const [vendored, upstream, pin] of PINS) {
    const live = sha256File(join(APP, upstream));
    const ok = live === pin;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${upstream}  pin=${pin.slice(0, 12)}…  live=${live.slice(0, 12)}…`);
    if (!ok) fail = true;
  }
} else {
  console.log(`\n(no sibling app checkout at ${APP} — skipped live upstream comparison)`);
}

process.exit(fail ? 1 : 0);

// Browser-safe keyless web core (powers verify.html). Node-free: crypto.subtle +
// vendored frozen leaves only. Exercises the same containment logic the offline
// single-file verifier runs from file://.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyKeylessWeb } from '../src/core/web-core.ts';
import type { LedgerRow } from '../src/vendored-frozen/types.ts';

const FX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
function load(name: string): { rows?: LedgerRow[]; tsaTokenBase64?: string | null } {
  return JSON.parse(readFileSync(join(FX, name), 'utf8'));
}

describe('web-core verifyKeylessWeb (offline containment check)', () => {
  it('mixed v1/v2 → attests-tip (token contains this tip imprint)', async () => {
    const o = load('mixed-v1v2.json');
    const r = await verifyKeylessWeb({ rows: o.rows ?? [], tsaTokenBase64: o.tsaTokenBase64 });
    assert.equal(r.tsaContainment, 'attests-tip');
    assert.equal(r.rowCount, 4);
    assert.match(r.note, /run the CLI/);
  });

  it('empty → unstamped, tip 64 zeros', async () => {
    const o = load('empty.json');
    const r = await verifyKeylessWeb({ rows: o.rows ?? [], tsaTokenBase64: o.tsaTokenBase64 });
    assert.equal(r.tsaContainment, 'unstamped');
    assert.equal(r.chainTip, '0'.repeat(64));
  });

  it('tamper → no-attestation (token attests a different tip)', async () => {
    const o = load('tamper.json');
    const r = await verifyKeylessWeb({ rows: o.rows ?? [], tsaTokenBase64: o.tsaTokenBase64 });
    assert.equal(r.tsaContainment, 'no-attestation');
  });
});

// Golden-vector integration tests over the 5 NEW fixtures (plan Phase 3 §4.4):
//   (a) mixed v1/v2 chain        → tsa: verified
//   (b) tamper (flip cipher byte) → tsa: failed
//   (c) truncation (drop last)    → tsa: failed
//   (d) empty chain              → tip 64 zeros, tsa: unstamped
//   (e) MANIFEST hash-mismatch   → manifest: failed (+ ok package passes)
// PLUS Layer-2 keyed chain verify (mixed v1/v2 → verified; unknown spec → failed).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyExport } from '../src/core/tsa-verify.ts';
import { verifyChain } from '../src/core/chain-verify.ts';
import { validateManifest, type ManifestSchema } from '../src/core/manifest.ts';
import type { LedgerRow } from '../src/vendored-frozen/types.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FX = join(HERE, '..', 'fixtures');
const ZERO = '0'.repeat(64);

function loadJson(name: string): { rows?: LedgerRow[]; auditLedger?: LedgerRow[]; tsaTokenBase64?: string | null } {
  return JSON.parse(readFileSync(join(FX, name), 'utf8'));
}
function rowsOf(o: { rows?: LedgerRow[]; auditLedger?: LedgerRow[] }): LedgerRow[] {
  return o.rows ?? o.auditLedger ?? [];
}
const MIXED_CA = join(FX, 'mixed-ca.crt');
const KEY = new Uint8Array(Buffer.from(readFileSync(join(FX, 'fixture-key.hex'), 'utf8').trim(), 'hex'));

describe('Layer-1 keyless TSA verdicts (the 5 new fixtures)', () => {
  it('(a) mixed v1/v2 chain → tsa: verified', async () => {
    const o = loadJson('mixed-v1v2.json');
    const r = await verifyExport({ rows: rowsOf(o), tsaTokenBase64: o.tsaTokenBase64, caFile: MIXED_CA });
    assert.equal(r.tsa, 'verified', r.detail);
    assert.equal(r.rowCount, 4);
    assert.match(r.chainTip, /^[0-9a-f]{64}$/);
  });

  it('(b) tamper (flipped payloadCipher byte) → tsa: failed', async () => {
    const o = loadJson('tamper.json');
    const r = await verifyExport({ rows: rowsOf(o), tsaTokenBase64: o.tsaTokenBase64, caFile: MIXED_CA });
    assert.equal(r.tsa, 'failed', `expected failed, got ${r.tsa} (${r.detail})`);
  });

  it('(c) truncation (dropped last row) → tsa: failed', async () => {
    const o = loadJson('truncation.json');
    const r = await verifyExport({ rows: rowsOf(o), tsaTokenBase64: o.tsaTokenBase64, caFile: MIXED_CA });
    assert.equal(r.tsa, 'failed', `expected failed, got ${r.tsa} (${r.detail})`);
    assert.equal(r.rowCount, 3);
  });

  it('(d) empty chain → tip 64 zeros, tsa: unstamped', async () => {
    const o = loadJson('empty.json');
    const r = await verifyExport({ rows: rowsOf(o), tsaTokenBase64: o.tsaTokenBase64 });
    assert.equal(r.chainTip, ZERO);
    assert.equal(r.rowCount, 0);
    assert.equal(r.tsa, 'unstamped');
  });
});

describe('(e) MANIFEST validation', () => {
  function readPackage(dir: string): Record<string, Uint8Array> {
    const base = join(FX, dir);
    return {
      mimetype: new Uint8Array(readFileSync(join(base, 'mimetype'))),
      'report/a.txt': new Uint8Array(readFileSync(join(base, 'report', 'a.txt'))),
      'report/b.txt': new Uint8Array(readFileSync(join(base, 'report', 'b.txt'))),
    };
  }

  it('ok package → manifest verified (all hashes + package_hash match)', () => {
    const m = JSON.parse(readFileSync(join(FX, 'manifest-ok', 'META-INF', 'MANIFEST.json'), 'utf8')) as ManifestSchema;
    const res = validateManifest(m, readPackage('manifest-ok'));
    assert.equal(res.ok, true);
    assert.equal(res.packageHashOk, true);
    assert.deepEqual(res.mismatched, []);
  });

  it('bad package (one flipped byte) → manifest fails on the mismatched file', () => {
    const m = JSON.parse(readFileSync(join(FX, 'manifest-bad', 'META-INF', 'MANIFEST.json'), 'utf8')) as ManifestSchema;
    const res = validateManifest(m, readPackage('manifest-bad'));
    assert.equal(res.ok, false);
    assert.deepEqual(res.mismatched, ['report/b.txt']);
  });

  it('manifest excludes mimetype + itself from the file list', () => {
    const m = JSON.parse(readFileSync(join(FX, 'manifest-ok', 'META-INF', 'MANIFEST.json'), 'utf8')) as ManifestSchema;
    assert.ok(!('mimetype' in m.files));
    assert.ok(!('META-INF/MANIFEST.json' in m.files));
    assert.equal(m.layout, 'asic-e-style');
    assert.equal(m.tsa_qualified, false);
  });
});

describe('Layer-2 keyed chain verify (--key)', () => {
  const resolveKey = async (): Promise<Uint8Array> => KEY;

  it('mixed v1/v2 chain verifies end-to-end (each row under its OWN spec)', async () => {
    const o = loadJson('mixed-v1v2.json');
    const r = await verifyChain(rowsOf(o), { resolveKey });
    assert.equal(r.status, 'verified', JSON.stringify(r));
    if (r.status === 'verified') assert.equal(r.rowCount, 4);
  });

  it('tampered payloadCipher breaks the v2-row HMAC → failed', async () => {
    const o = loadJson('tamper.json');
    const r = await verifyChain(rowsOf(o), { resolveKey });
    assert.equal(r.status, 'failed');
    if (r.status === 'failed') assert.equal(r.reason, 'HMAC_MISMATCH');
  });

  it('unknown canonicalSpec → failed (hard reject)', async () => {
    const o = loadJson('mixed-v1v2.json');
    const rows = rowsOf(o).map((x) => ({ ...x }));
    rows[0] = { ...rows[0], canonicalSpec: 'jcs-rfc8785-v9' as LedgerRow['canonicalSpec'] };
    const r = await verifyChain(rows, { resolveKey });
    assert.equal(r.status, 'failed');
    if (r.status === 'failed') assert.equal(r.reason, 'CANONICAL_SPEC_UNSUPPORTED');
  });

  it('key unavailable → indeterminate, NOT failed (tri-state preserved)', async () => {
    const o = loadJson('mixed-v1v2.json');
    const r = await verifyChain(rowsOf(o), { resolveKey: async () => null });
    assert.equal(r.status, 'indeterminate');
    if (r.status === 'indeterminate') assert.equal(r.reason, 'KEY_RESOLUTION_FAILED');
  });

  it('empty chain → verified, genesis tip', async () => {
    const r = await verifyChain([], { resolveKey });
    assert.equal(r.status, 'verified');
    if (r.status === 'verified') assert.equal(r.tipHash, ZERO);
  });
});

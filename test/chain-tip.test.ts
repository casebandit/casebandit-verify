// Locks the vendored chain-tip composition against the cross-suite golden vector
// ported from casenotes-saas tests/fixtures/tsa/vector.json. A failure means the
// vendored frozen chain-tip.ts / ledger-sort.ts drifted from app source.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { computeChainTipHash, ZERO_TIP } from '../src/vendored-frozen/chain-tip.ts';
import { canonicalLedgerSort } from '../src/vendored-frozen/ledger-sort.ts';
import type { LedgerRow } from '../src/vendored-frozen/types.ts';

// Minimal row shapes — computeChainTipHash reads only the sort keys + cipher/hmac.
function row(p: Partial<LedgerRow>): LedgerRow {
  return {
    id: 'x',
    caseId: 'c',
    deviceId: '',
    deviceSeq: 0,
    clientTs: 0,
    keyEpoch: 0,
    payloadCipher: '',
    payloadNonce: '',
    routingHmac: '',
    canonicalSpec: 'jcs-rfc8785-v1',
    hashAlgo: 'sha256',
    ephemeral: false,
    ...p,
  };
}

describe('chain-tip composition (cross-suite golden vector)', () => {
  it('empty chain → 64 zero chars (genesis)', async () => {
    assert.equal(ZERO_TIP, '0'.repeat(64));
    assert.equal(await computeChainTipHash([]), '0'.repeat(64));
  });

  it('matches the ported vector.json tip (canonical sort applied)', async () => {
    // Listed UNSORTED (dev-B before dev-A, same clientTs) so a consumer skipping
    // the canonical sort computes the wrong tip.
    const rows = [
      row({ deviceId: 'dev-B', deviceSeq: 1000, clientTs: 1700000000000, payloadCipher: 'cipherB', routingHmac: 'hmacB' }),
      row({ deviceId: 'dev-A', deviceSeq: 1000, clientTs: 1700000000000, payloadCipher: 'cipherA', routingHmac: 'hmacA' }),
    ];
    const tip = await computeChainTipHash(rows);
    assert.equal(tip, '13ded4eaf5d68829e244558c5d491e87a737241bc3e856e07038291dc823ac76');
  });

  it('canonicalLedgerSort orders (clientTs, deviceId, deviceSeq) and does not mutate', () => {
    const input = [
      row({ deviceId: 'dev-B', deviceSeq: 1000, clientTs: 1700000000000 }),
      row({ deviceId: 'dev-A', deviceSeq: 1000, clientTs: 1700000000000 }),
    ];
    const sorted = canonicalLedgerSort(input);
    assert.equal(sorted[0].deviceId, 'dev-A');
    assert.equal(sorted[1].deviceId, 'dev-B');
    assert.equal(input[0].deviceId, 'dev-B'); // input untouched
  });
});

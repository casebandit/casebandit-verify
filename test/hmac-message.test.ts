// Ported golden vectors from casenotes-saas tests/unit/hmac-message.test.ts.
// Locks the v1 message BYTE-IDENTICAL to the routing-tuple message and proves the
// v2 message binds the widened tuple. A failure here means the vendored-mutable
// `ledger-hmac.ts` drifted from app source — bump the pin + these vectors.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize } from '../src/vendored-mutable/canonical-json.ts';
import { buildHmacMessage, type HmacMessageFields } from '../src/vendored-mutable/ledger-hmac.ts';
import { KNOWN_CANONICAL_SPECS } from '../src/vendored-frozen/types.ts';

const FIELDS: HmacMessageFields = {
  caseId: 'case-abc',
  deviceId: 'dev-xyz',
  deviceSeq: 42,
  clientTs: 1_700_000_000_000,
  keyEpoch: 0,
  ephemeral: false,
  payloadCipher: 'Y2lwaGVydGV4dA==',
  payloadNonce: 'bm9uY2U=',
  canonicalSpec: 'jcs-rfc8785-v2',
  hashAlgo: 'sha256',
};

const bytes = (u: Uint8Array): number[] => Array.from(u);

describe('KNOWN_CANONICAL_SPECS', () => {
  it('is exactly [v1, v2]', () => {
    assert.deepEqual([...KNOWN_CANONICAL_SPECS], ['jcs-rfc8785-v1', 'jcs-rfc8785-v2']);
  });
});

describe('buildHmacMessage — v1 golden vector (regression lock)', () => {
  it('v1 message is byte-identical to canonicalize over the routing tuple', () => {
    const msg = buildHmacMessage(FIELDS, 'jcs-rfc8785-v1');
    const golden = canonicalize({
      caseId: FIELDS.caseId,
      deviceId: FIELDS.deviceId,
      deviceSeq: FIELDS.deviceSeq,
      clientTs: FIELDS.clientTs,
    });
    assert.deepEqual(bytes(msg), bytes(golden));
  });

  it('v1 ignores cipher / nonce / epoch / ephemeral (routing-only)', () => {
    const a = buildHmacMessage(FIELDS, 'jcs-rfc8785-v1');
    const b = buildHmacMessage(
      { ...FIELDS, payloadCipher: 'DIFFERENT', payloadNonce: 'XX', keyEpoch: 9, ephemeral: true },
      'jcs-rfc8785-v1',
    );
    assert.deepEqual(bytes(a), bytes(b));
  });

  it('v1 golden byte vector is pinned', () => {
    // The exact UTF-8 bytes of `{"caseId":"case-abc","clientTs":1700000000000,"deviceId":"dev-xyz","deviceSeq":42}`
    const msg = buildHmacMessage(FIELDS, 'jcs-rfc8785-v1');
    assert.equal(
      new TextDecoder().decode(msg),
      '{"caseId":"case-abc","clientTs":1700000000000,"deviceId":"dev-xyz","deviceSeq":42}',
    );
  });
});

describe('buildHmacMessage — v2 binds the full security-relevant tuple', () => {
  const base = buildHmacMessage(FIELDS, 'jcs-rfc8785-v2');

  it('v2 differs from v1 for the same fields', () => {
    assert.notDeepEqual(bytes(base), bytes(buildHmacMessage(FIELDS, 'jcs-rfc8785-v1')));
  });
  it('changing payloadCipher changes the v2 message', () => {
    assert.notDeepEqual(bytes(base), bytes(buildHmacMessage({ ...FIELDS, payloadCipher: 'AAAA' }, 'jcs-rfc8785-v2')));
  });
  it('changing payloadNonce changes the v2 message', () => {
    assert.notDeepEqual(bytes(base), bytes(buildHmacMessage({ ...FIELDS, payloadNonce: 'AAAA' }, 'jcs-rfc8785-v2')));
  });
  it('changing keyEpoch changes the v2 message', () => {
    assert.notDeepEqual(bytes(base), bytes(buildHmacMessage({ ...FIELDS, keyEpoch: 1 }, 'jcs-rfc8785-v2')));
  });
  it('changing ephemeral changes the v2 message', () => {
    assert.notDeepEqual(bytes(base), bytes(buildHmacMessage({ ...FIELDS, ephemeral: true }, 'jcs-rfc8785-v2')));
  });
  it('changing canonicalSpec binds the spec (downgrade-resistance)', () => {
    assert.notDeepEqual(bytes(base), bytes(buildHmacMessage({ ...FIELDS, canonicalSpec: 'jcs-rfc8785-v1' }, 'jcs-rfc8785-v2')));
  });
});

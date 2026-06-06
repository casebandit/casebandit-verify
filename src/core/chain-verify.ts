/**
 * Layer-2 (KEYED, `--key`) — per-row HMAC chain verifier with tri-state outcome.
 *
 * Reproduced faithfully from casenotes-saas `apps/web/lib/verify-chain.ts`
 * (`verifyChain`), repointed onto the vendored-mutable `buildHmacMessage` and the
 * vendored-frozen types. `tweetnacl` is LAZY-LOADED (dynamic import) so the
 * keyless Layer-1 default never pulls it.
 *
 * Tri-state (NEVER collapsed):
 *   verified      — every row's HMAC recomputes + chain composes
 *   indeterminate — key material unavailable for some epoch (cold/offline) — NOT tamper
 *   failed        — real tamper (HMAC mismatch, chain mismatch, unknown spec, epoch gap)
 *
 * Per-row HMAC recompute dispatches on each row's OWN `canonicalSpec` via the
 * shared `buildHmacMessage`, so a MIXED v1/v2 chain verifies end-to-end and an
 * unknown spec is a hard `failed`.
 */
import { createHash, createHmac } from 'node:crypto';
import { buildHmacMessage } from '../vendored-mutable/ledger-hmac.ts';
import { KNOWN_CANONICAL_SPECS, HASH_ALGO, type LedgerRow, type LedgerPayloadKind } from '../vendored-frozen/types.ts';

export type VerifyFailureReason =
  | 'HMAC_MISMATCH'
  | 'CHAIN_HASH_MISMATCH'
  | 'KEY_EPOCH_MISSING'
  | 'CANONICAL_SPEC_UNSUPPORTED'
  | 'HASH_ALGO_UNSUPPORTED'
  | 'SEQ_GAP'
  | 'KEY_RESOLUTION_FAILED';

export type ChainVerifyResult =
  | { status: 'verified'; tipHash: string; rowCount: number; keyEpochsSeen: number[] }
  | { status: 'indeterminate'; brokenAt: number; reason: VerifyFailureReason }
  | { status: 'failed'; brokenAt: number; reason: VerifyFailureReason };

export interface ChainVerifyCtx {
  /** Resolves the raw HMAC/secretbox key bytes for a given (caseId, keyEpoch, ephemeral). */
  resolveKey(caseId: string, keyEpoch: number, ephemeral: boolean): Promise<Uint8Array | null>;
  /** Optional per-row chain anchors for precise `brokenAt` on a payloadCipher swap. */
  expectedChainHashes?: string[];
}

const GENESIS_HASH = '0'.repeat(64);

function fromBase64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

function sha256HexSync(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Stable canonical sort: (clientTs ASC, deviceId ASC, deviceSeq ASC). */
function sortRows(rows: LedgerRow[]): LedgerRow[] {
  return [...rows].sort((a, b) => {
    if (a.clientTs !== b.clientTs) return a.clientTs - b.clientTs;
    if (a.deviceId !== b.deviceId) return a.deviceId < b.deviceId ? -1 : 1;
    return a.deviceSeq - b.deviceSeq;
  });
}

/** Recompute the row HMAC under the row's OWN canonicalSpec via the shared builder. */
function recomputeRowHmac(row: LedgerRow, rawKey: Uint8Array): string {
  const message = buildHmacMessage(
    {
      caseId: row.caseId,
      deviceId: row.deviceId,
      deviceSeq: row.deviceSeq,
      clientTs: row.clientTs,
      keyEpoch: row.keyEpoch,
      ephemeral: row.ephemeral,
      payloadCipher: row.payloadCipher,
      payloadNonce: row.payloadNonce,
      canonicalSpec: row.canonicalSpec,
      hashAlgo: row.hashAlgo,
    },
    row.canonicalSpec,
  );
  return createHmac('sha256', rawKey).update(message).digest('base64');
}

/**
 * Try to decrypt + parse a row's payload to detect `kind: 'key-rotation'`.
 * Failure is NOT fatal (we fall back to (ephemeral, keyEpoch) transitions).
 * Lazy-loads tweetnacl so the keyless path never pulls it.
 */
async function tryReadPayloadKind(row: LedgerRow, key: Uint8Array): Promise<LedgerPayloadKind | null> {
  try {
    const { default: nacl } = await import('tweetnacl');
    const cipher = fromBase64(row.payloadCipher);
    const nonce = fromBase64(row.payloadNonce);
    if (nonce.length !== nacl.secretbox.nonceLength) return null;
    const plain = nacl.secretbox.open(cipher, nonce, key);
    if (!plain) return null;
    const text = new TextDecoder().decode(plain);
    const parsed = JSON.parse(text) as { kind?: unknown };
    return typeof parsed.kind === 'string' ? (parsed.kind as LedgerPayloadKind) : null;
  } catch {
    return null;
  }
}

/** Verify a ledger chain end-to-end. See module docstring for the contract. */
export async function verifyChain(rows: LedgerRow[], ctx: ChainVerifyCtx): Promise<ChainVerifyResult> {
  if (rows.length === 0) {
    return { status: 'verified', tipHash: GENESIS_HASH, rowCount: 0, keyEpochsSeen: [] };
  }

  const sorted = sortRows(rows);
  const rawKeyCache = new Map<string, Uint8Array>();
  const rawKeys: Uint8Array[] = new Array(sorted.length);

  for (let i = 0; i < sorted.length; i++) {
    const row = sorted[i];
    if (!KNOWN_CANONICAL_SPECS.includes(row.canonicalSpec)) {
      return { status: 'failed', brokenAt: row.deviceSeq, reason: 'CANONICAL_SPEC_UNSUPPORTED' };
    }
    if (row.hashAlgo !== HASH_ALGO) {
      return { status: 'failed', brokenAt: row.deviceSeq, reason: 'HASH_ALGO_UNSUPPORTED' };
    }
    const cacheKey = `${row.keyEpoch}|${row.ephemeral ? 1 : 0}|${row.caseId}`;
    let rawKey = rawKeyCache.get(cacheKey);
    if (!rawKey) {
      const resolved = await ctx.resolveKey(row.caseId, row.keyEpoch, row.ephemeral);
      if (resolved == null) {
        // INDETERMINATE, NOT failed: the key for this epoch is unavailable.
        return { status: 'indeterminate', brokenAt: row.deviceSeq, reason: 'KEY_RESOLUTION_FAILED' };
      }
      rawKey = resolved;
      rawKeyCache.set(cacheKey, rawKey);
    }
    rawKeys[i] = rawKey;
  }

  // Per-row independent HMAC recompute.
  const expectedHmacs: string[] = new Array(sorted.length);
  for (let i = 0; i < sorted.length; i++) {
    expectedHmacs[i] = recomputeRowHmac(sorted[i], rawKeys[i]);
  }

  // Walk serially: HMAC check + chain hash + (optional) anchor + epoch transitions.
  const keyEpochsSeen = new Set<number>();
  const deviceEpoch = new Map<string, number>();
  const devicePrev = new Map<string, { row: LedgerRow; rawKey: Uint8Array }>();
  let chainHash = GENESIS_HASH;
  const encoder = new TextEncoder();

  for (let i = 0; i < sorted.length; i++) {
    const row = sorted[i];
    const dev = row.deviceId;

    if (!deviceEpoch.has(dev)) {
      deviceEpoch.set(dev, row.keyEpoch);
    } else {
      const curEpoch = deviceEpoch.get(dev)!;
      if (row.keyEpoch !== curEpoch) {
        if (row.keyEpoch !== curEpoch + 1) {
          return { status: 'failed', brokenAt: row.deviceSeq, reason: 'KEY_EPOCH_MISSING' };
        }
        const prev = devicePrev.get(dev);
        if (!prev) {
          return { status: 'failed', brokenAt: row.deviceSeq, reason: 'KEY_EPOCH_MISSING' };
        }
        const prevKind = await tryReadPayloadKind(prev.row, prev.rawKey);
        if (prevKind !== 'key-rotation') {
          return { status: 'failed', brokenAt: row.deviceSeq, reason: 'KEY_EPOCH_MISSING' };
        }
        deviceEpoch.set(dev, row.keyEpoch);
      }
    }
    keyEpochsSeen.add(row.keyEpoch);

    if (expectedHmacs[i] !== row.routingHmac) {
      return { status: 'failed', brokenAt: row.deviceSeq, reason: 'HMAC_MISMATCH' };
    }

    const composed = encoder.encode(chainHash + '|' + row.payloadCipher + '|' + row.routingHmac);
    chainHash = sha256HexSync(composed);

    if (ctx.expectedChainHashes != null) {
      const anchor = ctx.expectedChainHashes[i];
      if (anchor != null && anchor !== chainHash) {
        return { status: 'failed', brokenAt: row.deviceSeq, reason: 'CHAIN_HASH_MISMATCH' };
      }
    }

    devicePrev.set(dev, { row, rawKey: rawKeys[i] });
  }

  return {
    status: 'verified',
    tipHash: chainHash,
    rowCount: sorted.length,
    keyEpochsSeen: Array.from(keyEpochsSeen).sort((a, b) => a - b),
  };
}

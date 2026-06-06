/**
 * ============================================================================
 * MUTABLE LEAF — DO NOT EDIT BY HAND.
 *
 * Pinned to casenotes-saas `apps/web/lib/ledger-hmac.ts` @ content-hash (sha256):
 *   12927308a76ab729198cb8e670bf8614e5886ea9a6846b639c154717d12f6acd
 *
 * `buildHmacMessage` is the ONE genuinely-mutable forensic leaf — it CHANGED
 * v1 -> v2 (the v2 message widened to bind payloadCipher + nonce + mode tuple),
 * and a future spec bump (v3) WILL change it again. It is therefore NOT a frozen
 * vendor: a spec bump REQUIRES bumping this pin + the golden vectors in
 * test/hmac-message.test.ts. The golden-vector CI catch is what makes that bump
 * LOUD (a verbatim-byte mismatch fails the suite) instead of a silent court-facing
 * drift on the keyed Layer-2 path.
 *
 * INTERIM BOUNDARY: the plan's intent is a VERSIONED PUBLISHED dependency
 * (`@casebandit/ledger-hmac`). The app is not yet published to npm, so the
 * versioned-dep intent is satisfied here by (1) this explicit pinned-hash
 * boundary + (2) the golden-vector regression catch. Replace this file with the
 * published package once the app publishes it.
 *
 * Layer-1 (keyless, the default) NEVER calls this — only Layer-2 (`--key`) does,
 * so the keyless default path stays vendored + dependency-minimal.
 * ============================================================================
 */
import { canonicalize } from './canonical-json.ts';
import { HASH_ALGO, type CanonicalSpec } from '../vendored-frozen/types.ts';

export interface RoutingTuple {
  caseId: string;
  deviceId: string;
  deviceSeq: number;
  clientTs: number;
}

/**
 * Every field a row HMAC message may bind, across all canonical specs. The v1
 * message reads only the four routing fields; the v2 message reads all ten.
 */
export interface HmacMessageFields extends RoutingTuple {
  keyEpoch: number;
  ephemeral: boolean;
  payloadCipher: string;
  payloadNonce: string;
  canonicalSpec: CanonicalSpec;
  hashAlgo: typeof HASH_ALGO;
}

/**
 * Build the JCS-canonical HMAC message for a row under `spec`. PURE + SYNC.
 *  - jcs-rfc8785-v1 — routing-tuple-only message (BYTE-IDENTICAL to the pre-v2
 *    message so every legitimate v1 row in prod keeps verifying).
 *  - jcs-rfc8785-v2 — widened message that ALSO binds payloadCipher + payloadNonce
 *    + keyEpoch + ephemeral + canonicalSpec + hashAlgo (per-row, anchor-free
 *    ciphertext authentication).
 */
export function buildHmacMessage(f: HmacMessageFields, spec: CanonicalSpec): Uint8Array {
  if (spec === 'jcs-rfc8785-v1') {
    return canonicalize({
      caseId: f.caseId,
      deviceId: f.deviceId,
      deviceSeq: f.deviceSeq,
      clientTs: f.clientTs,
    });
  }
  // jcs-rfc8785-v2 (widened). JCS sorts keys, so insertion order here is cosmetic.
  return canonicalize({
    caseId: f.caseId,
    deviceId: f.deviceId,
    deviceSeq: f.deviceSeq,
    clientTs: f.clientTs,
    keyEpoch: f.keyEpoch,
    ephemeral: f.ephemeral,
    payloadCipher: f.payloadCipher,
    payloadNonce: f.payloadNonce,
    canonicalSpec: f.canonicalSpec,
    hashAlgo: f.hashAlgo,
  });
}

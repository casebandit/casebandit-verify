/**
 * Minimal vendored ledger types — the SUBSET of casenotes-saas `shared/types.ts`
 * the verifier needs. Copied faithfully; the fields are an append-only on-the-wire
 * contract and never change shape (only the canonical-spec value set grows).
 *
 * Pinned to casenotes-saas shared/types.ts (LedgerRow, KNOWN_CANONICAL_SPECS,
 * CanonicalSpec, HASH_ALGO, LedgerPayload kinds) — see README "Vendored-leaf pins".
 * These are data types, not algorithm; they are safe to vendor.
 */

/**
 * Append-only set of known canonical specs. Old specs are NEVER removed (prod
 * rows under them must keep verifying forever). An unknown spec is a hard fail.
 *  - jcs-rfc8785-v1: routing-tuple-only HMAC message.
 *  - jcs-rfc8785-v2: widened HMAC message (binds payloadCipher + nonce + mode tuple).
 */
export const KNOWN_CANONICAL_SPECS = ['jcs-rfc8785-v1', 'jcs-rfc8785-v2'] as const;
export type CanonicalSpec = (typeof KNOWN_CANONICAL_SPECS)[number];

/** Hash algorithm pin for the derived chain hash. */
export const HASH_ALGO = 'sha256' as const;

/** Payload kinds (string-only subset; the verifier only reads `kind`). */
export type LedgerPayloadKind =
  | 'entity-create'
  | 'entity-status-change'
  | 'entity-important-toggle'
  | 'relationship-create'
  | 'relationship-update'
  | 'relationship-delete'
  | 'capture-add'
  | 'capture-grade-change'
  | 'case-open'
  | 'case-export'
  | 'verify-chain'
  | 'note'
  | 'key-rotation'
  | 'map-feature-add';

/**
 * One append-only forensic row. The chain hash is DERIVED (not stored).
 * The verifier reads exactly these fields; extra fields on the wire are ignored.
 */
export interface LedgerRow {
  id: string;
  caseId: string;
  deviceId: string;
  deviceSeq: number;
  clientTs: number;
  keyEpoch: number;
  payloadCipher: string; // base64 NaCl secretbox of JCS(payload)
  payloadNonce: string; // base64 24-byte nonce
  routingHmac: string; // v1: HMAC over routing tuple; v2: HMAC over the widened tuple
  canonicalSpec: CanonicalSpec; // v1|v2 — verifier recomputes the message per this value
  hashAlgo: typeof HASH_ALGO;
  ephemeral: boolean;
  userId?: string;
}

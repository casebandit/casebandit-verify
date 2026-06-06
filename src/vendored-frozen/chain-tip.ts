/**
 * ============================================================================
 * VENDORED FROZEN LEAF — DO NOT EDIT BY HAND.
 *
 * Verbatim copy of casenotes-saas `apps/web/lib/chain-tip.ts`.
 * Pinned to source content-hash (sha256):
 *   f8108a80ada9728d697914e947dd8a21520f818c9c46610589fe1b5927aacb62
 * (the upstream file imports `../../../shared/types.ts` + `./ledger-sort.ts`;
 *  here those are re-pointed to the vendored siblings — the ONLY change.)
 *
 * This leaf is SAFE to vendor: the chain composition
 *   H_i = SHA256(H_{i-1} + '|' + payloadCipher + '|' + routingHmac)
 * is CONTRACTUALLY FROZEN (CLAUDE.md — UNCHANGED across v1→v2 and F3). The
 * golden vectors catch any accidental drift against app source.
 * ============================================================================
 *
 * Chain-tip composition — byte-identical to the in-app verifier and the backend
 * recompute:
 *   - canonical sort `(clientTs ASC, deviceId ASC bytewise, deviceSeq ASC)`
 *   - H_i = SHA256(H_{i-1} + '|' + row.payloadCipher + '|' + row.routingHmac)
 *   - genesis = 64 zero chars; empty chain → genesis.
 *
 * Uses the `crypto.subtle` global (Node >= 20 + every browser) so the SAME file
 * powers the CLI (node) and the offline `verify.html` (browser).
 */
import type { LedgerRow } from './types.ts';
import { canonicalLedgerSort } from './ledger-sort.ts';

export const ZERO_TIP = '0'.repeat(64);

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i].toString(16);
    out += b.length === 1 ? '0' + b : b;
  }
  return out;
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return toHex(new Uint8Array(digest));
}

export async function computeChainTipHash(rows: LedgerRow[]): Promise<string> {
  if (rows.length === 0) return ZERO_TIP;
  const sorted = canonicalLedgerSort(rows);
  let prev = ZERO_TIP;
  for (const row of sorted) {
    prev = await sha256Hex(prev + '|' + row.payloadCipher + '|' + row.routingHmac);
  }
  return prev;
}

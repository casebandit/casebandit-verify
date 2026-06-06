/**
 * ============================================================================
 * VENDORED FROZEN LEAF — DO NOT EDIT BY HAND.
 *
 * Verbatim copy of casenotes-saas `apps/web/lib/ledger-sort.ts`.
 * Pinned to source content-hash (sha256):
 *   c8c6ac1461df58a659c1e2c71aab6bf685b3de037b1d3ae9988d86a2bef824ba
 * (the upstream file carries an import of `../../../shared/types.ts`; here the
 *  `LedgerRow` type is re-pointed to the vendored types — the ONLY change.)
 *
 * This leaf is SAFE to vendor: canonical ledger ordering is contractually frozen
 * (CLAUDE.md — the chain composition + sort never changed across v1→v2 / F3).
 * The golden vectors catch any accidental drift.
 * ============================================================================
 *
 * Canonical ledger order — `(clientTs ASC, deviceId ASC, deviceSeq ASC)`. The
 * SINGLE source of truth for ledger read ordering: the export chain tip, the
 * readable event log, the cipher appendix, `buildReportSource`, AND the
 * interactive Notes / Collection-Log views all sort through this so a
 * multi-author (team) chain renders in the exact order the verifier walks.
 * Returns a NEW array — never mutates the input.
 */
import type { LedgerRow } from './types.ts';

export function canonicalLedgerSort(rows: LedgerRow[]): LedgerRow[] {
  return [...rows].sort(
    (a, b) =>
      a.clientTs - b.clientTs ||
      (a.deviceId < b.deviceId ? -1 : a.deviceId > b.deviceId ? 1 : 0) ||
      a.deviceSeq - b.deviceSeq,
  );
}

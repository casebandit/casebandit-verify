/**
 * Browser-safe KEYLESS core for the offline `verify.html`. Node-free: uses only
 * `crypto.subtle` + the vendored frozen leaves (chain-tip + tokenAttestsTip).
 * NO openssl, NO node:crypto, NO tweetnacl — so esbuild can bundle it into a
 * single self-contained IIFE that opens from `file://` under CSP default-src 'none'.
 *
 * It does the two checks a keyless examiner can run with zero external tools:
 *   1. recompute the chain tip from the rows;
 *   2. `tokenAttestsTip` containment — the token DER contains the OCTET STRING
 *      `04 20 || SHA256(rawTip)`, i.e. it timestamps THIS tip.
 * It deliberately does NOT validate the RFC 3161 signature / CA chain / genTime —
 * that needs openssl, so it prints the honesty boundary and points at the CLI.
 */
import { computeChainTipHash } from '../vendored-frozen/chain-tip.ts';
import { tokenAttestsTip } from '../vendored-frozen/tsa-token.ts';
import type { LedgerRow } from '../vendored-frozen/types.ts';

export interface WebVerifyInput {
  rows: LedgerRow[];
  tsaTokenBase64?: string | null;
}

export interface WebVerifyOutput {
  chainTip: string;
  rowCount: number;
  /**
   * Keyless web tri-state for the TSA, honest about its ceiling:
   *   attests-tip   — token contains this tip's messageImprint (containment ok)
   *   unstamped     — no token present
   *   no-attestation — a token is present but does NOT attest this tip (mismatch)
   * NOTE: 'attests-tip' is NOT a full signature/CA verdict; run the CLI for that.
   */
  tsaContainment: 'attests-tip' | 'unstamped' | 'no-attestation';
  note: string;
}

const CLI_NOTE =
  'For full RFC 3161 signature / CA-chain / genTime validation run the CLI: ' +
  'node verify.js --in <export.json> --token <token.tsr> --ca <ca.pem>';

export async function verifyKeylessWeb(input: WebVerifyInput): Promise<WebVerifyOutput> {
  const chainTip = await computeChainTipHash(input.rows);
  const rowCount = input.rows.length;

  if (!input.tsaTokenBase64) {
    return { chainTip, rowCount, tsaContainment: 'unstamped', note: CLI_NOTE };
  }
  const attests = await tokenAttestsTip(input.tsaTokenBase64, chainTip);
  return {
    chainTip,
    rowCount,
    tsaContainment: attests ? 'attests-tip' : 'no-attestation',
    note: CLI_NOTE,
  };
}

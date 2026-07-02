/**
 * Layer-1 (KEYLESS) — chain-tip recompute + RFC 3161 TSA verification.
 *
 * Reproduced faithfully from casenotes-saas `tools/casebandit-verify.ts`
 * (`verifyExport` + `verifyAsOfGenTime` + `parseGenTimeEpoch`), repointed off the
 * app cross-import onto the vendored frozen `chain-tip.ts`. KEY-FREE: the chain
 * hash binds payloadCipher + routingHmac, no decryption needed.
 *
 *   tsa: verified   — token cryptographically attests the recomputed tip
 *   tsa: unstamped  — no token in the export (NOT a failure; unanchored)
 *   tsa: failed     — token does not attest the recomputed tip (tamper/mismatch)
 *
 * Requires Node >= 20 (`crypto.subtle` global) and `openssl` on PATH.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeChainTipHash } from '../vendored-frozen/chain-tip.ts';
import type { LedgerRow } from '../vendored-frozen/types.ts';

export type TsaVerdict = 'verified' | 'unstamped' | 'failed';

export interface TsaVerifyInput {
  rows: LedgerRow[];
  tsaTokenBase64?: string | null;
  /** PEM CA bundle for the TSA chain. Defaults to ../../ca/sectigo-tsa-ca-bundle.pem. */
  caFile?: string;
}

export interface TsaVerifyOutput {
  chainTip: string;
  rowCount: number;
  tsa: TsaVerdict;
  detail?: string;
}

const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_CA = join(HERE, '..', '..', 'ca', 'sectigo-tsa-ca-bundle.pem');

/** True on Node >= 20 (crypto.subtle global). */
export function nodeSupportsSubtleGlobal(version: string = process.version): boolean {
  const major = parseInt(version.replace(/^v/, '').split('.')[0], 10);
  return Number.isFinite(major) && major >= 20;
}

function stderrOf(err: unknown): string {
  return err instanceof Error
    ? (err as Error & { stderr?: Buffer }).stderr?.toString().trim() || err.message
    : String(err);
}

/** DER OID of id-sha256 (2.16.840.1.101.3.4.2.1), hex-encoded contents (sans tag/len). */
const SHA256_OID_HEX = '608648016503040201';

interface DerTlv {
  tag: number;
  /** Offset of the first content byte. */
  contentStart: number;
  /** Offset one past the last content byte. */
  end: number;
}

/**
 * Minimal DER TLV reader (definite-length only — sufficient for a TSTInfo, which
 * is fully DER). Deliberately NOT a general ASN.1 parser: the repo keeps deps
 * minimal (only tweetnacl) so a heavy parser is out of scope. Throws on any
 * malformed/indefinite length so callers can fail closed.
 */
function readTlv(buf: Buffer, offset: number): DerTlv {
  if (offset + 2 > buf.length) throw new Error('truncated DER');
  const tag = buf[offset];
  let i = offset + 1;
  let length = buf[i++];
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n === 0 || n > 4) throw new Error('unsupported DER length');
    if (i + n > buf.length) throw new Error('truncated DER length');
    // Use multiplication, not `<< 8`: a 4-byte length with the high bit set (e.g.
    // 0x84 80 00 00 00) would overflow the signed int32 `<<` into a NEGATIVE
    // length, making `end = i + length` land below `i` and pass the overrun check
    // with an empty/backwards range. Multiplication keeps it a positive JS number
    // (max 0xFFFFFFFF, well under 2^53); the overrun guard below then rejects it.
    length = 0;
    for (let k = 0; k < n; k++) length = length * 0x100 + buf[i++];
  }
  const end = i + length;
  if (end > buf.length) throw new Error('DER content overruns buffer');
  return { tag, contentStart: i, end };
}

/**
 * Extract the TSTInfo.messageImprint by WALKING the ASN.1 STRUCTURE — not by
 * scanning the blob for the hash bytes anywhere. Raw byte-containment is unsafe:
 * the imprint bytes could coincidentally appear elsewhere in the token (e.g.
 * inside a certificate serial or the signature), producing a false attest.
 *
 *   TSTInfo ::= SEQUENCE {
 *     version        INTEGER,
 *     policy         OBJECT IDENTIFIER,
 *     messageImprint MessageImprint,   -- the field we want
 *     ... }
 *   MessageImprint ::= SEQUENCE {
 *     hashAlgorithm  AlgorithmIdentifier,   -- SEQUENCE { OID, ... }
 *     hashedMessage  OCTET STRING }
 *
 * Returns the declared hash algorithm OID (hex) + the hashedMessage OCTET STRING
 * contents, or null if the structure does not match (→ caller fails closed).
 */
function extractMessageImprint(tstInfoDer: Buffer): { algOidHex: string; hashedMessage: Buffer } | null {
  try {
    const seq = readTlv(tstInfoDer, 0);
    if (seq.tag !== 0x30) return null; // TSTInfo SEQUENCE
    let off = seq.contentStart;

    const version = readTlv(tstInfoDer, off); // version INTEGER
    if (version.tag !== 0x02) return null;
    off = version.end;

    const policy = readTlv(tstInfoDer, off); // policy OID
    if (policy.tag !== 0x06) return null;
    off = policy.end;

    const imprint = readTlv(tstInfoDer, off); // messageImprint SEQUENCE
    if (imprint.tag !== 0x30) return null;

    const algId = readTlv(tstInfoDer, imprint.contentStart); // hashAlgorithm SEQUENCE
    if (algId.tag !== 0x30) return null;
    const algOid = readTlv(tstInfoDer, algId.contentStart); // algorithm OID
    if (algOid.tag !== 0x06) return null;

    const hashed = readTlv(tstInfoDer, algId.end); // hashedMessage OCTET STRING
    if (hashed.tag !== 0x04) return null;
    if (hashed.end > imprint.end) return null; // must sit INSIDE messageImprint

    return {
      algOidHex: tstInfoDer.subarray(algOid.contentStart, algOid.end).toString('hex'),
      hashedMessage: tstInfoDer.subarray(hashed.contentStart, hashed.end),
    };
  } catch {
    return null;
  }
}

/**
 * Parse the TSTInfo `genTime` (ASN.1 GeneralizedTime) → epoch seconds, via
 * examiner-trusted `openssl asn1parse`.
 */
function parseGenTimeEpoch(tstInfoPath: string): number | null {
  let out: string;
  try {
    out = execFileSync('openssl', ['asn1parse', '-inform', 'DER', '-in', tstInfoPath], { stdio: 'pipe' }).toString();
  } catch {
    return null;
  }
  const m = out.match(/GENERALIZEDTIME\s*:(\d{14})(?:\.\d+)?Z/);
  if (!m) return null;
  const s = m[1];
  const iso = `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? Math.floor(t / 1000) : null;
}

/**
 * As-of-genTime fallback (F3.2). Three independent gates, all openssl-only:
 *   1. signature is cryptographically valid (`cms -verify -noverify`);
 *   2. the token's messageImprint attests the LOCAL recomputed tip (the
 *      messageImprint field is extracted via ASN.1 and compared exactly — its
 *      hashAlgorithm must be sha256 and its hashedMessage must equal
 *      SHA256(rawTip));
 *   3. the signer cert chains to the bundled CA, carries the RFC 3161
 *      id-kp-timeStamping EKU (`-purpose timestampsign`), and is valid AS OF
 *      genTime.
 * Only all three together upgrade the verdict to `verified` — fail-closed.
 */
function verifyAsOfGenTime(tokenPath: string, caFile: string, rawTip: Buffer, dir: string): { ok: boolean; detail: string } {
  const tstInfoPath = join(dir, 'tstinfo.der');
  try {
    execFileSync('openssl', ['cms', '-verify', '-noverify', '-inform', 'DER', '-in', tokenPath, '-out', tstInfoPath], { stdio: 'pipe' });
  } catch (err) {
    return { ok: false, detail: `token signature did not verify: ${stderrOf(err)}` };
  }
  const imprint = createHash('sha256').update(rawTip).digest();
  const mi = extractMessageImprint(readFileSync(tstInfoPath));
  if (mi === null) {
    return { ok: false, detail: 'could not parse messageImprint from token TSTInfo' };
  }
  // Compare the EXTRACTED messageImprint field exactly (algorithm OID + hash),
  // not a byte-containment scan of the whole token.
  if (mi.algOidHex !== SHA256_OID_HEX || !mi.hashedMessage.equals(imprint)) {
    return { ok: false, detail: 'token messageImprint does not attest the recomputed tip' };
  }
  const epoch = parseGenTimeEpoch(tstInfoPath);
  if (epoch === null) {
    return { ok: false, detail: 'could not parse genTime from token' };
  }
  const genIso = new Date(epoch * 1000).toISOString();
  try {
    execFileSync(
      'openssl',
      // `-purpose timestampsign` enforces the id-kp-timeStamping EKU during chain
      // building, so a non-TSA cert that merely chains to the bundled CA cannot be
      // accepted as a timestamp signer (Tier-1 `ts -verify` enforces this already;
      // the Tier-2 fallback MUST NOT silently drop it via `-purpose any`).
      ['cms', '-verify', '-inform', 'DER', '-in', tokenPath, '-CAfile', caFile, '-purpose', 'timestampsign', '-attime', String(epoch), '-out', join(dir, 'attime-out.der')],
      { stdio: 'pipe' },
    );
  } catch (err) {
    return { ok: false, detail: `chain did not verify as of genTime ${genIso}: ${stderrOf(err)}` };
  }
  return { ok: true, detail: `verified as of genTime ${genIso} (signer cert not valid at the current clock — likely expired since issuance)` };
}

/**
 * Recompute the keyless chain tip and verify any embedded TSA token against it.
 */
export async function verifyExport(input: TsaVerifyInput): Promise<TsaVerifyOutput> {
  const chainTip = await computeChainTipHash(input.rows);
  const rowCount = input.rows.length;

  if (!input.tsaTokenBase64) {
    return { chainTip, rowCount, tsa: 'unstamped' };
  }

  const caFile = input.caFile ?? DEFAULT_CA;
  const dir = mkdtempSync(join(tmpdir(), 'cb-verify-'));
  try {
    const tokenPath = join(dir, 'token.der');
    const dataPath = join(dir, 'tip.bin');
    const rawTip = Buffer.from(chainTip, 'hex');
    writeFileSync(tokenPath, Buffer.from(input.tsaTokenBase64, 'base64'));
    writeFileSync(dataPath, rawTip);
    try {
      // Tier 1: current-clock RFC 3161 verify (the fast common path).
      execFileSync(
        'openssl',
        ['ts', '-verify', '-in', tokenPath, '-token_in', '-data', dataPath, '-CAfile', caFile],
        { stdio: 'pipe' },
      );
      return { chainTip, rowCount, tsa: 'verified' };
    } catch (tier1Err) {
      // Tier 2: re-verify as of the token's own genTime (signer cert may have
      // since expired but the timestamp remains valid evidence as of issuance).
      const r = verifyAsOfGenTime(tokenPath, caFile, rawTip, dir);
      return r.ok
        ? { chainTip, rowCount, tsa: 'verified', detail: r.detail }
        : { chainTip, rowCount, tsa: 'failed', detail: `${stderrOf(tier1Err)}; ${r.detail}` };
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

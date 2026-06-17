#!/usr/bin/env node
/**
 * casebandit-verify — standalone offline forensic verifier (public repo).
 *
 * TWO LAYERS, both tri-states kept SEPARATE in the output JSON:
 *
 *   Layer 1 (DEFAULT, KEYLESS) — reveals zero case content:
 *     • recompute the audit-ledger chain tip (binds payloadCipher + routingHmac);
 *     • RFC 3161 TSA verify the embedded/--token token attests that exact tip
 *       (openssl ts -verify, with an as-of-genTime fallback for expired signers);
 *     • optional MANIFEST file-hash + package-hash check (--manifest).
 *     →  tsa: verified | unstamped | failed
 *
 *   Layer 2 (`--key <keyfile>`, OPT-IN) — decrypts only for the key-holder:
 *     • per-row HMAC recompute under each row's OWN canonicalSpec (mixed v1/v2
 *       verifies; unknown spec → failed); secretbox key-rotation detection.
 *     →  chain: verified | indeterminate | failed
 *
 * Input (`--in <export.json>`): either the legacy `{ rows, tsaTokenBase64 }`
 * shape OR the app's JsonExportData (`{ auditLedger, tsaTokenBase64, chainTipHash }`).
 * `--token <file>` overrides the embedded token (raw DER or base64). `--ca <pem>`
 * overrides the bundled Sectigo CA. NO NETWORK — everything runs local + offline.
 *
 * Requires Node >= 20 (crypto.subtle global) and `openssl` on PATH for Layer-1
 * RFC 3161 validation. The keyless web verifier (verify.html) needs neither.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve, join, relative } from 'node:path';
import { verifyExport, nodeSupportsSubtleGlobal, type TsaVerdict } from './src/core/tsa-verify.ts';
import { verifyChain, type ChainVerifyResult } from './src/core/chain-verify.ts';
import { validateManifest, type ManifestSchema, type ManifestValidationResult, MANIFEST_PATH } from './src/core/manifest.ts';
import type { LedgerRow } from './src/vendored-frozen/types.ts';

interface CliArgs {
  in?: string;
  token?: string;
  ca?: string;
  key?: string;
  manifest?: string;
  packageDir?: string;
  json?: boolean;
}

interface RawInput {
  rows?: LedgerRow[];
  auditLedger?: LedgerRow[];
  tsaTokenBase64?: string | null;
  chainTipHash?: string;
}

function parseArgs(argv: string[]): CliArgs {
  const out: CliArgs = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--in') out.in = argv[++i];
    else if (a === '--token') out.token = argv[++i];
    else if (a === '--ca') out.ca = argv[++i];
    else if (a === '--key') out.key = argv[++i];
    else if (a === '--manifest') out.manifest = argv[++i];
    else if (a === '--package-dir') out.packageDir = argv[++i];
    else if (a === '--json') out.json = true;
    else if (a === '--no-network') {
      /* documented no-op: the verifier makes ZERO network calls by construction. */
    }
  }
  return out;
}

/**
 * Exit codes (kept DISTINCT so a caller scripting on $? can tell them apart):
 *   0 — clean (no positive tamper signal)
 *   1 — TAMPER detected (tsa/chain/manifest failed, or declared tip mismatch)
 *   2 — operational / input error (bad usage, unreadable or malformed evidence)
 * A forensic tool MUST fail-closed: malformed input is exit 2, never a silent
 * pass and never collapsed into the exit-1 tamper signal.
 */
const EXIT_TAMPER = 1;
const EXIT_ERROR = 2;

/** Operational/input error → clear message + exit 2 (never a raw stack trace). */
function fail(msg: string): never {
  console.error(`casebandit-verify: ${msg}`);
  process.exit(EXIT_ERROR);
}

/** Read + parse a JSON file, failing closed with a clear message on any error. */
function readJsonFile(path: string, label: string): unknown {
  let text: string;
  try {
    text = readFileSync(resolve(path), 'utf8');
  } catch (err) {
    return fail(`cannot read ${label} '${path}': ${(err as Error).message}`);
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    return fail(`${label} '${path}' is not valid JSON: ${(err as Error).message}`);
  }
}

const ROW_STRING_FIELDS = [
  'caseId',
  'deviceId',
  'payloadCipher',
  'payloadNonce',
  'routingHmac',
  'canonicalSpec',
  'hashAlgo',
] as const;
const ROW_NUMBER_FIELDS = ['deviceSeq', 'clientTs', 'keyEpoch'] as const;

/**
 * Fail-closed structural validation of the untrusted ledger BEFORE any hashing or
 * sorting. Without it a string `clientTs`/`deviceSeq` yields NaN comparisons and a
 * nondeterministic canonical sort (→ unstable, divergent chain tip), and a missing
 * field surfaces as an opaque downstream crash instead of a clear verdict.
 */
function assertLedgerRows(rows: unknown): asserts rows is LedgerRow[] {
  if (!Array.isArray(rows)) fail('ledger is not an array');
  rows.forEach((row, i) => {
    if (row === null || typeof row !== 'object') fail(`ledger row ${i} is not an object`);
    const r = row as Record<string, unknown>;
    for (const f of ROW_STRING_FIELDS) {
      if (typeof r[f] !== 'string') fail(`ledger row ${i}: field '${f}' must be a string (got ${typeof r[f]})`);
    }
    for (const f of ROW_NUMBER_FIELDS) {
      if (typeof r[f] !== 'number' || !Number.isFinite(r[f])) {
        fail(`ledger row ${i}: field '${f}' must be a finite number (got ${typeof r[f]})`);
      }
    }
    if (typeof r.ephemeral !== 'boolean') fail(`ledger row ${i}: field 'ephemeral' must be a boolean (got ${typeof r.ephemeral})`);
  });
}

/**
 * Accept either `{ rows }` (legacy) or `{ auditLedger }` (JsonExportData). A
 * present-but-empty array is allowed (an empty chain is legitimately unanchored).
 * An export with NEITHER field is malformed/stripped evidence → fail-closed (a
 * missing ledger must never read as a clean pass).
 */
function extractRows(parsed: RawInput): LedgerRow[] {
  const hasRows = Object.prototype.hasOwnProperty.call(parsed, 'rows');
  const hasLedger = Object.prototype.hasOwnProperty.call(parsed, 'auditLedger');
  if (hasRows && Array.isArray(parsed.rows)) return parsed.rows;
  if (hasLedger && Array.isArray(parsed.auditLedger)) return parsed.auditLedger;
  if (hasRows || hasLedger) fail("export has a 'rows'/'auditLedger' field that is not an array");
  return fail("export has no 'rows' or 'auditLedger' ledger array — cannot verify (malformed or stripped evidence)");
}

/** Read a token file as base64 (raw DER → base64; an already-base64 file passes through). */
function readTokenBase64(path: string): string {
  const buf = readFileSync(resolve(path));
  // Heuristic: a DER token starts with 0x30 (SEQUENCE). A base64 text file does not.
  if (buf.length > 0 && buf[0] === 0x30) return buf.toString('base64');
  return buf.toString('utf8').trim();
}

/** Read a raw key file (binary 32 bytes, or hex, or base64). */
function readKeyBytes(path: string): Uint8Array {
  const buf = readFileSync(resolve(path));
  if (buf.length === 32) return new Uint8Array(buf);
  const text = buf.toString('utf8').trim();
  if (/^[0-9a-fA-F]{64}$/.test(text)) return new Uint8Array(Buffer.from(text, 'hex'));
  const b64 = Buffer.from(text, 'base64');
  if (b64.length === 32) return new Uint8Array(b64);
  throw new Error(`key file ${path}: expected 32 raw bytes, 64 hex chars, or base64 of 32 bytes (got ${buf.length} bytes)`);
}

async function main(): Promise<void> {
  if (!nodeSupportsSubtleGlobal()) {
    console.error(`casebandit-verify requires Node >= 20 (found ${process.version}): crypto.subtle global is unavailable.`);
    process.exit(2);
  }
  const args = parseArgs(process.argv.slice(2));
  if (!args.in) {
    console.error('Usage: node verify.js --in <export.json> [--token <token.tsr>] [--ca <ca.pem>] [--key <keyfile>] [--manifest <MANIFEST.json>] [--json]');
    process.exit(2);
  }

  const parsedRaw = readJsonFile(args.in, 'export (--in)');
  if (parsedRaw === null || typeof parsedRaw !== 'object' || Array.isArray(parsedRaw)) {
    fail('export (--in) must be a JSON object');
  }
  const parsed = parsedRaw as RawInput;
  const rows = extractRows(parsed);
  assertLedgerRows(rows);
  const declaredTip =
    typeof parsed.chainTipHash === 'string' && /^[0-9a-fA-F]{64}$/.test(parsed.chainTipHash)
      ? parsed.chainTipHash.toLowerCase()
      : null;
  if (parsed.chainTipHash !== undefined && declaredTip === null) {
    fail("export 'chainTipHash' is present but is not a 64-char hex string");
  }
  const tsaTokenBase64 = args.token ? readTokenBase64(args.token) : parsed.tsaTokenBase64 ?? null;

  // ---- Layer 1: keyless chain-tip + TSA ----
  const tsaResult = await verifyExport({ rows, tsaTokenBase64, caFile: args.ca });

  // ---- Declared-tip anchor: bind the export's self-declared chainTipHash to the
  //      recomputed tip. The recomputed tip binds payloadCipher + routingHmac, so a
  //      mismatch means the rows do not produce the declared tip = tamper. This makes
  //      the previously-unused chainTipHash an active anchor (catches e.g. a v1
  //      payloadCipher swap left with a stale declared tip, even when unstamped). ----
  const tipMatch: 'match' | 'mismatch' | 'not-declared' =
    declaredTip === null ? 'not-declared' : declaredTip === tsaResult.chainTip.toLowerCase() ? 'match' : 'mismatch';

  // ---- Optional MANIFEST check (still Layer 1, keyless file-hash only) ----
  let manifest: {
    status: 'verified' | 'failed' | 'self-consistent' | 'not-provided';
    detail?: ManifestValidationResult;
  } = { status: 'not-provided' };
  if (args.manifest) {
    const mRaw = readJsonFile(args.manifest, 'manifest (--manifest)');
    if (mRaw === null || typeof mRaw !== 'object' || Array.isArray(mRaw)) {
      fail('manifest (--manifest) must be a JSON object');
    }
    const m = mRaw as ManifestSchema;
    if (m.files === null || typeof m.files !== 'object' || Array.isArray(m.files)) {
      fail("manifest (--manifest): 'files' must be an object map of path → sha256hex");
    }
    if (typeof m.package_hash !== 'string') {
      fail("manifest (--manifest): 'package_hash' must be a string");
    }
    if (args.packageDir) {
      // With --package-dir: recompute every file's SHA-256 from the REAL packaged
      // bytes and re-derive the package_hash → catches a flipped packaged byte, an
      // added/removed file, AND a tampered manifest. Only this mode yields 'verified'.
      const detail = validateManifest(m, readPackageEntries(resolve(args.packageDir)));
      manifest = { status: detail.ok ? 'verified' : 'failed', detail };
    } else {
      // WITHOUT --package-dir there are no real bytes to hash, so we can ONLY check
      // the manifest is internally self-consistent (its package_hash field matches
      // its own declared files map). This proves NOTHING about whether the packaged
      // files match their declared hashes, so it is reported as 'self-consistent'
      // (NOT 'verified', NOT a tamper) — supply --package-dir for real integrity.
      const detail = validateManifest(m, {});
      manifest = { status: detail.packageHashOk ? 'self-consistent' : 'failed', detail };
    }
  }

  // ---- Layer 2: keyed chain verify (opt-in) ----
  let chain: { status: ChainVerifyResult['status'] | 'not-attempted'; detail?: ChainVerifyResult } = {
    status: 'not-attempted',
  };
  if (args.key) {
    const keyBytes = readKeyBytes(args.key);
    const result = await verifyChain(rows, {
      // Single-key court package: the same case key resolves every (epoch,ephemeral).
      // A multi-epoch chain needs a key per epoch — out of scope for the CLI's
      // single --key (documented in README); supply the current key and rotated
      // chains return `indeterminate` for un-derivable epochs (NOT failed).
      resolveKey: async () => keyBytes,
    });
    chain = { status: result.status, detail: result };
  }

  const output = {
    chainTip: tsaResult.chainTip,
    declaredChainTip: declaredTip,
    tipMatch,
    rowCount: tsaResult.rowCount,
    tsa: tsaResult.tsa as TsaVerdict,
    tsaDetail: tsaResult.detail,
    manifest: manifest.status,
    manifestDetail: manifest.detail,
    chain: chain.status,
    chainDetail: chain.detail,
  };

  if (args.json) {
    console.log(JSON.stringify(output, null, 2));
  } else {
    console.log(`chain_tip: ${output.chainTip}`);
    if (output.tipMatch !== 'not-declared') console.log(`declared_tip: ${output.tipMatch}`);
    console.log(`rows: ${output.rowCount}`);
    console.log(`tsa: ${output.tsa}`);
    if (output.tsaDetail) console.log(`tsa_detail: ${output.tsaDetail.trim()}`);
    console.log(`manifest: ${output.manifest}`);
    console.log(`chain: ${output.chain}`);
    if (output.chainDetail && 'reason' in output.chainDetail) {
      console.log(`chain_detail: ${output.chainDetail.reason} @ deviceSeq=${output.chainDetail.brokenAt}`);
    }
  }

  // Exit non-zero ONLY on a positive tamper signal. unstamped / indeterminate /
  // not-attempted / self-consistent are NOT failures and must never be collapsed
  // into one. A declared-tip mismatch IS a tamper signal (rows ≠ declared tip).
  const tamper =
    output.tsa === 'failed' ||
    output.manifest === 'failed' ||
    output.chain === 'failed' ||
    output.tipMatch === 'mismatch';
  process.exit(tamper ? EXIT_TAMPER : 0);
}

/**
 * Recursively read every file under `dir` into a `{ relPath -> bytes }` map,
 * using forward-slash POSIX paths to match the MANIFEST's path keys.
 */
function readPackageEntries(dir: string): Record<string, Uint8Array> {
  const out: Record<string, Uint8Array> = {};
  const walk = (cur: string): void => {
    for (const name of readdirSync(cur)) {
      const full = join(cur, name);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else {
        const rel = relative(dir, full).split(/[\\/]/).join('/');
        out[rel] = new Uint8Array(readFileSync(full));
      }
    }
  };
  walk(dir);
  // The MANIFEST file itself is never hashed; drop it if it sits in the tree.
  delete out[MANIFEST_PATH];
  return out;
}

// Fail-closed at the top level: any unexpected error (unreadable token/key file,
// openssl missing, etc.) becomes a clear exit-2 operational error, never an
// unhandled-rejection stack trace that an examiner could mistake for a tamper.
main().catch((err: unknown) => fail(err instanceof Error ? err.message : String(err)));

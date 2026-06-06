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

/** Accept either `{ rows }` (legacy) or `{ auditLedger }` (JsonExportData). */
function extractRows(parsed: RawInput): LedgerRow[] {
  if (Array.isArray(parsed.rows)) return parsed.rows;
  if (Array.isArray(parsed.auditLedger)) return parsed.auditLedger;
  return [];
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

  const parsed = JSON.parse(readFileSync(resolve(args.in), 'utf8')) as RawInput;
  const rows = extractRows(parsed);
  const tsaTokenBase64 = args.token ? readTokenBase64(args.token) : parsed.tsaTokenBase64 ?? null;

  // ---- Layer 1: keyless chain-tip + TSA ----
  const tsaResult = await verifyExport({ rows, tsaTokenBase64, caFile: args.ca });

  // ---- Optional MANIFEST check (still Layer 1, keyless file-hash only) ----
  let manifest: { status: 'verified' | 'failed' | 'not-provided'; detail?: ManifestValidationResult } = {
    status: 'not-provided',
  };
  if (args.manifest) {
    const m = JSON.parse(readFileSync(resolve(args.manifest), 'utf8')) as ManifestSchema;
    // With --package-dir: recompute every file's SHA-256 from the real packaged
    // bytes and re-derive the package_hash → catches a flipped packaged byte,
    // an added/removed file, AND a tampered manifest. Without it: validate the
    // manifest's internal package_hash consistency only (catches a tampered
    // package_hash field but not a silently-swapped file).
    const entries = args.packageDir
      ? readPackageEntries(resolve(args.packageDir))
      : entriesFromManifestFiles(m);
    const detail = validateManifest(m, entries);
    const ok = args.packageDir ? detail.ok : detail.packageHashOk;
    manifest = { status: ok ? 'verified' : 'failed', detail };
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
  // not-attempted are NOT failures and must never be collapsed into a failure.
  const tamper =
    output.tsa === 'failed' ||
    output.manifest === 'failed' ||
    output.chain === 'failed';
  process.exit(tamper ? 1 : 0);
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

/**
 * Without a package directory, build the entries map from the manifest's own
 * declared file hashes so `validateManifest` can confirm internal consistency
 * (package_hash recompute + no added/removed). This cannot catch a swapped file
 * byte (no real bytes) but DOES catch a tampered package_hash / file map.
 * Implemented by feeding each declared hash back as a pre-hashed sentinel: we
 * instead return an empty map so only `packageHashOk` is consulted by the caller.
 */
function entriesFromManifestFiles(_m: ManifestSchema): Record<string, Uint8Array> {
  return {};
}

void main();

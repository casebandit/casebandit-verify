/**
 * MANIFEST builder + validator (Court Package Phase 4 B.2).
 *
 * `package_hash` is computed over the SORTED `(path, sha256)` tuple set — NOT raw
 * ZIP bytes (Option 3A). This is deterministic/reproducible across JSZip
 * versions, compression levels, and zip timestamps; a faithful re-zip of the same
 * files reproduces the same package_hash. The `mimetype` entry and the MANIFEST
 * file itself are EXCLUDED from both the file list and the package hash.
 *
 * Schema (plan §4 Phase 4 B.2):
 *   {
 *     layout: "asic-e-style",
 *     tsa_qualified: false,
 *     chain_tip_composition: "H_i = SHA256(H_{i-1} | payloadCipher | routingHmac)",
 *     canonical_spec_present: "jcs-rfc8785-v1" | "jcs-rfc8785-v2",
 *     hash_algo: "sha256",
 *     files: { "<path>": "<sha256hex>", ... },   // excludes mimetype + MANIFEST
 *     package_hash: "<sha256hex over sorted (path,sha256) tuples>"
 *   }
 */
import { createHash } from 'node:crypto';

export const MANIFEST_PATH = 'META-INF/MANIFEST.json';
export const MIMETYPE_PATH = 'mimetype';

/**
 * Own-property lookup that is IMMUNE to prototype pollution. Filenames are
 * attacker-controlled: a file (or manifest entry) literally named `toString`,
 * `constructor`, `hasOwnProperty`, `__proto__`, etc. inherits from
 * `Object.prototype`, so a plain `key in obj` / `obj[key]` would treat it as
 * present and silently bypass tamper detection. Every lookup over a
 * filename-keyed map in this file MUST go through these helpers.
 */
function hasOwn(obj: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}
function getOwn<T>(map: Record<string, T>, key: string): T | undefined {
  return hasOwn(map, key) ? map[key] : undefined;
}

export interface ManifestSchema {
  layout: 'asic-e-style';
  tsa_qualified: false;
  chain_tip_composition: string;
  canonical_spec_present: string;
  hash_algo: 'sha256';
  files: Record<string, string>;
  package_hash: string;
}

export const CHAIN_TIP_COMPOSITION =
  "H_i = SHA256(H_{i-1} + '|' + payloadCipher + '|' + routingHmac); genesis = 64 zero chars";

function sha256Hex(bytes: Uint8Array | Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Compute the deterministic package hash over a `{ path -> sha256hex }` map.
 * Sorts entries by path, joins each as `path + '\n' + sha256 + '\n'`, hashes.
 * The serialization is fixed so any reimplementation reproduces it byte-for-byte.
 */
export function computePackageHash(files: Record<string, string>): string {
  const paths = Object.keys(files).sort();
  const h = createHash('sha256');
  for (const p of paths) {
    h.update(p, 'utf8');
    h.update('\n', 'utf8');
    h.update(files[p], 'utf8');
    h.update('\n', 'utf8');
  }
  return h.digest('hex');
}

/**
 * Build a MANIFEST from a set of packaged files. `entries` maps every package
 * path to its raw bytes (including `mimetype` + everything else; this function
 * excludes `mimetype` + the MANIFEST itself from the file list + package hash).
 */
export function buildManifest(
  entries: Record<string, Uint8Array | Buffer>,
  meta: { canonicalSpecPresent: string },
): ManifestSchema {
  const files: Record<string, string> = {};
  for (const [path, bytes] of Object.entries(entries)) {
    if (path === MIMETYPE_PATH || path === MANIFEST_PATH) continue;
    files[path] = sha256Hex(bytes);
  }
  return {
    layout: 'asic-e-style',
    tsa_qualified: false,
    chain_tip_composition: CHAIN_TIP_COMPOSITION,
    canonical_spec_present: meta.canonicalSpecPresent,
    hash_algo: 'sha256',
    files,
    package_hash: computePackageHash(files),
  };
}

export interface ManifestValidationResult {
  ok: boolean;
  /** Files in the manifest whose recomputed hash does not match. */
  mismatched: string[];
  /** Files present on disk/in the package but absent from the manifest (excl. mimetype + MANIFEST). */
  missingFromManifest: string[];
  /** Files in the manifest absent from the provided package entries. */
  missingFromPackage: string[];
  /**
   * True iff `computePackageHash(manifest.files)` equals `manifest.package_hash`.
   * This is a SELF-CONSISTENCY check of the manifest only — it recomputes the
   * package hash from the manifest's OWN declared file map, NOT from real file
   * bytes. It catches a manifest whose `package_hash` field was edited without
   * updating `files` (or vice-versa), but proves NOTHING about whether the
   * packaged files match their declared hashes. Real integrity needs `entries`
   * (the actual bytes) → `mismatched`/`missingFrom*`/`ok`.
   */
  packageHashOk: boolean;
  expectedPackageHash: string;
  actualPackageHash: string;
}

/**
 * Validate a parsed MANIFEST against the actual packaged bytes. Recomputes every
 * file hash, checks for added/removed files, and recomputes the package hash.
 * `mimetype` + the MANIFEST file are excluded from comparison.
 */
export function validateManifest(
  manifest: ManifestSchema,
  entries: Record<string, Uint8Array | Buffer>,
): ManifestValidationResult {
  const mismatched: string[] = [];
  const missingFromPackage: string[] = [];
  const missingFromManifest: string[] = [];

  for (const [path, expected] of Object.entries(manifest.files)) {
    const bytes = getOwn(entries, path);
    if (bytes === undefined) {
      missingFromPackage.push(path);
      continue;
    }
    if (sha256Hex(bytes) !== expected) mismatched.push(path);
  }

  for (const path of Object.keys(entries)) {
    if (path === MIMETYPE_PATH || path === MANIFEST_PATH) continue;
    // hasOwn (NOT `path in manifest.files`): a package file named e.g. `toString`
    // must be reported as an unexpected extra file, not treated as expected via a
    // property inherited from Object.prototype — that would bypass tamper detection.
    if (!hasOwn(manifest.files, path)) missingFromManifest.push(path);
  }

  const actualPackageHash = computePackageHash(manifest.files);
  const packageHashOk = actualPackageHash === manifest.package_hash;

  const ok =
    mismatched.length === 0 &&
    missingFromPackage.length === 0 &&
    missingFromManifest.length === 0 &&
    packageHashOk;

  return {
    ok,
    mismatched,
    missingFromManifest,
    missingFromPackage,
    packageHashOk,
    expectedPackageHash: manifest.package_hash,
    actualPackageHash,
  };
}

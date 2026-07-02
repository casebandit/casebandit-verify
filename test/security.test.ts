// Regression tests for the four hardening findings (prototype-pollution tamper
// bypass, symlink/special-file DoS, and unbounded-load DoS). Each asserts the
// FIXED behaviour: a forensic verifier must fail-closed, never silently pass.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  writeFileSync,
  mkdtempSync,
  mkdirSync,
  cpSync,
  symlinkSync,
  truncateSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { validateManifest, type ManifestSchema } from '../src/core/manifest.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const FX = join(ROOT, 'fixtures');
const VERIFY = join(ROOT, 'verify.ts');

/** Run the CLI; return { status, stdout, stderr } without throwing on non-zero. */
function runCli(args: string[]): { status: number; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync(process.execPath, ['--import', 'tsx', VERIFY, ...args], {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).toString();
    return { status: 0, stdout, stderr: '' };
  } catch (err) {
    const e = err as { status?: number; stdout?: Buffer; stderr?: Buffer };
    return { status: e.status ?? -1, stdout: e.stdout?.toString() ?? '', stderr: e.stderr?.toString() ?? '' };
  }
}

const TMP = mkdtempSync(join(tmpdir(), 'cb-sec-'));

describe('FINDING A — prototype-pollution tamper bypass', () => {
  it('a package file named `toString` (absent from MANIFEST) is reported as an extra file, NOT treated as expected', () => {
    // Manifest declares ONE legit file; the package additionally contains a file
    // literally named `toString`. Pre-fix, `'toString' in manifest.files` was
    // true (inherited from Object.prototype) → the extra file slipped through.
    const manifest: ManifestSchema = {
      layout: 'asic-e-style',
      tsa_qualified: false,
      chain_tip_composition: 'x',
      canonical_spec_present: 'jcs-rfc8785-v2',
      hash_algo: 'sha256',
      files: { 'report/a.txt': 'deadbeef' },
      package_hash: 'ignored-here',
    };
    const entries: Record<string, Uint8Array> = {
      'report/a.txt': new Uint8Array(),
      toString: new Uint8Array([1, 2, 3]), // own property named `toString`
    };
    const res = validateManifest(manifest, entries);
    assert.ok(res.missingFromManifest.includes('toString'), 'extra `toString` file must be flagged');
    assert.equal(res.ok, false, 'verification must FAIL when an undeclared file is present');
  });

  it('a MANIFEST entry named `constructor` missing from the package is reported missing, not inherited', () => {
    const manifest: ManifestSchema = {
      layout: 'asic-e-style',
      tsa_qualified: false,
      chain_tip_composition: 'x',
      canonical_spec_present: 'jcs-rfc8785-v2',
      hash_algo: 'sha256',
      files: { constructor: 'deadbeef' },
      package_hash: 'ignored-here',
    };
    const res = validateManifest(manifest, {});
    assert.ok(res.missingFromPackage.includes('constructor'));
    assert.equal(res.ok, false);
  });

  it('CLI: package dir with an extra `toString` file → manifest: failed, exit 1', () => {
    const pkg = join(TMP, 'pkg-toString');
    cpSync(join(FX, 'manifest-ok'), pkg, { recursive: true });
    writeFileSync(join(pkg, 'toString'), 'sneaky extra file\n'); // not in MANIFEST
    const r = runCli([
      '--in', join(FX, 'empty.json'),
      '--manifest', join(pkg, 'META-INF', 'MANIFEST.json'),
      '--package-dir', pkg,
    ]);
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stdout, /manifest: failed/);
  });
});

describe('FINDING B — symlink / special-file DoS in --package-dir walk', () => {
  it('a symlink inside the package dir is rejected with a clear error (exit 2)', () => {
    const pkg = join(TMP, 'pkg-symlink');
    cpSync(join(FX, 'manifest-ok'), pkg, { recursive: true });
    symlinkSync('/dev/zero', join(pkg, 'evil-link')); // could hang if followed
    const r = runCli([
      '--in', join(FX, 'empty.json'),
      '--manifest', join(pkg, 'META-INF', 'MANIFEST.json'),
      '--package-dir', pkg,
    ]);
    assert.equal(r.status, 2, r.stdout);
    assert.match(r.stderr, /symlink/);
  });
});

describe('FINDING D — unbounded ledger load', () => {
  it('an over-cap ledger file is rejected with a clear error (exit 2)', () => {
    const big = join(TMP, 'huge.json');
    writeFileSync(big, '');
    truncateSync(big, 64 * 1024 * 1024 + 1); // sparse file just over the 64 MiB cap
    const r = runCli(['--in', big]);
    assert.equal(r.status, 2, r.stdout);
    assert.match(r.stderr, /exceeds the .*cap/);
  });
});

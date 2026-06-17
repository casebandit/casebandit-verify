// CLI fail-closed contract (regression net for the hardening pass). Spawns the
// real `verify.ts` entrypoint and asserts the EXIT-CODE discipline + verdicts:
//   0 = clean · 1 = tamper · 2 = operational/input error.
// Covers: declared-tip anchoring, malformed/stripped evidence, row type
// validation, and the honest `manifest: self-consistent` (no --package-dir) arm.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const FX = join(ROOT, 'fixtures');
const VERIFY = join(ROOT, 'verify.ts');
const MIXED_CA = join(FX, 'mixed-ca.crt');

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

const TMP = mkdtempSync(join(tmpdir(), 'cb-cli-'));
function tmp(name: string, body: string): string {
  const p = join(TMP, name);
  writeFileSync(p, body);
  return p;
}

describe('CLI exit-code discipline (0 clean / 1 tamper / 2 error)', () => {
  it('valid mixed export → exit 0, tsa verified, declared_tip match', () => {
    const r = runCli(['--in', join(FX, 'mixed-v1v2.json'), '--ca', MIXED_CA]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /tsa: verified/);
    assert.match(r.stdout, /declared_tip: match/);
  });

  it('tamper export → exit 1 (tsa failed + declared_tip mismatch)', () => {
    const r = runCli(['--in', join(FX, 'tamper.json'), '--ca', MIXED_CA]);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /tsa: failed/);
    assert.match(r.stdout, /declared_tip: mismatch/);
  });

  it('declared chainTipHash mismatch on an UNSTAMPED export → exit 1 (anchor)', () => {
    const o = JSON.parse(readFileSync(join(FX, 'mixed-v1v2.json'), 'utf8'));
    const bad = tmp('stale-tip.json', JSON.stringify({ rows: o.rows, tsaTokenBase64: null, chainTipHash: '0'.repeat(64) }));
    const r = runCli(['--in', bad]);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /declared_tip: mismatch/);
  });

  it('corrupt JSON → exit 2, clear message (never a stack trace)', () => {
    const bad = tmp('bad.json', '{not valid');
    const r = runCli(['--in', bad]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /is not valid JSON/);
  });

  it('export missing both ledger fields → exit 2 (fail-closed, not a clean pass)', () => {
    const bad = tmp('noledger.json', '{"foo":1}');
    const r = runCli(['--in', bad]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /no 'rows' or 'auditLedger'/);
  });

  it('row with non-numeric clientTs → exit 2 (type validation before hashing)', () => {
    const o = JSON.parse(readFileSync(join(FX, 'mixed-v1v2.json'), 'utf8'));
    o.rows[0].clientTs = 'NOPE';
    const bad = tmp('badrow.json', JSON.stringify(o));
    const r = runCli(['--in', bad]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /clientTs.*finite number/);
  });

  it('--manifest WITHOUT --package-dir → exit 0, manifest: self-consistent', () => {
    const r = runCli(['--in', join(FX, 'empty.json'), '--manifest', join(FX, 'manifest-ok', 'META-INF', 'MANIFEST.json')]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /manifest: self-consistent/);
  });

  it('--manifest WITH --package-dir (ok) → exit 0, manifest: verified', () => {
    const r = runCli([
      '--in', join(FX, 'empty.json'),
      '--manifest', join(FX, 'manifest-ok', 'META-INF', 'MANIFEST.json'),
      '--package-dir', join(FX, 'manifest-ok'),
    ]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /manifest: verified/);
  });

  it('--manifest WITH --package-dir (tampered) → exit 1, manifest: failed', () => {
    const r = runCli([
      '--in', join(FX, 'empty.json'),
      '--manifest', join(FX, 'manifest-bad', 'META-INF', 'MANIFEST.json'),
      '--package-dir', join(FX, 'manifest-bad'),
    ]);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /manifest: failed/);
  });
});

#!/usr/bin/env node
/**
 * Deterministic fixture builder for the golden-vector suite. Produces, OFFLINE
 * (self-signed test TSA — no network), every fixture the test suite consumes:
 *
 *   mixed-v1v2.json   — a 4-row chain mixing v1 + v2 rows; verifies end-to-end.
 *   mixed-token.der   — RFC 3161 token over THAT chain's computed tip → tsa:verified.
 *   tamper.json       — mixed chain with ONE payloadCipher byte flipped (+ its
 *                       token, which now attests a DIFFERENT tip) → tsa:failed.
 *   truncation.json   — mixed chain with the LAST row dropped (+ original token,
 *                       now over the wrong tip) → tsa:failed.
 *   empty.json        — zero rows → tip = 64 zeros, tsa:unstamped.
 *   manifest-ok/      — a 3-file package + a valid MANIFEST.json.
 *   manifest-bad/     — the same package with ONE file byte flipped (MANIFEST
 *                       unchanged) → manifest:failed.
 *   fixture-key.hex   — the 32-byte HMAC/secretbox key the chains are signed with.
 *
 * Run: `node test/build-fixtures.mjs`. Idempotent.
 */
import { execFileSync } from 'node:child_process';
import { createHash, createHmac, webcrypto } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import nacl from 'tweetnacl';
import { canonicalize } from '../src/vendored-mutable/canonical-json.ts';
import { buildHmacMessage } from '../src/vendored-mutable/ledger-hmac.ts';
import { computeChainTipHash } from '../src/vendored-frozen/chain-tip.ts';
import { buildManifest } from '../src/core/manifest.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FX = join(HERE, '..', 'fixtures');

// Deterministic 32-byte key (NOT a secret — a public test vector).
const KEY = new Uint8Array(32);
for (let i = 0; i < 32; i++) KEY[i] = (i * 7 + 3) & 0xff;
// Deterministic nonce per row index (fixtures must be reproducible).
function nonceFor(i) {
  const n = new Uint8Array(nacl.secretbox.nonceLength);
  for (let j = 0; j < n.length; j++) n[j] = (i * 13 + j) & 0xff;
  return n;
}
function b64(u8) {
  return Buffer.from(u8).toString('base64');
}
function secretbox(payloadObj, i) {
  const msg = new TextEncoder().encode(JSON.stringify(payloadObj));
  const nonce = nonceFor(i);
  const cipher = nacl.secretbox(msg, nonce, KEY);
  return { payloadCipher: b64(cipher), payloadNonce: b64(nonce) };
}
function hmacBase64(message) {
  return createHmac('sha256', Buffer.from(KEY)).update(Buffer.from(message)).digest('base64');
}

/** Build a fully-signed ledger row under the given spec. */
function makeRow({ i, caseId, deviceId, deviceSeq, clientTs, spec, payload }) {
  const { payloadCipher, payloadNonce } = secretbox(payload, i);
  const fields = {
    caseId,
    deviceId,
    deviceSeq,
    clientTs,
    keyEpoch: 0,
    ephemeral: false,
    payloadCipher,
    payloadNonce,
    canonicalSpec: spec,
    hashAlgo: 'sha256',
  };
  const message = buildHmacMessage(fields, spec);
  const routingHmac = hmacBase64(message);
  return {
    id: `row-${deviceId}-${deviceSeq}`,
    caseId,
    deviceId,
    deviceSeq,
    clientTs,
    keyEpoch: 0,
    payloadCipher,
    payloadNonce,
    routingHmac,
    canonicalSpec: spec,
    hashAlgo: 'sha256',
    ephemeral: false,
  };
}

const CASE = 'case-fixture-001';
const T0 = 1_700_000_000_000;

// A 4-row mixed v1/v2 chain across two devices (exercises the canonical sort).
const mixedRows = [
  makeRow({ i: 0, caseId: CASE, deviceId: 'dev-A', deviceSeq: 1000, clientTs: T0 + 1, spec: 'jcs-rfc8785-v1', payload: { kind: 'case-open', caseId: CASE } }),
  makeRow({ i: 1, caseId: CASE, deviceId: 'dev-A', deviceSeq: 1001, clientTs: T0 + 2, spec: 'jcs-rfc8785-v2', payload: { kind: 'note', body: 'first note', refs: [] } }),
  makeRow({ i: 2, caseId: CASE, deviceId: 'dev-B', deviceSeq: 2000, clientTs: T0 + 2, spec: 'jcs-rfc8785-v1', payload: { kind: 'entity-create', entityId: 'e1', entityType: 'person', label: 'Alice' } }),
  makeRow({ i: 3, caseId: CASE, deviceId: 'dev-A', deviceSeq: 1002, clientTs: T0 + 3, spec: 'jcs-rfc8785-v2', payload: { kind: 'note', body: 'second note', refs: [] } }),
];

/** Self-signed test TSA token over `rawTipBytes` (32 bytes). Offline. */
function makeTsaToken(rawTipBytes) {
  const dir = mkdtempSync(join(tmpdir(), 'cb-fx-tsa-'));
  try {
    const p = (f) => join(dir, f);
    writeFileSync(p('tip.bin'), Buffer.from(rawTipBytes));
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', p('ca.key'), '-out', p('ca.crt'), '-subj', '/CN=CaseBandit Test TSA Root/O=CaseBandit Test/C=US', '-days', '7300', '-sha256'], { stdio: 'pipe' });
    execFileSync('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', p('tsa.key'), '-out', p('tsa.csr'), '-subj', '/CN=CaseBandit Test TSA Signer/O=CaseBandit Test/C=US'], { stdio: 'pipe' });
    writeFileSync(p('tsa-ext.cnf'), 'basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = critical, timeStamping\n');
    execFileSync('openssl', ['x509', '-req', '-in', p('tsa.csr'), '-CA', p('ca.crt'), '-CAkey', p('ca.key'), '-CAcreateserial', '-out', p('tsa.crt'), '-days', '7300', '-sha256', '-extfile', p('tsa-ext.cnf')], { stdio: 'pipe' });
    writeFileSync(p('tsa-serial'), '01\n');
    writeFileSync(p('tsa.cnf'), `[ tsa_config1 ]\nserial = ${p('tsa-serial')}\ncrypto_device = builtin\nsigner_cert = ${p('tsa.crt')}\ncerts = ${p('ca.crt')}\nsigner_key = ${p('tsa.key')}\nsigner_digest = sha256\ndefault_policy = 1.3.6.1.4.1.99999.1.1\ndigests = sha256\naccuracy = secs:1\nclock_precision_digits = 0\nordering = yes\ntsa_name = yes\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n`);
    execFileSync('openssl', ['ts', '-query', '-data', p('tip.bin'), '-sha256', '-cert', '-out', p('request.tsq')], { stdio: 'pipe' });
    execFileSync('openssl', ['ts', '-reply', '-config', p('tsa.cnf'), '-section', 'tsa_config1', '-queryfile', p('request.tsq'), '-out', p('response.tsr')], { stdio: 'pipe' });
    execFileSync('openssl', ['ts', '-reply', '-in', p('response.tsr'), '-token_out', '-out', p('token.der')], { stdio: 'pipe' });
    // self-check
    execFileSync('openssl', ['ts', '-verify', '-data', p('tip.bin'), '-in', p('token.der'), '-token_in', '-CAfile', p('ca.crt')], { stdio: 'pipe' });
    return { token: readFileSync(p('token.der')), ca: readFileSync(p('ca.crt')) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function main() {
  if (!existsSync(FX)) mkdirSync(FX, { recursive: true });

  writeFileSync(join(FX, 'fixture-key.hex'), Buffer.from(KEY).toString('hex') + '\n');

  // --- mixed v1/v2 (verifies) + its token ---
  const tipHex = await computeChainTipHash(mixedRows);
  const rawTip = Buffer.from(tipHex, 'hex');
  const { token, ca } = makeTsaToken(rawTip);
  writeFileSync(join(FX, 'mixed-token.der'), token);
  writeFileSync(join(FX, 'mixed-ca.crt'), ca);
  writeFileSync(
    join(FX, 'mixed-v1v2.json'),
    JSON.stringify({ rows: mixedRows, tsaTokenBase64: token.toString('base64'), chainTipHash: tipHex }, null, 2) + '\n',
  );

  // --- tamper: flip ONE byte of the LAST row's payloadCipher (token unchanged → wrong tip) ---
  const tamperRows = mixedRows.map((r) => ({ ...r }));
  const last = tamperRows[tamperRows.length - 1];
  const cipherBytes = Buffer.from(last.payloadCipher, 'base64');
  cipherBytes[0] ^= 0xff;
  last.payloadCipher = cipherBytes.toString('base64');
  writeFileSync(
    join(FX, 'tamper.json'),
    JSON.stringify({ rows: tamperRows, tsaTokenBase64: token.toString('base64'), chainTipHash: tipHex }, null, 2) + '\n',
  );

  // --- truncation: drop the LAST row (original token now over the wrong tip) ---
  const truncRows = mixedRows.slice(0, -1);
  writeFileSync(
    join(FX, 'truncation.json'),
    JSON.stringify({ rows: truncRows, tsaTokenBase64: token.toString('base64'), chainTipHash: tipHex }, null, 2) + '\n',
  );

  // --- empty chain ---
  writeFileSync(join(FX, 'empty.json'), JSON.stringify({ rows: [], tsaTokenBase64: null }, null, 2) + '\n');

  // --- MANIFEST ok package ---
  const okDir = join(FX, 'manifest-ok');
  mkdirSync(join(okDir, 'report'), { recursive: true });
  mkdirSync(join(okDir, 'META-INF'), { recursive: true });
  const fileA = Buffer.from('report A content\n');
  const fileB = Buffer.from('report B content\n');
  const mimetype = Buffer.from('application/vnd.etsi.asic-e+zip');
  writeFileSync(join(okDir, 'mimetype'), mimetype);
  writeFileSync(join(okDir, 'report', 'a.txt'), fileA);
  writeFileSync(join(okDir, 'report', 'b.txt'), fileB);
  const entries = { mimetype, 'report/a.txt': fileA, 'report/b.txt': fileB };
  const manifest = buildManifest(entries, { canonicalSpecPresent: 'jcs-rfc8785-v2' });
  writeFileSync(join(okDir, 'META-INF', 'MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n');

  // --- MANIFEST bad package: same MANIFEST, ONE file byte flipped ---
  const badDir = join(FX, 'manifest-bad');
  mkdirSync(join(badDir, 'report'), { recursive: true });
  mkdirSync(join(badDir, 'META-INF'), { recursive: true });
  const fileBbad = Buffer.from('report B content TAMPERED\n');
  writeFileSync(join(badDir, 'mimetype'), mimetype);
  writeFileSync(join(badDir, 'report', 'a.txt'), fileA);
  writeFileSync(join(badDir, 'report', 'b.txt'), fileBbad);
  // SAME manifest as the ok package (so b.txt's recorded hash no longer matches).
  writeFileSync(join(badDir, 'META-INF', 'MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n');

  console.log('fixtures built:');
  console.log('  tip(mixed):', tipHex);
  console.log('  package_hash:', manifest.package_hash);
}

// Use the Node webcrypto global if not already present (Node >= 20 has it).
if (!globalThis.crypto) globalThis.crypto = webcrypto;
await main();

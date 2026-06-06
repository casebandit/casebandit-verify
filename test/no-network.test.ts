// CI no-network gate (plan Phase 3 §4.5). Asserts the verifier completes a full
// keyless + keyed verification with ALL network primitives sabotaged, and that
// package.json declares zero HTTP/network dependencies. Runtime is the real
// defense; the dep check is the regression net.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import dns from 'node:dns';
import { verifyExport } from '../src/core/tsa-verify.ts';
import { verifyChain } from '../src/core/chain-verify.ts';
import type { LedgerRow } from '../src/vendored-frozen/types.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FX = join(HERE, '..', 'fixtures');
const ROOT = join(HERE, '..');

function rowsOf(o: { rows?: LedgerRow[]; auditLedger?: LedgerRow[] }): LedgerRow[] {
  return o.rows ?? o.auditLedger ?? [];
}

describe('no-network gate: runtime', () => {
  const saved = {
    fetch: globalThis.fetch,
    httpRequest: http.request,
    httpsRequest: https.request,
    httpGet: http.get,
    httpsGet: https.get,
    netConnect: net.connect,
    netCreate: net.createConnection,
    dnsLookup: dns.lookup,
  };

  before(() => {
    const boom = (): never => {
      throw new Error('NETWORK ACCESS FORBIDDEN — the verifier must run fully offline');
    };
    const b = boom as unknown as never;
    globalThis.fetch = b;
    http.request = b;
    https.request = b;
    http.get = b;
    https.get = b;
    net.connect = b;
    net.createConnection = b;
    dns.lookup = b;
  });

  after(() => {
    globalThis.fetch = saved.fetch;
    http.request = saved.httpRequest;
    https.request = saved.httpsRequest;
    http.get = saved.httpGet;
    https.get = saved.httpsGet;
    net.connect = saved.netConnect;
    net.createConnection = saved.netCreate;
    dns.lookup = saved.dnsLookup;
  });

  it('Layer-1 keyless TSA verify completes offline → verified', async () => {
    const o = JSON.parse(readFileSync(join(FX, 'mixed-v1v2.json'), 'utf8'));
    const r = await verifyExport({ rows: rowsOf(o), tsaTokenBase64: o.tsaTokenBase64, caFile: join(FX, 'mixed-ca.crt') });
    assert.equal(r.tsa, 'verified', r.detail);
  });

  it('Layer-2 keyed chain verify completes offline → verified', async () => {
    const o = JSON.parse(readFileSync(join(FX, 'mixed-v1v2.json'), 'utf8'));
    const key = new Uint8Array(Buffer.from(readFileSync(join(FX, 'fixture-key.hex'), 'utf8').trim(), 'hex'));
    const r = await verifyChain(rowsOf(o), { resolveKey: async () => key });
    assert.equal(r.status, 'verified');
  });
});

describe('no-network gate: dependency manifest', () => {
  it('package.json declares zero HTTP/network dependencies', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
    const all = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    const allowlist = new Set(['tweetnacl', 'esbuild', 'tsx', 'typescript', '@types/node']);
    const forbidden = /(axios|node-fetch|got|undici|request|superagent|isomorphic-fetch|cross-fetch|http-proxy|ws)/i;
    for (const name of Object.keys(all)) {
      assert.ok(allowlist.has(name), `unexpected dependency: ${name}`);
      assert.ok(!forbidden.test(name), `network dependency forbidden: ${name}`);
    }
  });

  it('runtime dependencies are exactly { tweetnacl }', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
    assert.deepEqual(Object.keys(pkg.dependencies ?? {}), ['tweetnacl']);
  });
});

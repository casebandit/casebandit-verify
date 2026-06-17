# casebandit-verify

A **standalone, offline, public** forensic verifier for the CaseBandit audit-ledger
**Court Package**. This repository holds **only the verification algorithm — never
any case data, secret, `.env`, or private application code**. It is a *separate
public repository* from the (closed-source) CaseBandit application: the verifier
that confirms an export is intact must not share a build graph with the tool that
*generated* the export, so an opposing expert cannot raise the "same vendor /
circular" objection.

License: **Apache-2.0** (chosen over MIT for its explicit patent grant — defensive
for a forensic tool audited by hostile third parties). See `LICENSE`.

---

## What it proves (and what it deliberately does not)

The verifier runs **locally and fully offline** on the Court Package *you* control.
It makes **zero network calls** (CI-enforced — see "No-network gate" below).

### The public-method / private-data boundary

- **Layer 1 (default, KEYLESS)** reveals **zero case content**. It recomputes the
  audit-ledger chain tip from the rows (the chain hash binds `payloadCipher +
  routingHmac`, so no decryption is needed) and cryptographically verifies any
  RFC 3161 timestamp token attests that exact tip. A keyless third-party examiner
  can run this and learn the records are intact + trusted-timestamped **without
  ever seeing a single note, entity, or capture**.
- **Layer 2 (`--key <keyfile>`, OPT-IN)** decrypts **only for the key-holder**
  (the analyst, or a court-ordered disclosure). It recomputes each row's HMAC
  under that row's own canonical spec and walks the full chain. The key never
  leaves your machine.

Publishing this verifier publishes the **method, not the data.** CaseBandit's
zero-knowledge guarantee is unchanged: the company stores ciphertext it cannot
decrypt and an HMAC it cannot validate — **the only competent content-authenticating
witness is the analyst/user, never the operator.**

### Honest ceiling (never overclaim)

`verified` here means *this device recomputed the cryptographic chain + the
trusted timestamp checks out*. It is **not** an attestation by CaseBandit or any
third party that the records are *authentic* or *complete*, and it is **not** a
Rule 902(13)/(14) self-authenticating certification. This is **court-supporting**
evidence, not "court-certified".

Both tri-state verdicts are kept **separate and verbatim** in the output — they are
**never collapsed** into a binary pass/fail:

| Channel | Verdicts | Meaning of the non-`verified` arms |
|---------|----------|------------------------------------|
| `tsa`   | `verified` \| `unstamped` \| `failed` | `unstamped` = no token (unanchored, **NOT** a failure) |
| `chain` | `verified` \| `indeterminate` \| `failed` | `indeterminate` = key material unavailable (cold/offline, **NOT** tamper) |
| `manifest` | `verified` \| `self-consistent` \| `failed` \| `not-provided` | `self-consistent` = `--manifest` given **without** `--package-dir`: only the manifest's internal `package_hash` was checked, **NOT** the real file bytes (supply `--package-dir` for `verified`) |

If the export carries a `chainTipHash`, it is bound to the recomputed tip: a
`declared_tip: mismatch` (rows do not produce the declared tip) is a **tamper**
signal.

**Exit codes** (a caller can script on `$?`): `0` = clean · `1` = tamper
(`tsa`/`chain`/`manifest` `failed`, or `declared_tip` mismatch) · `2` =
operational/input error (bad usage, unreadable or malformed evidence). Malformed
input is **always** exit 2 — it is never silently passed nor collapsed into the
exit-1 tamper signal.

---

## Install & run

Requires **Node ≥ 20** (`crypto.subtle` global) and `openssl` on `PATH` (for the
Layer-1 RFC 3161 signature / CA-chain validation). The offline `verify.html` needs
neither.

```bash
npm install        # or: bun install
npm test           # all golden vectors incl. the 5 court fixtures
```

### CLI — Layer 1 (keyless, default)

```bash
# chain-tip recompute + RFC 3161 TSA verify against the embedded token:
node verify.js --in court-package/ledger/audit-ledger.json \
               --token court-package/ledger/tsa-token.tsr \
               --ca ca/sectigo-tsa-ca-bundle.pem

# add a MANIFEST + package-dir check (per-file SHA-256 + package_hash):
node verify.js --in <export.json> \
               --manifest court-package/META-INF/MANIFEST.json \
               --package-dir court-package
```

> The published entrypoint is the TypeScript file `verify.ts`, run via `tsx`
> (`npm run verify -- --in …`). The `node verify.js` form in the gates is the
> same program; if you prefer a plain `.js`, transpile `verify.ts` with `tsx`/`esbuild`.
> `--in` accepts either the legacy `{ rows, tsaTokenBase64 }` shape **or** the
> app's `JsonExportData` (`{ auditLedger, tsaTokenBase64, chainTipHash }`).

### CLI — Layer 2 (keyed, opt-in)

```bash
node verify.js --in <export.json> --key path/to/case-key.hex   # adds chain: verified|…
```

The keyfile is 32 raw bytes, or 64 hex chars, or base64 of 32 bytes. A single key
resolves every `(epoch, ephemeral)`; a multi-epoch (rotated) chain whose older
epoch keys you don't supply returns `chain: indeterminate` for those rows — **NOT**
`failed` (per the tri-state contract).

### Offline single-file `verify.html`

`verify.html` is a **single self-contained file**, openable directly from
`file://` (double-click). It bundles the keyless web core (no openssl, no Node,
no network) under CSP `default-src 'none'`. Paste the export JSON and it
recomputes the chain tip and checks the token *contains* that tip's message
imprint (a containment check). For full RFC 3161 signature / CA-chain / genTime
validation it tells you to **run the CLI**.

Rebuild it deterministically:

```bash
npm run build:web    # prints the SHA-256; must match the pin below
```

---

## Vendored-leaf content-hash pins

This repo vendors the *genuinely-frozen* algorithm leaves from the CaseBandit app
so a reviewer can diff each one against the app source. Each vendored file carries
a header pinning the **content-hash of the upstream file it was copied from**. The
only edits are the documented import re-points + the vendor header.

| Vendored file | Upstream `casenotes-saas` path | Upstream sha256 (pin) | Class |
|---------------|--------------------------------|-----------------------|-------|
| `src/vendored-frozen/chain-tip.ts`     | `apps/web/lib/chain-tip.ts`     | `f8108a80ada9728d697914e947dd8a21520f818c9c46610589fe1b5927aacb62` | **frozen** |
| `src/vendored-frozen/ledger-sort.ts`   | `apps/web/lib/ledger-sort.ts`   | `c8c6ac1461df58a659c1e2c71aab6bf685b3de037b1d3ae9988d86a2bef824ba` | **frozen** |
| `src/vendored-frozen/tsa-token.ts`     | `apps/web/lib/tsa-token.ts`     | `367a456153e3df437d538ad86919df0e2010368169d42924876e4893dc9794a3` | **frozen** |
| `src/vendored-mutable/ledger-hmac.ts`  | `apps/web/lib/ledger-hmac.ts`   | `12927308a76ab729198cb8e670bf8614e5886ea9a6846b639c154717d12f6acd` | **MUTABLE** |
| `src/vendored-mutable/canonical-json.ts` | `apps/web/lib/canonical-json.ts` | `a91824d9b62c5f7e7057c0b702e31f599a607d2c2a4576036754e2949387b0ea` | dep of the mutable leaf |
| `ca/sectigo-tsa-ca-bundle.pem`         | `tools/ca/sectigo-tsa-ca-bundle.pem` | `2e75187bb6ad3d3bb613f96712af23bfe747d0de2014c202c448c54f31f5e6da` | CA bundle |

Reproduce a pin: `sha256sum <upstream-file>`. Verify the whole pin table at once:
`npm run verify:pins` (compares against a sibling `casenotes-saas` checkout if present).

### Why "frozen" vs "mutable"

- **Frozen leaves** (`chain-tip`, `ledger-sort`, `tsa-token`) are **safe to vendor**:
  the chain composition `H_i = SHA256(H_{i-1} | payloadCipher | routingHmac)` and
  the canonical sort are **contractually frozen** — UNCHANGED across the v1→v2
  HMAC migration and the F3 TSA work. The golden vectors catch any accidental drift.
- **`buildHmacMessage` is the ONE genuinely-mutable forensic leaf.** It **changed
  v1 → v2** (the v2 message widened to bind `payloadCipher + nonce + mode tuple`)
  and a future spec bump (v3) *will* change it again. Vendoring it as a frozen copy
  would risk a **silent court-facing drift** on the keyed Layer-2 path. So it lives
  in `src/vendored-mutable/` behind a **LOUD pinned-hash boundary**: a spec bump
  REQUIRES bumping its pin *and* the golden vectors in `test/hmac-message.test.ts`,
  and the golden-vector CI catch turns that bump into a verbatim-byte test failure
  instead of a quiet divergence.

  > **Interim note.** The plan's end state is a *versioned published npm dependency*
  > (`@casebandit/ledger-hmac`) so a spec bump forces a visible `package.json` /
  > lockfile version bump. The app is not yet published to npm, so that intent is
  > satisfied *for now* by (1) the explicit pinned-hash boundary above and (2) the
  > golden-vector regression catch. Replace `src/vendored-mutable/ledger-hmac.ts`
  > with the published package once the app publishes it. Layer-1 (keyless, the
  > default) never calls `buildHmacMessage`, so the keyless path stays vendored +
  > dependency-minimal regardless.

---

## Reproducible build

- Node pinned to **≥ 20** (`.nvmrc` = 20; `engines.node` = `>=20`).
- Lockfile committed (`package-lock.json`); runtime deps are exactly `{ tweetnacl }`,
  dev deps are `{ @types/node, esbuild, tsx, typescript }`. **Zero HTTP/network deps.**
- The built **`verify.html` SHA-256 is pinned**:

  ```
  verify.html  sha256:  d6cc2bc20c4f0677b11990282fb68d28eedc3efe8d959728227abf4a5ac14d97
  ```

  `npm run build:web` rebuilds it and prints the hash; it must match. (Rebuild is
  byte-deterministic given the same Node + esbuild versions in the lockfile.)

## No-network gate

`test/no-network.test.ts` sabotages every network primitive (`fetch`, `http(s).request`,
`net.connect`, `dns.lookup`) and asserts a full Layer-1 + Layer-2 verification still
completes, then asserts `package.json` declares zero HTTP/network dependencies. The
**runtime** sabotage is the real defense; the dependency check is the regression net.

---

## Golden vectors / fixtures

Ported from the app's `tests/unit/hmac-message.test.ts` (v1 + v2 HMAC vectors) and
the cross-suite `tests/fixtures/tsa/vector.json` chain-tip vector, **plus 5 new
court fixtures** (`fixtures/`, regenerate with `node test/build-fixtures.mjs` — all
offline, self-signed test TSA, no network):

| Fixture | Expectation |
|---------|-------------|
| `mixed-v1v2.json` (+ `mixed-token.der`/`mixed-ca.crt`) | mixed v1/v2 chain → `tsa: verified`, `chain: verified` |
| `tamper.json` | one `payloadCipher` byte flipped → `tsa: failed`, `chain: failed (HMAC_MISMATCH)` |
| `truncation.json` | last row dropped → `tsa: failed` |
| `empty.json` | zero rows → tip = 64 zeros, `tsa: unstamped` |
| `manifest-ok/` vs `manifest-bad/` | a flipped packaged byte → `manifest: failed` |

---

## MANIFEST schema (Court Package `META-INF/MANIFEST.json`)

`package_hash` is computed over the **sorted `(path, sha256)` tuples — NOT raw ZIP
bytes** (so it's reproducible across zip libraries / compression / timestamps). The
`mimetype` entry and the MANIFEST file itself are excluded from both the file list
and the package hash.

```json
{
  "layout": "asic-e-style",
  "tsa_qualified": false,
  "chain_tip_composition": "H_i = SHA256(H_{i-1} + '|' + payloadCipher + '|' + routingHmac); genesis = 64 zero chars",
  "canonical_spec_present": "jcs-rfc8785-v2",
  "hash_algo": "sha256",
  "files": { "report/a.txt": "<sha256>", "...": "..." },
  "package_hash": "<sha256 over sorted (path,sha256) tuples>"
}
```

`layout: "asic-e-style"` and `tsa_qualified: false` are **honest by construction** —
this is an ASiC-E-*style* layout, **not** a qualified ASiC-E container, and the
timestamp is a standard RFC 3161 token, not an eIDAS-qualified one.

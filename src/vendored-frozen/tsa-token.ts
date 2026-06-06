/**
 * ============================================================================
 * VENDORED FROZEN LEAF — DO NOT EDIT BY HAND.
 *
 * Verbatim copy of casenotes-saas `apps/web/lib/tsa-token.ts`.
 * Pinned to source content-hash (sha256):
 *   367a456153e3df437d538ad86919df0e2010368169d42924876e4893dc9794a3
 *
 * SAFE to vendor: the RFC 3161 messageImprint encoding (OCTET STRING
 * `04 20 || SHA256(rawTip)`) is a fixed wire format, not a mutable algorithm.
 * This is the BROWSER-SAFE honesty gate (no openssl); the authoritative
 * signature/CA-chain/genTime check is the CLI (`verifyExport`).
 * ============================================================================
 *
 * Browser-side TSA token verification (footer half).
 *
 * Verify by a precise, spoof-resistant containment check:
 *   messageImprint = SHA-256(the 32 RAW tip bytes) = SHA256(hexDecode(tipHex))
 *   In the DER token the hashedMessage is encoded as an OCTET STRING:
 *     0x04 0x20 <32 imprint bytes>
 *   A token that genuinely timestamps OUR tip MUST contain that exact 34-byte
 *   sequence. Fail-closed: any decode/parse problem returns false.
 */

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function indexOfSubarray(haystack: Uint8Array, needle: Uint8Array): number {
  if (needle.length === 0 || haystack.length < needle.length) return -1;
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/** The pinned messageImprint for a chain tip: SHA-256 of the 32 RAW tip bytes. */
export async function messageImprintForTip(tipHex: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', hexToBytes(tipHex) as unknown as BufferSource);
  return new Uint8Array(digest);
}

/**
 * True iff the base64 DER token contains an OCTET STRING holding exactly the
 * messageImprint of `tipHex` — i.e. it attests this tip. Fail-closed on any
 * malformed input or non-64-hex tip.
 */
export async function tokenAttestsTip(tokenBase64: string, tipHex: string): Promise<boolean> {
  if (!/^[0-9a-f]{64}$/.test(tipHex)) return false;
  let token: Uint8Array;
  try {
    token = base64ToBytes(tokenBase64);
  } catch {
    return false;
  }
  if (token.length === 0) return false;
  const imprint = await messageImprintForTip(tipHex);
  const needle = new Uint8Array(2 + imprint.length);
  needle[0] = 0x04; // OCTET STRING tag
  needle[1] = 0x20; // length 32
  needle.set(imprint, 2);
  return indexOfSubarray(token, needle) !== -1;
}

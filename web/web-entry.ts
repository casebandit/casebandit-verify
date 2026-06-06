/**
 * esbuild IIFE entry for `verify.html`. Exposes the keyless web core on
 * `window.casebanditVerify` so the inline page script (CSP-restricted, no inline
 * <script> with logic beyond a tiny bootstrap) can call it. Bundled offline:
 *   esbuild web/web-entry.ts --bundle --format=iife --global-name=__cbv
 */
import { verifyKeylessWeb, type WebVerifyInput } from '../src/core/web-core.ts';

declare global {
  interface Window {
    casebanditVerify: {
      verifyKeylessWeb: (input: WebVerifyInput) => ReturnType<typeof verifyKeylessWeb>;
    };
  }
}

window.casebanditVerify = { verifyKeylessWeb };

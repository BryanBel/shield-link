// @ts-check
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { defineConfig, passthroughImageService } from 'astro/config';

import vercel from '@astrojs/vercel';

/**
 * Astro hashes the scripts it bundles, but not `is:inline` ones. The layout has exactly one
 * — the few lines that apply the saved style before first paint — so its hash is computed
 * here from the file itself, on every build. Editing that script can never leave the policy
 * pointing at a stale hash and the page with an unstyled flash.
 */
const layout = readFileSync(new URL('./src/layouts/Layout.astro', import.meta.url), 'utf8');
const scriptEnLinea = layout.match(/<script is:inline>([\s\S]*?)<\/script>/)?.[1];
if (!scriptEnLinea) throw new Error('Layout.astro: no se encontró el script is:inline que la CSP debe permitir');
const hashScriptEnLinea = `sha256-${createHash('sha256').update(scriptEnLinea).digest('base64')}`;

// https://astro.build/config
export default defineConfig({
  // A fresh analysis visits the link, follows its redirects and queries three registries.
  // Each step has its own timeout and the worst case stays near 12 s; this is the ceiling.
  adapter: vercel({ maxDuration: 15 }),

  // The site ships no images, but an SSR build still exposes Astro's /_image optimisation
  // endpoint. Backed by sharp — which is not installed — it answered every request with a
  // 500 carrying the internal error message. Passthrough serves local files untouched and
  // never loads an image processor, so there is nothing left to fail or to exploit.
  image: { service: passthroughImageService() },

  // No Markdown here, so no code blocks to highlight. Shiki's inline styles cannot pass the
  // CSP below, and left enabled it warns on every build.
  markdown: { syntaxHighlight: false },

  security: {
    // A Content-Security-Policy with a hash for every script and style Astro emits, so the
    // page runs only the code it was built with. Everything else is limited to this origin:
    // the page fetches nothing but /api/scan and loads nothing from elsewhere. It is
    // delivered as a <meta> tag; the directives a meta tag cannot carry, such as
    // frame-ancestors, are set as headers in vercel.json.
    csp: {
      directives: [
        "default-src 'self'",
        "connect-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
      ],
      scriptDirective: { hashes: [/** @type {`sha256-${string}`} */ (hashScriptEnLinea)] },
    },
  },
});

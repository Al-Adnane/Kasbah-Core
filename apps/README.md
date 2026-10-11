# apps/ — placeholders (not shipped)

These are scaffolding, not built applications (audit B8):

- `web/` — a Next.js shell (config + a `lib/kasbah.ts` API helper). **No pages.**
- `mobile/` — Expo config only. **No entry source**; `App.tsx` does not exist.
- `shared/kasbah-client.js` — the one real artefact here; a small fetch client.

The shipping client is the Electron app in `packages/desktop/`. Treat these as
placeholders and remove them, or build them out — do not present them as products.

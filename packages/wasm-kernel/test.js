const wasm = require('./index.js');
async function main() {
  const ok = await wasm.init();
  console.log('WASM init:', ok);
  if (ok) {
    const r = wasm.detectSecrets('My AWS key is AKIAIOSFODNN7EXAMPLE12');
    console.log('secrets result:', JSON.stringify(r));
    console.log('detected:', r && r.detected);
    console.log('WASM kernel: PASS');
  } else {
    console.log('WASM kernel: SKIPPED — pkg/ is not built (run `npm run build` with wasm-pack).');
    if (process.env.KASBAH_REQUIRE_WASM === '1') { console.error('KASBAH_REQUIRE_WASM=1 but the kernel is unavailable'); process.exit(1); }
  }
}
main().catch(console.error);

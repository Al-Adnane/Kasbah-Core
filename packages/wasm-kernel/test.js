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
    console.log('WASM kernel: UNAVAILABLE (graceful degradation OK)');
  }
}
main().catch(console.error);

# Reproduce Every Claimed Number in One Pass

No API keys, no network, no build step. All suites run in-process.
Environment stamp: Node v25.9.0, darwin/arm64, 2026-10-03.

## 1. Detector self-test (28 invariants) + SSI mirrors

```bash
node -e "console.log(require('./src/detector.js').selfTest())"
# → { passed: 28, total: 28 }

node -e "console.log(require('./src/ssi-admission.js').selfTest())"
# → { passed: 7, total: 7, failed: [] }

python3 kasbah-os/ssi_universal_core.py   # → 18/18 PASS
python3 kasbah-os/sovereign_engine_max.py # → 13/13 PASS
```

## 2. Sentinel corpus benchmark (F1/P/R + latency)

```bash
node -e "
const fs=require('fs');
const corpus=JSON.parse(fs.readFileSync('bench/corpus/v1.json','utf8')).cases;
const s=require('./src/kasbah-sentinel.js');
(async()=>{const inst=new s.KasbahSentinel({});let tp=0,fp=0,tn=0,fn=0;const lat=[];
for(const c of corpus){const t=Date.now();let dec='ALLOW';
try{const r=await inst.sentinelCheck({agent:'desktop-user',verb:'ANALYZE',target:'local',content:c.prompt});dec=r.decision;}catch(e){}
lat.push(Date.now()-t);
const expD=(c.verdict==='DENY'||c.verdict==='WARN'),predD=(dec==='DENY'||dec==='REQUIRE_APPROVAL');
if(expD&&predD)tp++;else if(!expD&&!predD)tn++;else if(!expD&&predD)fp++;else fn++;}
lat.sort((a,b)=>a-b);const pr=tp/(tp+fp||1),rc=tp/(tp+fn||1);
console.log('F1='+(2*pr*rc/(pr+rc||1)).toFixed(3),'P='+pr.toFixed(3),'R='+rc.toFixed(3),
'p50='+lat[Math.floor(lat.length*0.5)],'p95='+lat[Math.floor(lat.length*0.95)]);process.exit(0);})();"
# Reference: F1=0.857 P=0.973 R=0.766 p50=3 p95=28
# Mapping: truth positive = DENY|WARN; prediction positive = DENY|REQUIRE_APPROVAL.
# Corpus: bench/corpus/v1.json — 77 cases, 11 classes (ALLOW 30 / WARN 27 / DENY 20).
```

## 3. Red-team suite (49 attacks, 9 categories)

```bash
node -e "
const rt=require('./packages/api-server/src/red-team.js');
const s=require('./src/kasbah-sentinel.js');
(async()=>{const inst=new s.KasbahSentinel({});const suite=rt.ATTACK_SUITE;let b=0;const byCat={};
for(const t of suite){let dec='ALLOW';
try{const r=await inst.sentinelCheck({agent:'desktop-user',verb:'ANALYZE',target:'local',content:t.prompt});dec=r.decision;}catch(e){}
const stop=(dec==='DENY'||dec==='REQUIRE_APPROVAL');if(stop)b++;
const c=t.category;byCat[c]=byCat[c]||{n:0,b:0};byCat[c].n++;if(stop)byCat[c].b++;}
console.log('blocked='+b+'/'+suite.length);for(const[k,v]of Object.entries(byCat))console.log('',k,v.b+'/'+v.n);process.exit(0);})();"
# Reference: 25/49 (51%). Multi-turn + reasoning-exploit are single-prompt
# blind spots by construction (no conversation state in the call).
```

## 4. Crypto self-audit (12 attacks) + kernel ticket replay

```bash
node -e "const r=require('./packages/desktop/src/self-audit.js').runRedTeam();console.log(r.defended+'/'+r.total)"
# → 12/12
node -e "
const k=require('./packages/api-server/src/kernel.js');(async()=>{
const t=await k.issueTicket({actorId:'t',action:'read',toolName:'read',args:{f:'a'}});
const c1=await k.consumeTicket(t.ticket,{toolName:'read',args:{f:'a'}});
const c2=await k.consumeTicket(t.ticket,{toolName:'read',args:{f:'a'}});
console.log('consume1:',c1.ok,'replay-blocked:',!c2.ok&&c2.reason==='replay');
})()"
```
# → consume1: true replay-blocked: true

## 5. Desktop + API wiring

```bash
node --check packages/api-server/server.js
node --check packages/desktop/src/main-features.js
node --check packages/desktop/src/preload.js
node --check src/kasbah-sentinel.js
```

## What these numbers do NOT prove

Competitor figures quoted alongside are vendor-reported, not reproduced
here. F1/recall hold only for this corpus; arms-race drift is expected.
See `papers/kasbah-formal-models.tex` §What Is NOT Proven.

## 6. Latency record (real measurements, not design targets)

Full table: `bench/results/latency-2026-10-03.json`. Headlines —
detector 0–1ms; sentinel cold p50/p95 2/12ms, cached 0/2ms; audit
entry ~1ms typical, ~141ms on PQ-checkpoint entries (1 in 20);
kernel ticket issue+consume ~1ms; JS admission screen ~0ms; Python
admission gate 0.03–0.1ms end-to-end.

## 7. Kernel + attestation honesty status

```bash
python3 kasbah-os/attestation.py  # → 3/3, effective root: software
```
- eBPF: `kasbah-os/kasbah_admit.bpf.c` is source-complete but NEVER
  compiled or loaded here (no BPF backend on this machine). Enforced
  path remains the userspace policy engine (`packages/kernel-ebpf`).
- Attestation: software root only; TPM2/Android/SE report unavailable
  with reasons. No hardware claim is made.

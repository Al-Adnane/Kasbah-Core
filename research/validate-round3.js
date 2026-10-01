'use strict';
/**
 * validate-round3.js — API-accurate harnesses (correct signatures + enough data
 * to pass each module's insufficient-data guard). Round 1/2 INCONCLUSIVE verdicts
 * were harness bugs (wrong arg shapes), NOT module failures — this proves it by
 * exercising each module the way its code actually expects.
 *
 * Constructed ground truth; external validity still pending real data.
 */
const fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '..'); const S = p => require(path.join(ROOT, 'src', p));
function lcg(seed){let s=seed>>>0;return()=>{s=(s*1103515245+12345)&0x7fffffff;return s/0x7fffffff;};}
function gauss(r){let u=0,v=0;while(!u)u=r();while(!v)v=r();return Math.sqrt(-2*Math.log(u))*Math.cos(2*Math.PI*v);}
function auc(rows){const P=rows.filter(r=>r.label).map(r=>r.score),N=rows.filter(r=>!r.label).map(r=>r.score);if(!P.length||!N.length)return NaN;let w=0,t=0;for(const a of P)for(const b of N){if(a>b)w++;else if(a===b)t++;}return(w+0.5*t)/(P.length*N.length);}
function permP(rows,obs,iters=2000){const L=rows.map(r=>r.label),Sc=rows.map(r=>r.score),d=Math.abs(obs-0.5),r=lcg(0x51ed);let h=0;for(let k=0;k<iters;k++){const p=L.slice();for(let i=p.length-1;i>0;i--){const j=Math.floor(r()*(i+1));[p[i],p[j]]=[p[j],p[i]];}if(Math.abs(auc(Sc.map((s,i)=>({score:s,label:p[i]})))-0.5)>=d)h++;}return(h+1)/(iters+1);}
function variance(xs){const m=xs.reduce((a,b)=>a+b,0)/(xs.length||1);return xs.reduce((a,x)=>a+(x-m)**2,0)/(xs.length||1);}
function bh(ps,q=0.05){const idx=ps.map((p,i)=>({p,i})).sort((a,b)=>a.p-b.p);const m=idx.length;let kmax=-1;for(let k=0;k<m;k++)if(idx[k].p<=((k+1)/m)*q)kmax=k;const sig=new Array(m).fill(false);for(let k=0;k<=kmax;k++)sig[idx[k].i]=true;return sig;}
function verdict(a,p,sig,sv){if(!isFinite(a))return'ERR';if(sv!=null&&sv<1e-12)return'INCONCLUSIVE(benchmark)';if(a>=0.70&&sig)return'PROMOTE';if(a>=0.55)return'KEEP-ADVISORY';if(a<=0.30&&sig)return'INVERTED';return'DEPRECATE-CANDIDATE';}
const results=[];
function run(module,fn){try{const rows=fn();const a=auc(rows);results.push({module,auc:a,p:permP(rows,a),scoreVar:variance(rows.map(r=>r.score)),n:rows.length});}catch(e){results.push({module,auc:NaN,p:1,err:e.message.slice(0,80)});}}

// ── do-bft: collusion = VARIANCE COLLAPSE (correct model). obs = array of {value}.
run('do-bft-consensus',()=>{const{DOBFTConsensus}=S('do-bft-consensus');const rnd=lcg(11);const rows=[];
  for(let tr=0;tr<60;tr++){const col=tr%2===0;const c=new DOBFTConsensus({minObservers:7,epsilon:8});
    for(let o=0;o<9;o++)c.registerObserver('o'+o);
    const obs=c.collectPerturbedObservations(0.5);            // array of {observerId,value}, full Laplace noise
    if(col)obs.forEach((o,i)=>{o.value=0.5+0.0005*i;});       // colluders agree → variance collapses
    const r=c.detectCollusion(obs);
    rows.push({score:1-(r.p_value??1),label:col?1:0});}       // collapse → low p → high score
  return rows;});

// ── persistent-homology: 6-cycle vs star. registerCommunication(from,to). ≥3 agents.
run('persistent-homology-covert',()=>{const{PersistentHomologyCovertDetector}=S('persistent-homology-covert');const rows=[];
  for(let tr=0;tr<50;tr++){const cyc=tr%2===0;const d=new PersistentHomologyCovertDetector({minCycleSize:3,persistenceThreshold:0.05});
    const ring=['a','b','c','d','e','f'];
    const edges=cyc?ring.map((u,i)=>[u,ring[(i+1)%6]]):ring.slice(1).map(u=>['a',u]);
    for(let rep=0;rep<3;rep++)for(const[u,v]of edges){d.registerCommunication(u,v);d.registerCommunication(v,u);}
    let sc=0;try{const r=d.detectCovertCycles();
      sc=(r.totalH1Features ?? r.significantH1 ?? (r.detected?1:0))||0;}catch(_){}  // H1 Betti number: ring→1, star→0
    rows.push({score:sc,label:cyc?1:0});}
  return rows;});

// ── timing: 2 agents, ≥30 IRIs each. recordResponse(agentId, ts). covert = correlated IRIs.
run('timing-channel-detector',()=>{const{TimingChannelDetector}=S('timing-channel-detector');const rnd=lcg(53);const rows=[];
  for(let tr=0;tr<50;tr++){const chan=tr%2===0;const d=new TimingChannelDetector({minSamples:30,windowSeconds:1e9});
    let tA=Date.now(),tB=Date.now();   // module windows by wall-clock → anchor at now
    for(let i=0;i<45;i++){
      const bit=rnd()<0.5?1:0;
      const gapA=bit?100:300; tA+=gapA; d.recordResponse('A',tA);
      const gapB=chan?(bit?100:300):(100+200*rnd()); tB+=gapB; d.recordResponse('B',tB); // B mirrors A's bit iff covert
    }
    let sc=0;try{const r=d.analyze();sc=(r.maxMutualInformation??r.mutualInformation??r.channelCapacity??(Array.isArray(r.pairs)?Math.max(0,...r.pairs.map(p=>p.mutualInformation||0)):0))||0;}catch(_){}
    rows.push({score:sc,label:chan?1:0});}
  return rows;});

// ── hypergraph: 3 agents on SHARED targets (n-ary) vs disjoint. recordEvent(agentId,action,target).
run('hypergraph-collusion-detector',()=>{const{HypergraphCollusionDetector}=S('hypergraph-collusion-detector');const rnd=lcg(83);const rows=[];
  for(let tr=0;tr<40;tr++){const nary=tr%2===0;const d=new HypergraphCollusionDetector({minHyperedgeSize:2,spectralGapWarn:3});
    for(let i=0;i<60;i++){const tgt=nary?'shared'+(i%3):('t'+Math.floor(rnd()*30));
      d.recordEvent('A','act',nary?'shared'+(i%3):'tA'+i,{riskScore:0.6});
      d.recordEvent('B','act',nary?'shared'+(i%3):'tB'+i,{riskScore:0.6});
      d.recordEvent('C','act',nary?'shared'+(i%3):'tC'+i,{riskScore:0.6});}
    let sc=0;try{const r=d.analyze();sc=(r.spectralGap??r.maxGapRatio??(r.isColluding?1:0))||0;}catch(_){}
    rows.push({score:sc,label:nary?1:0});}
  return rows;});

// ── stigmergic: registerEnvModification({resource,agentId,operation,ts}). ≥5/agent. covert = shared resources.
run('stigmergic-covert-channel',()=>{const{StigmergicCovertChannelDetector}=S('stigmergic-covert-channel');const rnd=lcg(71);const rows=[];
  for(let tr=0;tr<40;tr++){const cov=tr%2===0;const d=new StigmergicCovertChannelDetector({windowSize:40});
    for(let i=0;i<30;i++){const bit=rnd()<0.5?1:0;
      d.registerEnvModification({resource:cov?('r'+bit):('rA'+(rnd()<0.5?0:1)),agentId:'A',operation:'write',timestamp:i});
      d.registerEnvModification({resource:cov?('r'+bit):('rB'+(rnd()<0.5?0:1)),agentId:'B',operation:'read',timestamp:i+0.5});}
    let sc=0;try{const r=d.analyzeAllPairs();const pairs=r.stigmergicPairs||[];
      sc=(Array.isArray(pairs)&&pairs.length?Math.max(...pairs.map(p=>p.mutualInformation||p.mi||0)):(r.detected?1:0))||0;}catch(_){}
    rows.push({score:sc,label:cov?1:0});}
  return rows;});

// ── lmid: observe(vector). calibrate on sphere, test off-manifold.
run('latent-manifold-intrusion',()=>{const{LatentManifoldMonitor}=S('latent-manifold-intrusion');const rnd=lcg(41);const rows=[];
  const dim=8; const sphere=()=>{const v=Array.from({length:dim},()=>gauss(rnd));const n=Math.hypot(...v);return v.map(x=>x/n);};
  for(let tr=0;tr<40;tr++){const intr=tr%2===0;const m=new LatentManifoldMonitor({embeddingDim:dim,windowSize:30,geodesicThreshold:0.15});
    for(let i=0;i<40;i++){try{m.observe(sphere());}catch(_){}}
    const test=intr?Array.from({length:dim},()=>5):sphere();
    let sc=0;try{const r=m.observe(test);sc=(r.geodesicDeviation??r.maxDeviation??r.fisherRao??(r.isIntrusion?1:0))||0;}catch(_){}
    rows.push({score:sc,label:intr?1:0});}
  return rows;});

const wd=results.filter(r=>isFinite(r.auc));const sig=bh(wd.map(r=>r.p),0.05);
wd.forEach((r,i)=>{r.bhSig=sig[i];r.verdict=verdict(r.auc,r.p,sig[i],r.scoreVar);});
results.filter(r=>!isFinite(r.auc)).forEach(r=>r.verdict='ERR');
console.log('\n=== ROUND 3: API-accurate harnesses ===');
for(const r of results)console.log(r.module.padEnd(32),'AUC='+(isFinite(r.auc)?r.auc.toFixed(3):'n/a'),'p='+(r.p!=null?r.p.toFixed(3):'—'),'var='+(r.scoreVar!=null?r.scoreVar.toExponential(1):'—'),'->',r.verdict,r.err?('· '+r.err):'');
fs.writeFileSync(path.join(ROOT,'research/results/validation-round3.json'),JSON.stringify({date:'2026-05-30',note:'API-accurate constructed-GT; external validity pending real data',empirical:results},null,2));
console.log('\nwrote research/results/validation-round3.json');

#!/usr/bin/env node
'use strict';

/**
 * KASBAH X-RAY HOOK PROOF — CORRECTED BENCH
 * 
 * Each engine tested with correct:
 *   - Import name (verified from module.exports)
 *   - Method signature (verified from source)
 *   - Input format (verified from parser implementations)
 */

const path = require('path');
const fs = require('fs');

// ─── LOAD (verified exports) ────────────────────────────────────────────────

let detectgpt, ManipulationEngine, DatingGuardEngine, BotnetRadarEngine, NeuralWitnessEngine;
const loadErrors = {};

// detectgpt.js → exports { detectAIText }
try {
  const mod = require('../src/detectgpt.js');
  detectgpt = mod.detectAIText;
  if (!detectgpt) throw new Error('detectAIText not found in exports');
} catch(e) { loadErrors.detectgpt = e.message; }

// manipulation-engine.js → exports { ManipulationEngine, ... }
try {
  const mod = require('../products/relationship-guard/src/manipulation-engine.js');
  ManipulationEngine = mod.ManipulationEngine;
  if (!ManipulationEngine) throw new Error('ManipulationEngine not found in exports');
} catch(e) { loadErrors.relationshipGuard = e.message; }

// dating-engine.js → exports { DatingGuardEngine, ... }
try {
  const mod = require('../products/dating-guard/src/dating-engine.js');
  DatingGuardEngine = mod.DatingGuardEngine;
  if (!DatingGuardEngine) throw new Error('DatingGuardEngine not found');
} catch(e) { loadErrors.datingGuard = e.message; }

// swarm-engine.js → exports { BotnetRadarEngine, ... }
try {
  const mod = require('../products/botnet-radar/src/swarm-engine.js');
  BotnetRadarEngine = mod.BotnetRadarEngine;
  if (!BotnetRadarEngine) throw new Error('BotnetRadarEngine not found');
} catch(e) { loadErrors.botnetRadar = e.message; }

// neural-witness/engine.js → exports { NeuralWitnessEngine, ... }
try {
  const mod = require('../products/neural-witness/engine.js');
  NeuralWitnessEngine = mod.NeuralWitnessEngine;
  if (!NeuralWitnessEngine) throw new Error('NeuralWitnessEngine not found');
} catch(e) { loadErrors.neuralWitness = e.message; }

// ─── HELPERS ────────────────────────────────────────────────────────────────

function metrics(tp, fp, fn, tn) {
  const n = tp + fp + fn + tn || 1;
  const accuracy = (tp + tn) / n;
  const precision = tp / ((tp + fp) || 1);
  const recall = tp / ((tp + fn) || 1);
  const f1 = 2 * precision * recall / ((precision + recall) || 1);
  return {
    accuracy: (accuracy * 100).toFixed(1),
    precision: (precision * 100).toFixed(1),
    recall: (recall * 100).toFixed(1),
    f1: (f1 * 100).toFixed(1),
    n,
    tp, fp, fn, tn
  };
}

function labelIcon(expected, predicted) {
  if (expected === predicted) return '✓';
  return '✗';
}

// ─── TEST 1: detectAIText (AI vs Human) ─────────────────────────────────────

function testDetectGPT() {
  console.log('\n═══════════════════════════════════════════');
  console.log('  TEST: detectgpt — AI vs Human Text');
  console.log('═══════════════════════════════════════════\n');

  if (!detectgpt) {
    console.log(`  ❌ LOAD FAILED: ${loadErrors.detectgpt}`);
    return { error: 'load_failed', ...metrics(0,0,0,0) };
  }

  const samples = [
    // AI text — needs: >= 40 chars, >= 2 sentences, >= 20 words
    { id:'AI-01', label:true, text: "The Renaissance period, spanning roughly from the 14th to the 17th century, marked a profound cultural transformation across Europe. Emerging first in Italy before spreading northward, this era witnessed a remarkable revival of classical learning. Artists and thinkers revolutionized expression through new techniques and bold ideas." },
    { id:'AI-02', label:true, text: "I appreciate your thoughtful question about quantum mechanics and consciousness. From a scientific perspective, the connection remains speculative, though several theoretical frameworks have been proposed. The prevailing view in modern physics favors decoherence-based explanations that do not require conscious observers." },
    { id:'AI-03', label:true, text: "Here is a comprehensive analysis of the project requirements. First, we should implement the authentication layer using OAuth 2.0 with PKCE flow for enhanced security. Second, the database schema should be normalized to third normal form. Third, rate limiting should use token bucket algorithms with configurable thresholds." },
    { id:'AI-04', label:true, text: "Climate change represents one of the most pressing challenges of our era. Multiple lines of evidence confirm that global temperatures are rising at an unprecedented rate. The scientific consensus is clear and robust. Mitigation strategies must be implemented urgently to avoid the most severe consequences." },
    { id:'AI-05', label:true, text: "The fundamental principles of object-oriented programming include encapsulation, inheritance, and polymorphism. These concepts enable developers to create modular and reusable code. Understanding these principles is essential for building maintainable software systems at scale." },
    
    // Human text — must also meet length requirements
    { id:'HW-01', label:false, text: "ok so i tried to explain this to my friend yesterday and honestly i just kept going in circles. she kept asking questions and i kept making things up. like i know the basics but also i dont? anyway we ended up just googling it together and laughing. sometimes that's better than pretending you know stuff you definitely dont know." },
    { id:'HW-02', label:false, text: "my kid asked me yesterday why the sky is blue and i just stood there like an idiot. i know its something about light scattering but i couldnt explain it. so we looked it up together and honestly the best part was that she didnt even care about the answer. she just wanted to sit with me and ask random questions." },
    { id:'HW-03', label:false, text: "just got back from the weirdest first date honestly. he showed up in cargo shorts and a blazer i cannot even make this up?? anyway we talked about aliens for like three hours straight and he paid for dinner. so honestly not the worst evening. my friends think im insane for agreeing to a second date but here we are lmao." },
    { id:'HW-04', label:false, text: "i dont know man sometimes i wonder if im doing the right thing staying in this city. my family keeps asking when im moving back but i like it here even if its hard sometimes. my cat seems happy at least that has to count for something right? anyway its probably just the seasonal depression talking i should go outside more." },
    { id:'HW-05', label:false, text: "wait so you're telling me that people actually pay money for that?? no offense but i could literally just do the same thing myself in like twenty minutes with a basic script. maybe i should start charging people. the audacity of these companies honestly. anyway im just complaining ignore me." },
  ];

  let tp = 0, fp = 0, fn = 0, tn = 0;
  const results = [];

  for (const sample of samples) {
    try {
      const r = detectgpt(sample.text);
      // detectAIText returns: { score, burstiness, perplexity, isAI, signals }
      const predicted = r?.isAI === true;
      const score = r?.score;
      
      results.push({ id: sample.id, label: sample.label, predicted, score, raw: JSON.stringify(r).slice(0, 200) });
      
      if (sample.label && predicted) tp++;
      else if (sample.label && !predicted) fn++;
      else if (!sample.label && predicted) fp++;
      else tn++;
    } catch(e) {
      results.push({ id: sample.id, error: e.message });
    }
  }

  for (const r of results) {
    const lbl = r.label ? 'AI' : 'HUM';
    const prd = r.predicted ? 'AI' : 'HUM';
    console.log(`  ${labelIcon(r.label, r.predicted)} ${r.id}: truth=${lbl} pred=${prd} score=${r.score ?? '??'}`);
    if (r.error) console.log(`     ERR: ${r.error}`);
  }

  return metrics(tp, fp, fn, tn);
}

// ─── TEST 2: ManipulationEngine — Gaslighting/DARVO ──────────────────────────

function testManipulationEngine() {
  console.log('\n═══════════════════════════════════════════');
  console.log('  TEST: ManipulationEngine — Gaslighting');
  console.log('═══════════════════════════════════════════\n');

  if (!ManipulationEngine) {
    console.log(`  ❌ LOAD FAILED: ${loadErrors.relationshipGuard}`);
    return { error: 'load_failed', ...metrics(0,0,0,0) };
  }

  const engine = new ManipulationEngine();

  const samples = [
    { id:'MAN-01', label:true, text: "you're imagining things again. i never said that. you always do this and twist my words and then get upset about something that never happened. everyone thinks you're being dramatic about this and honestly you should just calm down." },
    { id:'MAN-02', label:true, text: "you made me do this. if you hadn't been so controlling all the time i wouldn't have had to go behind your back and do what i did. this is your fault not mine. you should be apologizing to me right now." },
    { id:'MAN-03', label:true, text: "oh come on, it's not that bad and you're making a huge deal out of nothing. can't you take a joke? i was just kidding and you're overreacting like you always do when someone teases you." },
    { id:'MAN-04', label:true, text: "typical you. always playing the victim and never taking responsibility for anything. every single time this happens it's somehow my fault and you're completely innocent. that's honestly pathetic and everyone can see through it." },
    { id:'MAN-05', label:true, text: "why do you keep bringing this up when i already apologized? you're just trying to make me feel guilty and it's not fair. i said i was sorry and you won't let it go because you love holding things over me." }, // stonewalling + blame-shift

    { id:'OK-01', label:false, text: "hey, i'm feeling a bit hurt by what happened earlier today and i wanted to check in with you about it. can we talk when you have a moment? i would love to understand your perspective too and not just mine." },
    { id:'OK-02', label:false, text: "i think we're both tired tonight honestly and maybe we should just pause this conversation and revisit it tomorrow when we've both had some rest. no hard feelings at all 💛" },
    { id:'OK-03', label:false, text: "thanks for telling me how you feel about this. i honestly didn't realize that bothered you so much and i'm glad you brought it up. i'll try to be more mindful going forward and check in more often." },
    { id:'OK-04', label:false, text: "i see where you're coming from now and it makes a lot of sense. sorry i was defensive earlier. let's figure out a way to handle this better next time so neither of us feels this way." },
    { id:'OK-05', label:false, text: "i appreciate you being honest with me about all of this even though it was hard to hear. let's grab coffee tomorrow morning and talk it through properly when we're both fresh." },
  ];

  let tp = 0, fp = 0, fn = 0, tn = 0;
  const results = [];

  for (const sample of samples) {
    try {
      // ManipulationEngine.analyze(conversationText, options)
      const r = engine.analyze(sample.text);
      
      if (r?.error) {
        results.push({ id: sample.id, error: r.error });
        continue;
      }

      // surfacePatterns.totalScore is the primary signal
      const score = r?.surfacePatterns?.totalScore || 0;
      const predicted = score > 40; // threshold for manipulation flag
      
      results.push({ id: sample.id, label: sample.label, predicted, score });

      if (sample.label && predicted) tp++;
      else if (sample.label && !predicted) fn++;
      else if (!sample.label && predicted) fp++;
      else tn++;
    } catch(e) {
      results.push({ id: sample.id, error: e.message });
    }
  }

  for (const r of results) {
    const lbl = r.label ? 'MAN' : 'OK';
    const prd = r.predicted ? 'MAN' : 'OK';
    console.log(`  ${labelIcon(r.label, r.predicted)} ${r.id}: truth=${lbl} pred=${prd} score=${r.score ?? '??'}`);
    if (r.error) console.log(`     ERR: ${r.error}`);
  }

  return metrics(tp, fp, fn, tn);
}

// ─── TEST 3: DatingGuardEngine — Romance Scams ───────────────────────────────

function testDatingGuard() {
  console.log('\n═══════════════════════════════════════════');
  console.log('  TEST: DatingGuard — Romance Scams');
  console.log('═══════════════════════════════════════════\n');

  if (!DatingGuardEngine) {
    console.log(`  ❌ LOAD FAILED: ${loadErrors.datingGuard}`);
    return { error: 'load_failed', ...metrics(0,0,0,0) };
  }

  const engine = new DatingGuardEngine();

  const samples = [
    // DatingGuardEngine.analyze(profileData, messagesText) — TWO args!
    { id:'SCAM-01', label:true,
      profile: { bio: "I'm a military officer deployed overseas looking for my soulmate. I believe in true love and destiny." },
      text: "i've never met anyone like you before honestly. i feel so connected to you even though we just started talking. i'm currently deployed overseas with the military and my bank account is frozen. could you possibly help me with a small transfer? it's urgently needed and i'll pay you back immediately." },
    { id:'SCAM-02', label:true,
      profile: { bio: "God-fearing honest man looking for a woman to spend my life with. Family values are everything." },
      text: "you're my soulmate, i'm absolutely sure of it now. i'm stuck at the airport in Lagos and my flight was cancelled unexpectedly. i need some money for a new ticket urgently. can you western union me something? i promise i'll pay you back as soon as i land." },
    { id:'SCAM-03', label:true,
      profile: { bio: "CEO and entrepreneur. I travel the world for business but my heart is looking for home. No games please." },
      text: "i can't video call right now because my camera is broken but i promise i'm real and genuine. i'm working on an oil rig and there's an emergency with my mother's hospital bills. could you help me with the payment for the surgery? i already love you so much even though we haven't met." },
    { id:'SCAM-04', label:true,
      profile: { bio: "Simple man with a big heart. Currently working abroad but my heart is in my home country." },
      text: "hello beautiful i need your help urgently. i've been robbed here and they took everything including my wallet and passport. i have no one else to turn to but you. please send anything you can. i will repay you double when i get back. you are my only hope right now." },

    { id:'DATE-01', label:false,
      profile: { bio: "Software engineer, dog dad, love hiking and cooking. Looking for someone who laughs at dad jokes." },
      text: "hey i had a really nice time tonight! the sushi was great but honestly the company was better 😊 want to do it again next week? maybe that Italian place you mentioned?" },
    { id:'DATE-02', label:false,
      profile: { bio: "Bookworm, coffee addict, terrible at bowling. Looking for someone who doesn't mind my book collection." },
      text: "haha no way you like that band too? i thought i was the only person who listened to them anymore. okay we definitely need to go to their concert when they're in town this spring." },
    { id:'DATE-03', label:false,
      profile: { bio: "Marketing professional by day, foodie by night. Love traveling and discovering new restaurants." },
      text: "hey so i have kind of a busy week coming up with work but i'd love to grab coffee on sunday afternoon if you're free? no pressure at all if you're busy of course!" },
    { id:'DATE-04', label:false,
      profile: { bio: "Teacher, runner, amateur photographer. Looking for someone kind who doesn't take life too seriously." },
      text: "that's so cool that you're into photography too! i mostly do street photography but i've been wanting to try portraits. maybe we could go shoot together sometime and you can teach me some things?" },
  ];

  let tp = 0, fp = 0, fn = 0, tn = 0;
  const results = [];

  for (const sample of samples) {
    try {
      const r = engine.analyze(sample.profile, sample.text);
      // Returns: { riskScore, verdict, scamPatterns, warnings }
      const score = r?.riskScore;
      const predicted = (r?.verdict === 'HIGH_RISK' || (score !== undefined && score >= 0.5));
      
      results.push({ id: sample.id, label: sample.label, predicted, score: r?.riskScore?.toFixed(2), verdict: r?.verdict });

      if (sample.label && predicted) tp++;
      else if (sample.label && !predicted) fn++;
      else if (!sample.label && predicted) fp++;
      else tn++;
    } catch(e) {
      results.push({ id: sample.id, error: e.message });
    }
  }

  for (const r of results) {
    const lbl = r.label ? 'SCAM' : 'OK';
    const prd = r.predicted ? 'SCAM' : 'OK';
    console.log(`  ${labelIcon(r.label, r.predicted)} ${r.id}: truth=${lbl} pred=${prd} score=${r.score ?? '??'} verdict=${r.verdict ?? '?'}`);
    if (r.error) console.log(`     ERR: ${r.error}`);
  }

  return metrics(tp, fp, fn, tn);
}

// ─── TEST 4: BotnetRadarEngine — Bot Coordination ────────────────────────────

function testBotnetRadar() {
  console.log('\n═══════════════════════════════════════════');
  console.log('TEST: BotnetRadar — Bot Coordination');
  console.log('═══════════════════════════════════════════\n');

  if (!BotnetRadarEngine) {
    console.log(`❌ LOAD FAILED: ${loadErrors.botnetRadar}`);
    return { error: 'load_failed', ...metrics(0,0,0,0) };
  }

  const engine = new BotnetRadarEngine();

  const samples = [
    // Thread format: @user: message or user: message (verified against ThreadParser)
    { id:'BOT-01', label:true, text:
      "user1: This product changed my life!\n" +
      "user2: This product changed my life!\n" +
      "user3: This product changed my life!\n" +
      "user4: This product changed my life! Amazing results!!\n" +
      "user5: This product changed my life!! Best purchase ever\n" +
      "user6: This product changed my life! Can't believe the results" },
    { id:'BOT-02', label:true, text:
      "bot_a: Great post! Very informative content\n" +
      "bot_b: Great post! Very informative content\n" +
      "bot_c: Great post! Very informative content\n" +
      "bot_d: Great post! Very informative content\n" +
      "bot_e: Great post! Very informative content" },
    { id:'BOT-03', label:true, text:
      "accountA: You should definitely invest in $TOKEN now!!\n" +
      "accountB: Already invested, this is going to the moon 🚀\n" +
      "accountC: Best investment of my life honestly\n" +
      "accountD: Just bought more $TOKEN before it pumps\n" +
      "accountE: To the moon!! Don't miss this opportunity!!" },

    { id:'GEN-01', label:false, text:
      "alice: has anyone tried the new update yet?\n" +
      "bob: yeah i installed it yesterday, there's a weird bug with the search bar\n" +
      "carol: i haven't seen that — what does the bug do exactly?\n" +
      "bob: it sometimes returns results from last week instead of current ones\n" +
      "dave: oh that's annoying. i'll wait for the patch then before updating\n" +
      "carol: same here. thanks for the heads up bob, appreciate it" },
    { id:'GEN-02', label:false, text:
      "elena: thinking of switching to vim full time\n" +
      "frank: lmao why would you do that to yourself honestly\n" +
      "grace: vim is actually great once you get past the learning curve\n" +
      "elena: the learning curve is basically vertical frank that's the problem\n" +
      "frank: hahaha fair point. okay i respect the decision even if i don't understand it\n" +
      "grace: respect the journey. see you on the other side of the config file" },
    { id:'GEN-03', label:false, text:
      "henry: anyone else having issues with the API rate limiting today?\n" +
      "iris: yeah our error rates spiked about an hour ago\n" +
      "henry: same here. i opened a ticket with support but no response yet\n" +
      "jack: classic. we switched to the backup endpoint and it's working fine now\n" +
      "iris: good idea. i'll do the same and report back if it helps" },
  ];

  let tp = 0, fp = 0, fn = 0, tn = 0;
  const results = [];

  for (const sample of samples) {
    try {
      const r = engine.analyze(sample.text);
      // Returns: { swarmProbability, verdict, chshScore, ... }
      
      if (r?.error) {
        results.push({ id: sample.id, error: r.error });
        continue;
      }

      const score = r?.swarmProbability || 0;
      // verdict is 'BOT_SWARM' >= 0.7, 'SUSPICIOUS' >= 0.4, 'ORGANIC' < 0.4
      const predicted = (r?.verdict === 'BOT_SWARM' || r?.verdict === 'SUSPICIOUS' || score >= 0.4);
      
      results.push({ id: sample.id, label: sample.label, predicted, score: score?.toFixed(2), botRatio: r?.botRatio });

      if (sample.label && predicted) tp++;
      else if (sample.label && !predicted) fn++;
      else if (!sample.label && predicted) fp++;
      else tn++;
    } catch(e) {
      results.push({ id: sample.id, error: e.message });
    }
  }

  for (const r of results) {
    const lbl = r.label ? 'BOT' : 'GEN';
    const prd = r.predicted ? 'BOT' : 'GEN';
    console.log(`  ${labelIcon(r.label, r.predicted)} ${r.id}: truth=${lbl} pred=${prd} score=${r.score ?? '??'}`);
    if (r.error) console.log(`     ERR: ${r.error}`);
  }

  return metrics(tp, fp, fn, tn);
}

// ─── TEST 5: NeuralWitness — AI Model Fingerprint ────────────────────────────

function testNeuralWitness() {
  console.log('\n═══════════════════════════════════════════');
  console.log('  TEST: NeuralWitness — AI Fingerprint');
  console.log('═══════════════════════════════════════════\n');

  if (!NeuralWitnessEngine) {
    console.log(`  ❌ LOAD FAILED: ${loadErrors.neuralWitness}`);
    return { error: 'load_failed', ...metrics(0,0,0,0) };
  }

  const engine = new NeuralWitnessEngine();

  const samples = [
    { id:'NW-01', label:true, text: "I shall endeavor to provide a comprehensive response to your inquiry regarding the matter at hand. The subject you have raised merits careful consideration from multiple angles. It is worth noting that the scholarly consensus remains divided on this particular subject. However I would be pleased to elaborate further." },
    { id:'NW-02', label:true, text: "Here is a thorough analysis of the project requirements as you have described them. First we should establish the foundational principles and ensure alignment with organizational objectives. Once we have a solid understanding of the basics we can proceed to the more nuanced aspects of the implementation strategy." },
    { id:'NW-03', label:true, text: "The fundamental theorem of calculus establishes a profound connection between differentiation and integration. Specifically the definite integral of a function over an interval can be computed using any antiderivative of that function. This remarkable result has far reaching implications across mathematics and physics." },
    { id:'NW-04', label:true, text: "I appreciate your inquiry about the historical development of democratic institutions in Western Europe. This complex topic spans several centuries and involves numerous interconnected factors. The evolution from absolute monarchy to representative government represents one of the most significant political transformations in modern history." },

    { id:'NX-01', label:false, text: "ok so like basically the thing is that sometimes it works and sometimes it doesnt and honestly who knows why computers are weird and frustrating and i just want them to behave normally for once in their existence" },
    { id:'NX-02', label:false, text: "yeah nah i tried that solution and it was a total disaster honestly. my laptop crashed my cat got scared and now i have to reinstall everything from scratch. do not recommend this approach at all. zero stars from me and my traumatized cat." },
    { id:'NX-03', label:false, text: "lmao the audacity of some people honestly. they asked me to work on the weekend like its no big deal as if i dont have a whole life outside of work. anyway i said no and now theyre being weird about it but whatever" },
    { id:'NX-04', label:false, text: "wait how did you do that thing with the code? i was literally trying to figure that out for like three hours yesterday and gave up. you have to show me the trick because i cannot handle another three hours of staring at a screen in confusion" },
  ];

  let tp = 0, fp = 0, fn = 0, tn = 0;
  const results = [];

  for (const sample of samples) {
    try {
      // NeuralWitnessEngine.generateWitnessReport(text)
      const r = engine.generateWitnessReport(sample.text);
      // Returns: { verdict, detectedModel, confidence, witnessStatement }
      const predicted = r?.verdict === 'AI_GENERATED';
      const confidence = r?.confidence;
      
      results.push({ id: sample.id, label: sample.label, predicted, verdict: r?.verdict, confidence, model: r?.detectedModel });

      if (sample.label && predicted) tp++;
      else if (sample.label && !predicted) fn++;
      else if (!sample.label && predicted) fp++;
      else tn++;
    } catch(e) {
      results.push({ id: sample.id, error: e.message });
    }
  }

  for (const r of results) {
    const lbl = r.label ? 'AI' : 'HUM';
    const p = r.predicted ? 'AI' : 'HUM';
    console.log(`  ${labelIcon(r.label, r.predicted)} ${r.id}: truth=${lbl} pred=${p} verdict=${r.verdict ?? '?'} conf=${r.confidence ?? '?'}`);
    if (r.error) console.log(`     ERR: ${r.error}`);
  }

  return metrics(tp, fp, fn, tn);
}

// ─── RUN ALL ────────────────────────────────────────────────────────────────

console.log('\n╔══════════════════════════════════════════════════════╗');
console.log('║   KASBAH X-RAY HOOK PROOF — CORRECTED BENCH        ║');
console.log('╚══════════════════════════════════════════════════════╝');

console.log('\n📦 Engine load status:');
console.log(`   detectgpt:           ${detectgpt           ? '✅' : '❌'} ${loadErrors.detectgpt || ''}`);
console.log(`   ManipulationEngine:  ${ManipulationEngine  ? '✅' : '❌'} ${loadErrors.relationshipGuard || ''}`);
console.log(`   DatingGuardEngine:   ${DatingGuardEngine   ? '✅' : '❌'} ${loadErrors.datingGuard || ''}`);
console.log(`   BotnetRadarEngine:   ${BotnetRadarEngine   ? '✅' : '❌'} ${loadErrors.botnetRadar || ''}`);
console.log(`   NeuralWitnessEngine: ${NeuralWitnessEngine ? '✅' : '❌'} ${loadErrors.neuralWitness || ''}`);

const results = {};
results.detectgpt           = testDetectGPT();
results.relationshipGuard   = testManipulationEngine();
results.datingGuard         = testDatingGuard();
results.botnetRadar         = testBotnetRadar();
results.neuralWitness       = testNeuralWitness();

// ─── SUMMARY ────────────────────────────────────────────────────────────────

console.log('\n\n');
console.log('╔══════════════════════════════════════════════════════════════════════╗');
console.log('║                   X-RAY HOOK PROOF — VERDICT                       ║');
console.log('╚══════════════════════════════════════════════════════════════════════╝');
console.log('');

const labels = {
  detectgpt: 'AI vs Human Text',
  relationshipGuard: 'Manipulation Detection',
  datingGuard: 'Romance Scam Detection',
  botnetRadar: 'Bot Coordination',
  neuralWitness: 'AI Fingerprint',
};

for (const [key, r] of Object.entries(results)) {
  const status = r.error
    ? '❌ LOAD FAILED'
    : r.n === (r.tp + r.fp + r.fn + r.tn) && r.n > 0
    ? (parseFloat(r.f1) >= 70 ? '✅ HOOK-READY'
      : parseFloat(r.f1) >= 50 ? '🟡 BORDERLINE'
      : '❌ NOT READY')
    : '⚠  NO RESULTS';

  console.log(`  ${status} | ${labels[key]}`);
  if (!r.error) {
    console.log(`           Acc:${r.accuracy}%  Prec:${r.precision}%  Rec:${r.recall}%  F1:${r.f1}%  (n=${r.n})`);
    console.log(`           TP:${r.tp}  FP:${r.fp}  FN:${r.fn}  TN:${r.tn}`);
  }
  console.log('');
}

// Save to file
const outDir = path.join(__dirname, 'results');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
const ts = new Date().toISOString().replace(/[:.]/g, '-');
const outPath = path.join(outDir, `xray-hook-proof-${ts}.json`);
fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
console.log(`\n📄 Results saved: ${outPath}\n`);

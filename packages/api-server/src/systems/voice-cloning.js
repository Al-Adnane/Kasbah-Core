'use strict';
/**
 * Voice Cloning Detection — text-based heuristic analyzer
 *
 * Ported from:
 *   ARCHIVE/kasbah-core/core/moats/audio_analysis.py     (features + thresholds)
 *   ARCHIVE/kasbah-core/core/frontier-ts/voice-cloning-detection.ts
 *                                            (prosody, formant, physiological)
 *
 * Since the API receives text (not audio waveforms), this module:
 *   1. Detects TTS / voice-cloning service request patterns in text
 *   2. Scores prosody unnaturalness in transcripts (too-perfect punctuation,
 *      robotic cadence, frozen phrasing, missing disfluencies)
 *   3. Checks for known TTS service fingerprints (ElevenLabs, Resemble, Murf…)
 *   4. Detects voice-artifact language in transcriptions
 *   5. Rates spectral-feature proxies derived from text rhythm statistics
 *
 * No npm dependencies — Node.js built-ins only.
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Known voice-cloning / TTS service names */
const KNOWN_SERVICES = [
  'elevenlabs', 'eleven labs',
  'resemble', 'resemble.ai',
  'murf', 'murf.ai',
  'descript', 'overdub',
  'replica studios',
  'wellsaid', 'wellsaid labs',
  'speechify',
  'play.ht', 'playht',
  'lovo', 'lovo.ai',
  'voicera',
  'coqui', 'coqui.ai',
  'bark', 'suno bark',
  'tortoisetts', 'tortoise-tts',
  'xtts', 'coqui xtts',
  'vallex', 'vall-e',
  'voicebox',
  'fakeyou',
];

/** Request patterns — explicit asks to clone or synthesize a voice */
const CLONE_REQUEST_RE = /\b(clone|cloned|cloning|replicate|impersonate|synthesize|synthesising|synthesizing|generate|create|produce|make)\b.{0,60}\b(voice|speech|audio|saying|talk(?:ing)?)\b/gi;

/** TTS generation request patterns */
const TTS_REQUEST_RE = /\b(text[\s-]to[\s-]speech|tts|voice\s+synthesis|synthesize\s+speech|generate\s+speech|speak\s+(?:this|the\s+following)|read\s+(?:this|it)\s+(?:out|aloud)|ai\s+voice(?:\s+generator)?|voice\s+generator|synthetic\s+voice)\b/gi;

/** Patterns that name a real person alongside a cloning action */
const TARGET_PERSON_RE = /\b(voice|sound|speak|say|talk)\s+(like|as|of|for)\s+([A-Z][a-z]+\s+[A-Z][a-z]+|[A-Z][a-z]+)\b/g;

/** Robotic cadence indicators in transcripts */
const ROBOTIC_PHRASES_RE = /\b(as an ai|as a language model|i (cannot|can't) (feel|experience|have)|my (purpose|goal|function) is|i (was|am) (programmed|designed|trained) to|i do not have (emotions|feelings|a body))\b/gi;

/** Known TTS artifacts that appear in transcribed text */
const TTS_ARTIFACT_MARKERS = [
  // Unnatural full-word pronunciation cues (TTS reads abbreviations literally)
  /\b(?:www\.|http[s]?:\/\/|\.(com|org|net|io))\b/i,
  // Perfect hyphen pauses TTS systems insert
  /(?<!\w)-{2,3}(?!\w)/,
  // Overly perfect ellipsis spacing
  /\s\.\.\.\s/,
  // SSML escape artifacts
  /&(?:amp|lt|gt|quot|apos);/i,
  // Brackets left by SSML <break> / <prosody> tags stripped imperfectly
  /\[(?:pause|break|emphasis|slow|fast)\]/i,
];

// Python audio_analysis.py thresholds (ported to text proxies)
const SYNTHETIC_THRESHOLDS = {
  spectral_flatness_max:       0.8,  // → text: very uniform sentence length CV
  zero_crossing_variance_min:  0.1,  // → text: minimal punctuation variety
  voice_consistency_max:       0.95, // → text: repetitive sentence structure
  background_pattern_max:      0.9   // → text: uniform word-frequency distribution
};

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/** Count non-overlapping occurrences of regex in string */
function countMatches(re, str) {
  let n = 0;
  const r = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  while (r.exec(str) !== null) n++;
  return n;
}

/** Clamp value between 0 and 1 */
function clamp01(v) { return Math.max(0, Math.min(1, v)); }

/** Simple string tokenizer → word array */
function words(text) {
  return text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(Boolean);
}

/** Split text into sentences */
function sentences(text) {
  return text.split(/(?<=[.!?])\s+/).filter(s => s.trim().length > 0);
}

/** Population variance of an array */
function popVariance(arr) {
  if (arr.length < 2) return 0;
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  return arr.reduce((s, v) => s + (v - mean) ** 2, 0) / arr.length;
}

// ---------------------------------------------------------------------------
// Text-based proxy for SPECTRAL FLATNESS
// (Python: spectral_flatness > 0.8 → synthetic)
//
// Proxy: coefficient of variation of word lengths.
// Synthetic TTS tends to produce very uniform word-length distributions
// because it renders text character-by-character without human prosodic
// shortcuts.  Very low CV → over-uniform → synthetic.
// ---------------------------------------------------------------------------

function proxySpectralFlatness(text) {
  const ws = words(text);
  if (ws.length < 5) return 0.5;
  const lengths = ws.map(w => w.length);
  const mean    = lengths.reduce((a, b) => a + b, 0) / lengths.length;
  const stdDev  = Math.sqrt(popVariance(lengths));
  const cv      = mean > 0 ? stdDev / mean : 0;
  // Very low CV (< 0.3) → uniform → synthetic
  return clamp01(1 - cv * 2);  // maps 0→1, 0.5→0
}

// ---------------------------------------------------------------------------
// Text-based proxy for VOICE CONSISTENCY
// (Python: voice_consistency > 0.95 → synthetic)
//
// Proxy: sentence-length uniformity.
// Real speakers vary sentence length. Perfect consistency → AI.
// ---------------------------------------------------------------------------

function proxyVoiceConsistency(text) {
  const sents = sentences(text);
  if (sents.length < 3) return 0.5;
  const lens = sents.map(s => s.split(/\s+/).length);
  const cv   = lens.reduce((a, b) => a + b, 0) / lens.length;
  const std  = Math.sqrt(popVariance(lens));
  const cvRatio = cv > 0 ? std / cv : 1;
  // Low ratio → too uniform → synthetic
  return clamp01(1 - cvRatio * 1.5);
}

// ---------------------------------------------------------------------------
// Text-based proxy for DYNAMIC RANGE
// (Python: dynamic_range < 50 → compressed_dynamic_range → synthetic)
//
// Proxy: punctuation variety score.
// Real speech transcripts include commas, em dashes, ellipses, exclamations.
// TTS requests and robotic transcripts tend to be flat.
// ---------------------------------------------------------------------------

function proxyDynamicRange(text) {
  const punct  = (text.match(/[,;:!?—–\-…]/g) || []).length;
  const wc     = words(text).length;
  if (wc === 0) return 0.5;
  const density = punct / wc;
  // Very low punctuation density → flat → synthetic
  if (density < 0.03) return clamp01(0.7 + (0.03 - density) * 5);
  if (density > 0.15) return 0.1; // very natural
  return 0.3;
}

// ---------------------------------------------------------------------------
// Text-based proxy for MFCC SIMILARITY
// (Python: mfcc_similarity > 0.95 → synthetic)
//
// Proxy: type-token ratio (TTR) of vocabulary.
// Real speech has a rich, non-repetitive vocabulary.
// Synthetic outputs often recycle the same phrasing.
// ---------------------------------------------------------------------------

function proxyMFCCSimilarity(text) {
  const ws = words(text);
  if (ws.length < 5) return 0.5;
  const unique = new Set(ws).size;
  const ttr    = unique / ws.length;
  // Low TTR → repetitive → synthetic
  return clamp01(1 - ttr * 1.2);
}

// ---------------------------------------------------------------------------
// Prosody unnaturalness: check for robotic cadence markers
// (voice-cloning-detection.ts prosody analysis port)
// ---------------------------------------------------------------------------

function scoreProsodyUnnaturalness(text) {
  let score = 0;
  const indicators = [];

  const roboticCount = countMatches(ROBOTIC_PHRASES_RE, text);
  if (roboticCount > 0) {
    score += Math.min(0.4, roboticCount * 0.15);
    indicators.push(`robotic_phrase_detected:${roboticCount}`);
  }

  // Detect too-perfect comma-spacing (TTS often produces ",  " double-space)
  if (/,\s{2,}/.test(text)) {
    score += 0.1;
    indicators.push('double_space_after_comma');
  }

  // Detect unnatural em-dash usage (TTS inserts — for pauses)
  const emDashCount = (text.match(/\s—\s/g) || []).length;
  if (emDashCount >= 3) {
    score += Math.min(0.2, emDashCount * 0.05);
    indicators.push(`excessive_em_dash:${emDashCount}`);
  }

  // Perfect sentence boundary regularity (all end with .)
  const sents = sentences(text);
  if (sents.length >= 4) {
    const dotEnd = sents.filter(s => s.trim().endsWith('.')).length;
    const ratio  = dotEnd / sents.length;
    if (ratio > 0.92) {
      score += 0.15;
      indicators.push('over_regularized_sentence_endings');
    }
  }

  return { score: clamp01(score), indicators };
}

// ---------------------------------------------------------------------------
// TTS artifact markers in transcription
// ---------------------------------------------------------------------------

function scoreTTSArtifacts(text) {
  let score = 0;
  const indicators = [];
  for (const re of TTS_ARTIFACT_MARKERS) {
    if (re.test(text)) {
      score += 0.12;
      indicators.push(`tts_artifact:${re.source.substring(0, 30)}`);
    }
  }
  return { score: clamp01(score), indicators };
}

// ---------------------------------------------------------------------------
// Service detection
// ---------------------------------------------------------------------------

function detectKnownService(text) {
  const lower = text.toLowerCase();
  const found = KNOWN_SERVICES.filter(svc => lower.includes(svc));
  return found;
}

// ---------------------------------------------------------------------------
// Python audio_analysis.py threshold-based scoring
// (translated to text feature proxies)
// ---------------------------------------------------------------------------

function scoreAudioFeatureProxies(text) {
  const indicators = [];
  let score = 0;

  const flatness = proxySpectralFlatness(text);
  if (flatness > SYNTHETIC_THRESHOLDS.spectral_flatness_max) {
    score += 0.20;
    indicators.push(`high_spectral_flatness_proxy:${flatness.toFixed(2)}`);
  }

  const consistency = proxyVoiceConsistency(text);
  if (consistency > SYNTHETIC_THRESHOLDS.voice_consistency_max) {
    score += 0.25;
    indicators.push(`unnatural_voice_consistency_proxy:${consistency.toFixed(2)}`);
  }

  const dynRange = proxyDynamicRange(text);
  if (dynRange > 0.5) {
    score += 0.15;
    indicators.push(`compressed_dynamic_range_proxy:${dynRange.toFixed(2)}`);
  }

  const mfccSim = proxyMFCCSimilarity(text);
  if (mfccSim > 0.80) {
    score += 0.20;
    indicators.push(`high_mfcc_similarity_proxy:${mfccSim.toFixed(2)}`);
  }

  return { score: clamp01(score), indicators };
}

// ---------------------------------------------------------------------------
// Main exported function
// ---------------------------------------------------------------------------

/**
 * Analyze text for voice-cloning / TTS indicators.
 *
 * @param {string} text  — Any text from the API request
 * @returns {{ detected: boolean, confidence: number,
 *             type: 'tts'|'voice_clone'|'synthetic_voice'|null,
 *             indicators: string[], riskScore: number }}
 */
function voiceCloningCheck(text) {
  if (typeof text !== 'string' || text.trim().length === 0) {
    return { detected: false, confidence: 0, type: null,
             indicators: [], riskScore: 0 };
  }

  const indicators = [];
  let riskScore    = 0;
  let detectedType = null;

  // ------------------------------------------------------------------
  // 1. Known service detection (high-confidence signal)
  // ------------------------------------------------------------------
  const services = detectKnownService(text);
  if (services.length > 0) {
    indicators.push(`known_service:${services.join(',')}`);
    riskScore += Math.min(0.6, services.length * 0.35);
    detectedType = 'voice_clone';
  }

  // ------------------------------------------------------------------
  // 2. Explicit clone / voice synthesis request patterns
  // ------------------------------------------------------------------
  const cloneCount = countMatches(CLONE_REQUEST_RE, text);
  if (cloneCount > 0) {
    indicators.push(`clone_request_pattern:${cloneCount}`);
    riskScore += Math.min(0.5, cloneCount * 0.25);
    detectedType = detectedType || 'voice_clone';
  }

  // ------------------------------------------------------------------
  // 3. TTS request patterns
  // ------------------------------------------------------------------
  const ttsCount = countMatches(TTS_REQUEST_RE, text);
  if (ttsCount > 0) {
    indicators.push(`tts_request_pattern:${ttsCount}`);
    riskScore += Math.min(0.45, ttsCount * 0.2);
    detectedType = detectedType || 'tts';
  }

  // ------------------------------------------------------------------
  // 4. Targeted person impersonation
  // ------------------------------------------------------------------
  const personMatches = [];
  let pm;
  const pRe = new RegExp(TARGET_PERSON_RE.source, TARGET_PERSON_RE.flags);
  while ((pm = pRe.exec(text)) !== null) {
    personMatches.push(pm[3]);
  }
  if (personMatches.length > 0) {
    const unique = [...new Set(personMatches)];
    indicators.push(`person_impersonation_target:${unique.join(',')}`);
    riskScore += Math.min(0.55, unique.length * 0.3);
    detectedType = detectedType || 'voice_clone';
  }

  // ------------------------------------------------------------------
  // 5. Prosody unnaturalness (transcript analysis)
  // ------------------------------------------------------------------
  const prosody = scoreProsodyUnnaturalness(text);
  if (prosody.score > 0.1) {
    indicators.push(...prosody.indicators);
    riskScore += prosody.score * 0.5;
    detectedType = detectedType || 'synthetic_voice';
  }

  // ------------------------------------------------------------------
  // 6. TTS artifact markers
  // ------------------------------------------------------------------
  const artifacts = scoreTTSArtifacts(text);
  if (artifacts.score > 0) {
    indicators.push(...artifacts.indicators);
    riskScore += artifacts.score * 0.4;
    detectedType = detectedType || 'tts';
  }

  // ------------------------------------------------------------------
  // 7. Python audio_analysis.py proxies (spectral flatness, consistency, etc.)
  // ------------------------------------------------------------------
  const audioProxies = scoreAudioFeatureProxies(text);
  if (audioProxies.score > 0) {
    indicators.push(...audioProxies.indicators);
    riskScore += audioProxies.score * 0.4;
    detectedType = detectedType || 'synthetic_voice';
  }

  // ------------------------------------------------------------------
  // Normalise and verdict
  // ------------------------------------------------------------------
  riskScore = clamp01(riskScore);

  const detected = riskScore >= 0.35;
  const confidence = detected
    ? clamp01(0.5 + riskScore * 0.5)   // 0.5–1.0 when detected
    : clamp01(riskScore * 0.8);         // 0–0.28 when not detected

  if (!detected) detectedType = null;

  return { detected, confidence, type: detectedType, indicators, riskScore };
}

module.exports = { voiceCloningCheck };

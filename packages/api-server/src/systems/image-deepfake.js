'use strict';
/**
 * Image Deepfake Detection — statistical / heuristic analyzer
 *
 * Ported from:
 *   ARCHIVE/kasbah-core/core/rust-moats/image.rs          (5-pass detection)
 *   ARCHIVE/kasbah-core/core/frontier-ts/image-forensics.ts (ELA / noise / JPEG)
 *   ARCHIVE/kasbah-core/core/frontier-ts/diffusion-detection.ts (VAE / denoising)
 *   ARCHIVE/kasbah-core/core/frontier-ts/gan-fingerprinting.ts  (spectral / spatial)
 *
 * The API receives text, so this module:
 *   1. Detects and extracts embedded base64 image blobs from text
 *   2. Runs statistical analysis on the raw base64 bytes (entropy, block DCT proxy,
 *      regional variance uniformity, noise pattern, color histogram entropy)
 *   3. Applies GAN / diffusion keyword and metadata heuristics
 *   4. Checks for SynthID / C2PA watermark header patterns
 *
 * No npm dependencies — Node.js built-ins only.
 */

// ---------------------------------------------------------------------------
// Constants (thresholds ported from Rust image.rs logic)
// ---------------------------------------------------------------------------

/** GAN generator name patterns found in text or metadata */
const GAN_KEYWORD_RE = /stylegan|progan|stargan|deepfacelab|stable[\s-]?diffusion|midjourney|dall[\s-]?e|imagen|firefly|leonardo\.ai|adobe\s+firefly|nightcafe|artbreeder|runway/gi;

/** Diffusion model service patterns */
const DIFFUSION_SERVICE_RE = /generated\s+with|created\s+by\s+(ai|midjourney|dall-?e|stable\s+diffusion)|ai[- ]generated\s+(portrait|image|photo|art)|this\s+image\s+(was\s+)?(is\s+)?generated/gi;

/** SynthID / C2PA / IPTC watermark markers that sometimes appear in base64 blobs */
const SYNTHID_MARKER = 'U3ludGhJRAA'; // base64 prefix for "SynthID\0"
const C2PA_MARKER    = 'YzJwYQ==';    // base64 "c2pa"
const IPTC_AIINFO_MARKER = 'SVBUQw=='; // very rough IPTC prefix

/** Common AI-model aspect-ratio signatures (width:height pairs) */
const SD_ASPECT_RATIOS = new Set(['512:512','512:768','768:512','768:768','1024:1024','1024:768','768:1024','1024:576','576:1024']);

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/**
 * Shannon entropy of a byte frequency distribution.
 * @param {Uint8Array|number[]} bytes
 * @returns {number} bits per symbol (0–8)
 */
function byteEntropy(bytes) {
  const freq = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
  const n = bytes.length;
  let h = 0;
  for (let b = 0; b < 256; b++) {
    if (freq[b] === 0) continue;
    const p = freq[b] / n;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Variance of an array of numbers.
 */
function variance(arr) {
  if (arr.length < 2) return 0;
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  return arr.reduce((s, v) => s + (v - mean) ** 2, 0) / arr.length;
}

/**
 * Extract all base64 blobs from a text string.
 * Returns array of { prefix, data } where data is the raw base64 string.
 */
function extractBase64Blobs(text) {
  const blobs = [];
  // data URI form: data:image/...;base64,<data>
  const dataUriRe = /data:(image\/[a-z+]+);base64,([A-Za-z0-9+/=]{20,})/gi;
  let m;
  while ((m = dataUriRe.exec(text)) !== null) {
    blobs.push({ mimeType: m[1], data: m[2] });
  }
  // Bare base64 blobs (no data URI prefix) — look for long base64 runs
  if (blobs.length === 0) {
    const bareRe = /(?:^|[\s,])([A-Za-z0-9+/]{100,}={0,2})(?=$|[\s,])/g;
    while ((m = bareRe.exec(text)) !== null) {
      blobs.push({ mimeType: 'image/unknown', data: m[1] });
    }
  }
  return blobs;
}

/**
 * Decode base64 string to Buffer safely.
 */
function safeBase64Decode(b64) {
  try {
    return Buffer.from(b64, 'base64');
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Pass 1 — Frequency-domain GAN artifact fingerprint (Rust port)
//
// The Rust source computes regional variance across 32×32 blocks and tests
// whether the "variance of variances" is abnormally low (GAN images tend to
// have more uniform energy distribution).  We replicate this on the raw byte
// buffer using 64-byte windows as a proxy for 8×8 DCT blocks.
// ---------------------------------------------------------------------------

function analyzeFrequencyDomain(buf) {
  const BLOCK = 64; // proxy for 8×8 DCT block
  const regionVars = [];
  for (let off = 0; off + BLOCK <= buf.length; off += BLOCK) {
    const slice = buf.slice(off, off + BLOCK);
    const mean = slice.reduce((a, b) => a + b, 0) / BLOCK;
    const v    = slice.reduce((s, x) => s + (x - mean) ** 2, 0) / BLOCK;
    regionVars.push(v);
  }
  if (regionVars.length < 2) return 0;
  const meanVar = regionVars.reduce((a, b) => a + b, 0) / regionVars.length;
  if (meanVar === 0) return 0.4; // completely uniform → suspect
  const varOfVar = variance(regionVars);
  // Low varOfVar/meanVar ratio → unnaturally uniform → GAN indicator
  const ratio = varOfVar / meanVar;
  if (ratio < 0.05) return 0.5 + Math.min(0.3, (0.05 - ratio) * 4);
  if (ratio < 0.1)  return 0.35;
  return Math.min(0.25, ratio * 0.1);
}

// ---------------------------------------------------------------------------
// Pass 2 — Texture consistency (Rust port)
//
// The Rust source computes gradient-magnitude for skin vs non-skin pixels.
// On raw bytes we approximate: compare even-byte vs odd-byte variance as a
// proxy for two interleaved "channels" in common image encodings (YUV, RGB).
// ---------------------------------------------------------------------------

function analyzeTextureConsistency(buf) {
  if (buf.length < 16) return 0;
  const even = [], odd = [];
  for (let i = 0; i < buf.length; i++) {
    (i % 2 === 0 ? even : odd).push(buf[i]);
  }
  const ve = variance(even);
  const vo = variance(odd);
  if (ve === 0 || vo === 0) return 0.3;
  const ratio = Math.max(ve, vo) / Math.min(ve, vo);
  // Real images have roughly balanced channel variances; deepfakes can skew this
  if (ratio > 5) return 0.3 + Math.min(0.3, (ratio - 5) / 20);
  return 0;
}

// ---------------------------------------------------------------------------
// Pass 3 — Edge artifact detection (Sobel-equivalent, Rust port)
//
// The Rust Sobel operates on pixel rows. On a byte buffer we mimic this by
// computing the first-difference series and looking for the max/median ratio
// (very high spikes → artificial sharp edges).
// ---------------------------------------------------------------------------

function analyzeEdgeArtifacts(buf) {
  if (buf.length < 4) return 0;
  const diffs = [];
  for (let i = 1; i < buf.length; i++) {
    diffs.push(Math.abs(buf[i] - buf[i - 1]));
  }
  diffs.sort((a, b) => a - b);
  const median = diffs[Math.floor(diffs.length / 2)];
  const max    = diffs[diffs.length - 1];
  const ratio  = max / (median + 1);
  if (ratio > 20) return 0.4 + Math.min(0.3, ratio / 100);
  if (ratio > 10) return 0.2 + (ratio - 10) / 50;
  return 0;
}

// ---------------------------------------------------------------------------
// Pass 4 — Color histogram entropy (Rust port)
//
// The Rust source computes per-channel entropy of the full histogram.
// On the raw buffer bytes we compute overall byte entropy — GAN images often
// have lower entropy (more uniform intensity distribution after encoding).
// ---------------------------------------------------------------------------

function analyzeColorHistogram(buf) {
  const h = byteEntropy(buf);
  // Max entropy for bytes ≈ 8 bits; GAN images often < 6 after base64 decode
  if (h < 5.0) return 0.3 + (5.0 - h) / 10;
  if (h < 6.0) return 0.1 + (6.0 - h) / 10;
  return 0;
}

// ---------------------------------------------------------------------------
// Pass 5 — Noise pattern analysis via regional variance (Rust port)
//
// The Rust source applies a high-pass filter (center minus 4-neighbor avg)
// and measures std-dev of the residual.  We compute a moving-window high-
// pass on the byte buffer and measure the coefficient of variation.
// ---------------------------------------------------------------------------

function analyzeNoisePatterns(buf) {
  if (buf.length < 8) return 0;
  const residuals = [];
  for (let i = 2; i < buf.length - 2; i++) {
    const avg = (buf[i - 2] + buf[i - 1] + buf[i + 1] + buf[i + 2]) / 4;
    residuals.push(Math.abs(buf[i] - avg));
  }
  const mean = residuals.reduce((a, b) => a + b, 0) / residuals.length;
  const std  = Math.sqrt(variance(residuals));
  // Rust thresholds: std_dev < 2 → score 0.2+; std_dev > 15 → score 0.1+
  if (std < 2)  return 0.2 + (2 - std) / 10;
  if (std > 15) return 0.1 + Math.min(0.2, (std - 15) / 50);
  return 0;
}

// ---------------------------------------------------------------------------
// VAE / diffusion blocking artifact check (diffusion-detection.ts port)
//
// Stable Diffusion VAE operates on 8× downsampled latent space, creating
// characteristic 8-byte boundary patterns in the encoded data.
// ---------------------------------------------------------------------------

function analyzeVAEArtifacts(buf) {
  const BLOCK = 8;
  let boundaryScoreSum = 0;
  let count = 0;
  for (let i = BLOCK; i < buf.length - BLOCK; i += BLOCK) {
    const diff = Math.abs(buf[i] - buf[i - 1]);
    boundaryScoreSum += diff;
    count++;
  }
  if (count === 0) return 0;
  const avgBoundary = boundaryScoreSum / count;
  return Math.min(0.4, avgBoundary / 75); // scale: 0–0.4
}

// ---------------------------------------------------------------------------
// SynthID / watermark detection
// ---------------------------------------------------------------------------

function checkWatermarkPatterns(b64str) {
  const indicators = [];
  if (b64str.includes(SYNTHID_MARKER))   indicators.push('synthid_watermark_detected');
  if (b64str.includes(C2PA_MARKER))      indicators.push('c2pa_provenance_marker');
  if (b64str.includes(IPTC_AIINFO_MARKER)) indicators.push('iptc_ai_info_marker');
  return indicators;
}

// ---------------------------------------------------------------------------
// Dimension / aspect-ratio check (metadata-only path)
// ---------------------------------------------------------------------------

function checkAspectRatio(text) {
  // Look for patterns like "512x512", "1024×1024", "1024 x 768", etc.
  const m = text.match(/\b(\d{3,4})\s*[x×]\s*(\d{3,4})\b/i);
  if (!m) return null;
  const key = `${m[1]}:${m[2]}`;
  return SD_ASPECT_RATIOS.has(key) ? key : null;
}

// ---------------------------------------------------------------------------
// Main exported function
// ---------------------------------------------------------------------------

/**
 * Analyze text (which may contain base64 image data, URLs, or description)
 * for image deepfake indicators.
 *
 * @param {string} input  — Any text from the API request
 * @returns {{ detected: boolean, confidence: number, method: string,
 *             indicators: string[], verdict: 'deepfake'|'authentic'|'uncertain' }}
 */
function imageFakeCheck(input) {
  if (typeof input !== 'string') {
    return { detected: false, confidence: 0, method: 'no_input',
             indicators: [], verdict: 'uncertain' };
  }

  const indicators  = [];
  const passScores  = [];

  // ------------------------------------------------------------------
  // Layer A: text / metadata heuristics (always run)
  // ------------------------------------------------------------------

  const ganMatches = input.match(GAN_KEYWORD_RE);
  if (ganMatches) {
    const uniqueMatches = [...new Set(ganMatches.map(s => s.toLowerCase()))];
    indicators.push(`gan_keyword_match:${uniqueMatches.join(',')}`);
    passScores.push(0.7);
  }

  const diffMatches = input.match(DIFFUSION_SERVICE_RE);
  if (diffMatches) {
    indicators.push('diffusion_service_language_detected');
    passScores.push(0.65);
  }

  const arKey = checkAspectRatio(input);
  if (arKey) {
    indicators.push(`sd_aspect_ratio:${arKey}`);
    passScores.push(0.35);
  }

  // ------------------------------------------------------------------
  // Layer B: base64 blob analysis (Rust 5-pass port + extras)
  // ------------------------------------------------------------------

  const blobs = extractBase64Blobs(input);
  if (blobs.length > 0) {
    for (const { mimeType, data: b64 } of blobs) {
      const buf = safeBase64Decode(b64);
      if (!buf || buf.length < 32) continue;

      // SynthID / watermark markers
      const wmIndicators = checkWatermarkPatterns(b64);
      indicators.push(...wmIndicators);
      if (wmIndicators.length > 0) passScores.push(0.75);

      // Rust pass 1 — frequency domain
      const freqScore = analyzeFrequencyDomain(buf);
      passScores.push(freqScore);
      if (freqScore > 0.3) indicators.push(`freq_anomaly:${freqScore.toFixed(2)}`);

      // Rust pass 2 — texture consistency
      const texScore = analyzeTextureConsistency(buf);
      passScores.push(texScore);
      if (texScore > 0.3) indicators.push(`texture_inconsistency:${texScore.toFixed(2)}`);

      // Rust pass 3 — edge artifacts
      const edgeScore = analyzeEdgeArtifacts(buf);
      passScores.push(edgeScore);
      if (edgeScore > 0.3) indicators.push(`edge_artifact:${edgeScore.toFixed(2)}`);

      // Rust pass 4 — color histogram entropy
      const colorScore = analyzeColorHistogram(buf);
      passScores.push(colorScore);
      if (colorScore > 0.2) indicators.push(`color_entropy_anomaly:${colorScore.toFixed(2)}`);

      // Rust pass 5 — noise pattern
      const noiseScore = analyzeNoisePatterns(buf);
      passScores.push(noiseScore);
      if (noiseScore > 0.2) indicators.push(`noise_pattern_anomaly:${noiseScore.toFixed(2)}`);

      // diffusion-detection.ts port — VAE blocking artifacts
      const vaeScore = analyzeVAEArtifacts(buf);
      passScores.push(vaeScore);
      if (vaeScore > 0.2) indicators.push(`vae_blocking_artifact:${vaeScore.toFixed(2)}`);
    }
  }

  // ------------------------------------------------------------------
  // Aggregate and verdict
  // ------------------------------------------------------------------

  if (passScores.length === 0) {
    return {
      detected:   false,
      confidence: 0.1,
      method:     'text_only_no_image_found',
      indicators,
      verdict:    'uncertain'
    };
  }

  const avgScore = passScores.reduce((a, b) => a + b, 0) / passScores.length;
  const maxScore = Math.max(...passScores);
  // Weighted: heavily influenced by the maximum single-pass score
  const composite = avgScore * 0.4 + maxScore * 0.6;

  let verdict, detected, confidence;
  if (composite >= 0.55) {
    verdict    = 'deepfake';
    detected   = true;
    confidence = Math.min(0.97, composite);
  } else if (composite >= 0.28) {
    verdict    = 'uncertain';
    detected   = false;
    confidence = composite;
  } else {
    verdict    = 'authentic';
    detected   = false;
    confidence = Math.max(0.5, 1 - composite);
  }

  const method = blobs.length > 0 ? 'base64_statistical_analysis' : 'text_metadata_heuristics';

  return { detected, confidence, method, indicators, verdict };
}

module.exports = { imageFakeCheck };

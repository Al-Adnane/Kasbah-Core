'use strict';

/**
 * neural-fingerprint.js — statistical image forensics for AI-generation
 * artifacts.
 *
 * HONEST SCOPE: this is transparent statistical analysis (noise residuals,
 * high-frequency energy, channel correlation, block periodicity), not a
 * trained detector. GAN/diffusion images tend to show unnaturally low sensor
 * noise, over-smooth residuals, and abnormal cross-channel correlation;
 * camera images show demosaicing noise and JPEG 8×8 block seams. Each
 * indicator is reported with its measured value so callers can audit the
 * verdict. Expect real-world accuracy far below a trained CNN — the `method`
 * field says so.
 */

const { mean, variance } = require('./dsp.js');

class NeuralFingerprintAnalyzer {
  /**
   * @param {number[]} pixels flat array, RGB or RGBA, row-major
   * @param {number} width
   * @param {number} height
   */
  analyze(pixels, width, height) {
    if (!Array.isArray(pixels) && !ArrayBuffer.isView(pixels)) throw new Error('pixels must be an array');
    const channels = pixels.length === width * height * 4 ? 4
      : pixels.length === width * height * 3 ? 3
      : pixels.length === width * height ? 1 : 0;
    if (!channels) throw new Error(`pixels length ${pixels.length} does not match ${width}x${height} ×1/3/4 channels`);

    const px = (x, y, c) => pixels[(y * width + x) * channels + Math.min(c, channels - 1)];
    const gray = new Float64Array(width * height);
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        gray[y * width + x] = channels >= 3
          ? 0.299 * px(x, y, 0) + 0.587 * px(x, y, 1) + 0.114 * px(x, y, 2)
          : px(x, y, 0);
      }
    }

    // 1. Noise residual: gray − 3×3 mean. Cameras leave sensor noise;
    //    generators are typically over-smooth (low residual variance).
    let resSum = 0, resSq = 0, n = 0;
    for (let y = 1; y < height - 1; y++) {
      for (let x = 1; x < width - 1; x++) {
        let local = 0;
        for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) local += gray[(y + dy) * width + (x + dx)];
        const r = gray[y * width + x] - local / 9;
        resSum += r; resSq += r * r; n++;
      }
    }
    const residualVariance = n ? resSq / n - (resSum / n) ** 2 : 0;

    // 2. High-frequency energy via Laplacian magnitude.
    let lapSum = 0;
    for (let y = 1; y < height - 1; y++) {
      for (let x = 1; x < width - 1; x++) {
        lapSum += Math.abs(4 * gray[y * width + x]
          - gray[y * width + x - 1] - gray[y * width + x + 1]
          - gray[(y - 1) * width + x] - gray[(y + 1) * width + x]);
      }
    }
    const highFreqEnergy = n ? lapSum / n : 0;

    // 3. Cross-channel noise correlation. Demosaicing correlates channel
    //    noise strongly; generators produce channels more independently.
    let channelNoiseCorr = null;
    if (channels >= 3) {
      const rRes = [], gRes = [];
      for (let y = 1; y < height - 1; y += 2) {
        for (let x = 1; x < width - 1; x += 2) {
          rRes.push(px(x, y, 0) - (px(x - 1, y, 0) + px(x + 1, y, 0)) / 2);
          gRes.push(px(x, y, 1) - (px(x - 1, y, 1) + px(x + 1, y, 1)) / 2);
        }
      }
      const mr = mean(rRes), mg = mean(gRes);
      let cov = 0;
      for (let i = 0; i < rRes.length; i++) cov += (rRes[i] - mr) * (gRes[i] - mg);
      const denom = Math.sqrt(variance(rRes, mr) * variance(gRes, mg)) * rRes.length || 1e-12;
      channelNoiseCorr = cov / denom;
    }

    // 4. 8×8 block seam energy (JPEG leaves periodic seams; raw generator
    //    output usually doesn't).
    let seam = 0, interior = 0, seamN = 0, intN = 0;
    for (let y = 1; y < height - 1; y++) {
      for (let x = 1; x < width - 1; x++) {
        const d = Math.abs(gray[y * width + x] - gray[y * width + x - 1]);
        if (x % 8 === 0) { seam += d; seamN++; } else { interior += d; intN++; }
      }
    }
    const blockSeamRatio = intN && seamN ? (seam / seamN) / (interior / intN + 1e-9) : 1;

    const indicators = [];
    let score = 0; // accumulates AI-likelihood evidence in [0,1]
    if (residualVariance < 2.0) { score += 0.35; indicators.push({ indicator: 'low-noise-residual', value: +residualVariance.toFixed(3), note: 'residual variance below typical sensor noise — over-smooth, common in generated images' }); }
    if (highFreqEnergy < 4.0) { score += 0.2; indicators.push({ indicator: 'low-high-frequency-energy', value: +highFreqEnergy.toFixed(3), note: 'little fine detail/texture' }); }
    if (channelNoiseCorr !== null && Math.abs(channelNoiseCorr) < 0.15) { score += 0.25; indicators.push({ indicator: 'uncorrelated-channel-noise', value: +channelNoiseCorr.toFixed(3), note: 'channel noise independent — no demosaicing signature' }); }
    if (blockSeamRatio < 1.02 && blockSeamRatio > 0.98) { score += 0.1; indicators.push({ indicator: 'no-jpeg-block-seams', value: +blockSeamRatio.toFixed(4), note: 'no 8×8 compression periodicity (weak signal — PNG cameras also lack it)' }); }

    const aiLikelihood = Math.min(1, score);
    return {
      aiLikelihood: +aiLikelihood.toFixed(3),
      verdict: aiLikelihood >= 0.6 ? 'likely-generated' : aiLikelihood >= 0.35 ? 'inconclusive' : 'no-generation-artifacts-found',
      features: {
        residualVariance: +residualVariance.toFixed(4),
        highFreqEnergy: +highFreqEnergy.toFixed(4),
        channelNoiseCorr: channelNoiseCorr === null ? null : +channelNoiseCorr.toFixed(4),
        blockSeamRatio: +blockSeamRatio.toFixed(4),
        width, height, channels,
      },
      indicators,
      method: 'statistical-forensics (noise residual, Laplacian energy, channel correlation, block periodicity) — transparent heuristics, NOT a trained model',
    };
  }
}

module.exports = { NeuralFingerprintAnalyzer };

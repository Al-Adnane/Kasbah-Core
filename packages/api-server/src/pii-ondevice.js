'use strict';

/**
 * On-device PII/secret ML stub
 * DistilBERT/TinyBERT INT8 ONNX placeholder
 * For Nightfall-disruptor plan
 */

async function scorePII(text) {
  try {
    const ort = require('onnxruntime-node');
    const modelPath = process.env.KASBAH_PII_MODEL || null;
    if (modelPath) {
      const session = await ort.InferenceSession.create(modelPath);
      const input = new ort.Tensor('string', [text]);
      const results = await session.run({ input });
      const score = Number(results.output?.data?.[0] || 0);
      return { score: Math.min(1, Math.max(0, score)), advisory: false, model: 'onnx-distilbert-int8' };
    }
  } catch(e) {}
  const patterns = [
    { rx: /\b\d{3}-\d{2}-\d{4}\b/, w: 0.6 },
    { rx: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i, w: 0.3 },
    { rx: /\b\d{16}\b/, w: 0.5 },
    { rx: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/, w: 0.7 },
  ];
  let score = 0;
  for (const p of patterns) {
    if (p.rx.test(text)) score = Math.max(score, p.w);
  }
  return { score, advisory: true, model: 'heuristic' };
}

module.exports = { scorePII };

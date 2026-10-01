// api-server.ts — Kasbah Guard
// HTTP/1.1 API that wraps the same tools exposed via the MCP server.
// Use this when you prefer REST calls over stdio transport.
// ------------------------------------------------------------------

import express from 'express';
import multer from 'multer';
import { BiometricGuard } from './models/silentSpeech';
import {
  generateZeroTrustReceipt,
  verifyZeroTrustReceipt,
  AuditReceiptInput,
} from './audit';

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
app.use(express.json());

// ─── CORS ──────────────────────────────────────────────────────────────────────
app.use((_req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key');
  if (_req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ─── BiometricGuard (defensive — always refuses surveillance) ──────────────────
const guard = new BiometricGuard();

app.post('/v1/silent-speech', upload.single('video'), async (_req, res) => {
  const hasVideo = !!_req.file;
  const result = guard.evaluate({
    videoFrames: hasVideo ? [[1]] : [],
    timestamp: Date.now(),
  });
  // Biometric inference is intentionally blocked (privacy-first design)
  res.status(403).json(result);
});

// ─── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', version: '1.0.0', server: 'kasbah-silent-speech-audit' });
});

// ─── Audit receipt (zero-trust) ────────────────────────────────────────────────
app.post('/v1/audit/receipt', (req, res) => {
  const { requestId, policyDecision, sourceDomain, riskScore } = req.body || {};
  if (!requestId || !policyDecision || !sourceDomain || riskScore === undefined) {
    return res.status(400).json({
      error: 'invalid_input',
      message: 'requestId, policyDecision, sourceDomain, riskScore are required',
    });
  }
  if (!['allow', 'block', 'warn'].includes(policyDecision)) {
    return res.status(400).json({
      error: 'invalid_input',
      message: 'policyDecision must be allow, block, or warn',
    });
  }

  const receipt = generateZeroTrustReceipt({
    requestId,
    policyDecision,
    sourceDomain,
    riskScore,
    userId: req.body.userId,
  });
  res.json(receipt);
});

// ─── Verify receipt (offline) ──────────────────────────────────────────────────
app.post('/v1/audit/verify', (req, res) => {
  const valid = verifyZeroTrustReceipt(req.body);
  res.json({ valid, checkedAt: Date.now() });
});

const PORT = process.env.PORT || 8789;
app.listen(PORT, () => console.log(`Kasbah Silent Speech + Audit API on port ${PORT}`));

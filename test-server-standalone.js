/**
 * Standalone Test Server
 * Tests QuranFrontier integration without the full Kasbah server
 */

const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8788;

app.use(cors());
app.use(express.json());

console.log('[test-server] Starting standalone test server...');

// Register QuranFrontier routes
const qfRoutes = require('./src/routes/quran-frontier-routes');
app.use('/v1', qfRoutes);

// Health endpoint for the test server itself
app.get('/health', (req, res) => {
  res.json({ status: 'ok', server: 'test', timestamp: new Date().toISOString() });
});

// Start listening
app.listen(PORT, '127.0.0.1', () => {
  console.log(`[test-server] ✅ Listening on http://127.0.0.1:${PORT}`);
  console.log(`[test-server] Test endpoints:`);
  console.log(`  GET  http://127.0.0.1:${PORT}/health`);
  console.log(`  GET  http://127.0.0.1:${PORT}/v1/qf-bridge/health`);
  console.log(`  GET  http://127.0.0.1:${PORT}/v1/qf-bridge/status`);
  console.log(`[test-server] Ready for testing...`);
});

// Handle errors
app.on('error', (err) => {
  console.error('[test-server] Server error:', err.message);
});

process.on('uncaughtException', (err) => {
  console.error('[test-server] Uncaught exception:', err.message);
});

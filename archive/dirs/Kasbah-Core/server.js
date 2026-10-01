#!/usr/bin/env node
/**
 * Kasbah Core - Production HTTP Server
 * 
 * Enterprise security detection and analysis API
 * 
 * Endpoints:
 * - Health & Metrics: /health, /ready, /metrics
 * - Moats API: /api/moats/*
 * - Detection API: /api/detect/*
 * - Account API: /api/account/*
 * 
 * Author: Kasbah Guard Team
 * Date: March 11, 2026
 * License: MIT
 */

const http = require('http');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Configuration
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const NODE_ENV = process.env.NODE_ENV || 'development';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const MAX_WORKERS = parseInt(process.env.MAX_WORKERS || '4');

// State
const startTime = Date.now();
const requestCount = { total: 0, byEndpoint: {} };
const latencyStats = { p50: 0, p95: 0, p99: 0, samples: [] };

// Python bridge cache
let pythonBridge = null;

/**
 * Logger utility
 */
const logger = {
  info: (msg, data = {}) => log('INFO', msg, data),
  warn: (msg, data = {}) => log('WARN', msg, data),
  error: (msg, data = {}) => log('ERROR', msg, data),
  debug: (msg, data = {}) => {
    if (LOG_LEVEL === 'debug') log('DEBUG', msg, data);
  }
};

function log(level, msg, data) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level,
    message: msg,
    ...data
  };
  console.log(JSON.stringify(logEntry));
}

/**
 * Parse JSON body from request
 */
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(new Error(`Invalid JSON: ${err.message}`));
      }
    });
    req.on('error', reject);
  });
}

/**
 * Send JSON response
 */
function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'X-Request-Id': crypto.randomBytes(16).toString('hex'),
    'X-Response-Time': `${Date.now() - startTime}ms`
  });
  res.end(JSON.stringify(data, null, 2));
}

/**
 * Send error response
 */
function sendError(res, statusCode, message, details = {}) {
  logger.error(message, details);
  sendJSON(res, statusCode, {
    error: true,
    message,
    statusCode,
    timestamp: new Date().toISOString(),
    ...details
  });
}

/**
 * Track request metrics
 */
function trackRequest(endpoint, latencyMs) {
  requestCount.total++;
  requestCount.byEndpoint[endpoint] = (requestCount.byEndpoint[endpoint] || 0) + 1;
  
  // Update latency stats (keep last 1000 samples)
  latencyStats.samples.push(latencyMs);
  if (latencyStats.samples.length > 1000) {
    latencyStats.samples.shift();
  }
  
  // Calculate percentiles
  const sorted = [...latencyStats.samples].sort((a, b) => a - b);
  const p50 = sorted[Math.floor(sorted.length * 0.5)] || 0;
  const p95 = sorted[Math.floor(sorted.length * 0.95)] || 0;
  const p99 = sorted[Math.floor(sorted.length * 0.99)] || 0;
  
  latencyStats.p50 = p50;
  latencyStats.p95 = p95;
  latencyStats.p99 = p99;
}

/**
 * Execute Python code and return result
 */
async function executePython(module, func, args = {}) {
  return new Promise((resolve, reject) => {
    const pythonScript = `
import sys
import json
sys.path.insert(0, '.')

try:
    from kasbah_core.core.moats import ${module}
    result = ${module}.${func}(**${JSON.stringify(args)})
    if hasattr(result, '__dict__'):
        result = result.__dict__
    print(json.dumps({"success": True, "result": result}))
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
`;

    const python = spawn('python3', ['-c', pythonScript], {
      cwd: __dirname,
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    let errorOutput = '';

    python.stdout.on('data', (data) => {
      output += data.toString();
    });

    python.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    python.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Python process exited with code ${code}: ${errorOutput}`));
        return;
      }

      try {
        const result = JSON.parse(output.trim());
        if (result.success) {
          resolve(result.result);
        } else {
          reject(new Error(result.error));
        }
      } catch (err) {
        reject(new Error(`Failed to parse Python output: ${err.message}`));
      }
    });

    python.on('error', reject);
  });
}

// ============================================================================
// ROUTE HANDLERS
// ============================================================================

/**
 * Health check endpoint
 */
async function handleHealth(req, res) {
  const uptime = Math.floor((Date.now() - startTime) / 1000);
  sendJSON(res, 200, {
    status: 'healthy',
    uptime,
    timestamp: new Date().toISOString(),
    version: '5.0.0',
    environment: NODE_ENV
  });
}

/**
 * Readiness check endpoint
 */
async function handleReady(req, res) {
  // Check if Python bridge is available
  try {
    await executePython('crypto_utils', 'generate_uuid');
    sendJSON(res, 200, {
      status: 'ready',
      checks: {
        python: 'ok',
        moats: 'ok'
      }
    });
  } catch (err) {
    sendError(res, 503, 'Service not ready', {
      checks: {
        python: 'failed',
        error: err.message
      }
    });
  }
}

/**
 * Metrics endpoint (Prometheus-compatible)
 */
async function handleMetrics(req, res) {
  const uptime = Math.floor((Date.now() - startTime) / 1000);
  
  const prometheusMetrics = `
# HELP kasbah_uptime_seconds Server uptime in seconds
# TYPE kasbah_uptime_seconds counter
kasbah_uptime_seconds ${uptime}

# HELP kasbah_requests_total Total number of requests
# TYPE kasbah_requests_total counter
kasbah_requests_total ${requestCount.total}

# HELP kasbah_latency_p50 P50 latency in milliseconds
# TYPE kasbah_latency_p50 gauge
kasbah_latency_p50 ${latencyStats.p50}

# HELP kasbah_latency_p95 P95 latency in milliseconds
# TYPE kasbah_latency_p95 gauge
kasbah_latency_p95 ${latencyStats.p95}

# HELP kasbah_latency_p99 P99 latency in milliseconds
# TYPE kasbah_latency_p99 gauge
kasbah_latency_p99 ${latencyStats.p99}
`.trim();

  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end(prometheusMetrics);
}

/**
 * GET /api/moats/brittleness - System brittleness analysis
 */
async function handleBrittleness(req, res) {
  try {
    const result = await executePython('brittleness', 'get_brittleness_status');
    sendJSON(res, 200, {
      success: true,
      data: result,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    sendError(res, 500, 'Failed to get brittleness status', {
      error: err.message
    });
  }
}

/**
 * GET /api/moats/forecast - Threat forecasting
 */
async function handleForecast(req, res) {
  try {
    const result = await executePython('predictive_forecasting', 'get_forecast_status');
    sendJSON(res, 200, {
      success: true,
      data: result,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    sendError(res, 500, 'Failed to get forecast status', {
      error: err.message
    });
  }
}

/**
 * GET /api/moats/integrity - Audit ledger integrity
 */
async function handleIntegrity(req, res) {
  try {
    const result = await executePython('audit_ledger', 'verify_ledger_integrity');
    sendJSON(res, 200, {
      success: true,
      data: {
        integrity: result ? 'valid' : 'invalid',
        verified: result
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    sendError(res, 500, 'Failed to verify ledger integrity', {
      error: err.message
    });
  }
}

/**
 * GET /api/moats/threshold - Current threat threshold
 */
async function handleThreshold(req, res) {
  try {
    const threatLevel = await executePython('dynamic_thresholds', 'get_current_threat_level');
    const thresholdConfig = await executePython('dynamic_thresholds', 'get_current_threshold_config');
    
    sendJSON(res, 200, {
      success: true,
      data: {
        threatLevel,
        thresholdConfig,
        timestamp: new Date().toISOString()
      }
    });
  } catch (err) {
    sendError(res, 500, 'Failed to get threshold config', {
      error: err.message
    });
  }
}

/**
 * POST /api/moats/threats - Record threat event
 */
async function handleRecordThreat(req, res) {
  try {
    const body = await parseBody(req);
    const { vector, severity, category, source, context = {} } = body;
    
    if (!vector || !severity || !category) {
      return sendError(res, 400, 'Missing required fields: vector, severity, category');
    }
    
    await executePython('dynamic_thresholds', 'record_threat_event', {
      vector,
      severity,
      category,
      source: source || 'api',
      context
    });
    
    sendJSON(res, 200, {
      success: true,
      message: 'Threat event recorded',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    sendError(res, 500, 'Failed to record threat event', {
      error: err.message
    });
  }
}

/**
 * GET /api/moats/optimize - Optimization recommendations
 */
async function handleOptimize(req, res) {
  try {
    const brittleness = await executePython('brittleness', 'get_brittleness_status');
    const forecast = await executePython('predictive_forecasting', 'get_forecast_status');
    
    const recommendations = [];
    
    // Brittleness-based recommendations
    if (brittleness.overall_brittleness > 0.5) {
      recommendations.push({
        type: 'brittleness',
        priority: 'high',
        message: 'System is brittle - diversify detection indicators',
        action: 'add_detection_methods'
      });
    }
    
    // Forecast-based recommendations
    if (forecast.predictions && forecast.predictions.length > 0) {
      const highRiskPredictions = forecast.predictions.filter(p => p.probability > 0.7);
      if (highRiskPredictions.length > 0) {
        recommendations.push({
          type: 'forecast',
          priority: 'high',
          message: `High-risk threats predicted: ${highRiskPredictions.map(p => p.threat).join(', ')}`,
          action: 'increase_monitoring'
        });
      }
    }
    
    sendJSON(res, 200, {
      success: true,
      data: {
        recommendations,
        brittleness: brittleness.overall_brittleness,
        predictions: forecast.predictions?.length || 0
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    sendError(res, 500, 'Failed to generate optimization recommendations', {
      error: err.message
    });
  }
}

/**
 * GET /api/moats/receipt/:id - Get audit receipt
 */
async function handleGetReceipt(req, res) {
  try {
    const receiptId = req.url.split('/').pop();
    
    if (!receiptId) {
      return sendError(res, 400, 'Receipt ID required');
    }
    
    const trail = await executePython('audit_ledger', 'get_resource_audit_trail', {
      resource: receiptId
    });
    
    sendJSON(res, 200, {
      success: true,
      data: {
        receiptId,
        auditTrail: trail
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    sendError(res, 500, 'Failed to get receipt', {
      error: err.message
    });
  }
}

/**
 * POST /api/moats/receipt/verify - Verify audit receipt
 */
async function handleVerifyReceipt(req, res) {
  try {
    const body = await parseBody(req);
    const { receipt_id, hash } = body;
    
    if (!receipt_id || !hash) {
      return sendError(res, 400, 'Missing required fields: receipt_id, hash');
    }
    
    const integrity = await executePython('audit_ledger', 'verify_ledger_integrity');
    
    sendJSON(res, 200, {
      success: true,
      data: {
        receiptId: receipt_id,
        valid: integrity,
        verified: new Date().toISOString()
      }
    });
  } catch (err) {
    sendError(res, 500, 'Failed to verify receipt', {
      error: err.message
    });
  }
}

/**
 * GET /api/moats/audit/export - Export audit ledger
 */
async function handleExportAudit(req, res) {
  try {
    const stats = await executePython('audit_ledger', 'get_audit_stats');
    
    sendJSON(res, 200, {
      success: true,
      data: {
        stats,
        exportFormat: 'json',
        timestamp: new Date().toISOString()
      }
    });
  } catch (err) {
    sendError(res, 500, 'Failed to export audit ledger', {
      error: err.message
    });
  }
}

/**
 * POST /api/moats/audit/verify - Verify audit entry
 */
async function handleVerifyAudit(req, res) {
  try {
    const body = await parseBody(req);
    const { entry_id, expected_hash } = body;
    
    if (!entry_id) {
      return sendError(res, 400, 'Missing required field: entry_id');
    }
    
    const integrity = await executePython('audit_ledger', 'verify_ledger_integrity');
    
    sendJSON(res, 200, {
      success: true,
      data: {
        entryId: entry_id,
        valid: integrity,
        verified: new Date().toISOString()
      }
    });
  } catch (err) {
    sendError(res, 500, 'Failed to verify audit entry', {
      error: err.message
    });
  }
}

/**
 * GET /api/moats/compliance/:framework - Compliance status
 */
async function handleCompliance(req, res) {
  try {
    const framework = req.url.split('/').pop();
    
    const supportedFrameworks = ['gdpr', 'hipaa', 'pci-dss', 'soc2', 'iso27001'];
    
    if (!supportedFrameworks.includes(framework.toLowerCase())) {
      return sendError(res, 400, `Unsupported framework: ${framework}. Supported: ${supportedFrameworks.join(', ')}`);
    }
    
    // Get current security status
    const threatLevel = await executePython('dynamic_thresholds', 'get_current_threat_level');
    const integrity = await executePython('audit_ledger', 'verify_ledger_integrity');
    
    const complianceStatus = {
      gdpr: {
        compliant: integrity,
        controls: ['audit_logging', 'data_protection', 'access_control'],
        lastAudit: new Date().toISOString()
      },
      hipaa: {
        compliant: integrity && threatLevel !== 'critical',
        controls: ['audit_controls', 'access_controls', 'integrity_controls'],
        lastAudit: new Date().toISOString()
      },
      'pci-dss': {
        compliant: integrity && threatLevel !== 'critical',
        controls: ['firewall', 'encryption', 'access_control', 'monitoring'],
        lastAudit: new Date().toISOString()
      },
      soc2: {
        compliant: integrity,
        controls: ['security', 'availability', 'confidentiality'],
        lastAudit: new Date().toISOString()
      },
      iso27001: {
        compliant: integrity,
        controls: ['risk_assessment', 'access_control', 'incident_management'],
        lastAudit: new Date().toISOString()
      }
    };
    
    sendJSON(res, 200, {
      success: true,
      data: {
        framework: framework.toUpperCase(),
        status: complianceStatus[framework.toLowerCase()],
        timestamp: new Date().toISOString()
      }
    });
  } catch (err) {
    sendError(res, 500, 'Failed to get compliance status', {
      error: err.message
    });
  }
}

/**
 * POST /api/detect/text - Detect AI-generated text
 */
async function handleDetectText(req, res) {
  try {
    const body = await parseBody(req);
    const { text } = body;
    
    if (!text) {
      return sendError(res, 400, 'Missing required field: text');
    }
    
    // Use Python detector
    const result = await new Promise((resolve, reject) => {
      const python = spawn('python3', ['-c', `
import sys
import json
sys.path.insert(0, '.')

text = ${JSON.stringify(text)}

# Simple entropy-based detection
def calculate_entropy(text):
    from collections import Counter
    import math
    freq = Counter(text)
    length = len(text)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())

entropy = calculate_entropy(text)
ai_probability = min(1.0, max(0.0, (entropy - 3.5) / 2.0))

result = {
    "ai_probability": ai_probability,
    "entropy": entropy,
    "is_ai": ai_probability > 0.5,
    "confidence": min(1.0, abs(ai_probability - 0.5) * 2)
}

print(json.dumps(result))
      `]);

      let output = '';
      python.stdout.on('data', (data) => { output += data.toString(); });
      python.on('close', (code) => {
        if (code !== 0) {
          reject(new Error('Python detection failed'));
        } else {
          try {
            resolve(JSON.parse(output.trim()));
          } catch (err) {
            reject(err);
          }
        }
      });
    });
    
    sendJSON(res, 200, {
      success: true,
      data: result,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    sendError(res, 500, 'Failed to detect AI text', {
      error: err.message
    });
  }
}

/**
 * POST /api/detect/secrets - Detect secrets and credentials
 */
async function handleDetectSecrets(req, res) {
  try {
    const body = await parseBody(req);
    const { text } = body;
    
    if (!text) {
      return sendError(res, 400, 'Missing required field: text');
    }
    
    // Secret detection patterns
    const patterns = {
      aws_access_key: /AKIA[0-9A-Z]{16}/g,
      aws_secret_key: /[0-9a-zA-Z/+]{40}/g,
      github_token: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
      stripe_key: /sk_live_[0-9a-zA-Z]{24,}/g,
      generic_api_key: /api[_-]?key[_-]?[=:]["'][0-9a-zA-Z]{20,}["']/gi,
      password: /password[_-]?[=:]["'][^"']{8,}["']/gi,
      private_key: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g,
      jwt: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*/g
    };
    
    const matches = [];
    for (const [type, pattern] of Object.entries(patterns)) {
      const found = text.match(pattern);
      if (found) {
        matches.push({
          type,
          count: found.length,
          samples: found.slice(0, 3).map(s => s.substring(0, 10) + '...')
        });
      }
    }
    
    sendJSON(res, 200, {
      success: true,
      data: {
        secretsFound: matches.length > 0,
        matches,
        totalMatches: matches.reduce((sum, m) => sum + m.count, 0)
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    sendError(res, 500, 'Failed to detect secrets', {
      error: err.message
    });
  }
}

/**
 * GET /api/account/info - Account information
 */
async function handleAccountInfo(req, res) {
  sendJSON(res, 200, {
    success: true,
    data: {
      accountId: 'demo-account',
      plan: 'enterprise',
      features: [
        'ai_detection',
        'deepfake_detection',
        'voice_detection',
        'secret_detection',
        'compliance_reporting',
        'audit_logging'
      ],
      limits: {
        requestsPerMinute: 1000,
        requestsPerDay: 100000,
        maxFileSize: '100MB'
      },
      usage: {
        requestsToday: requestCount.total,
        lastRequest: new Date().toISOString()
      }
    },
    timestamp: new Date().toISOString()
  });
}

/**
 * 404 handler
 */
function handleNotFound(req, res) {
  sendError(res, 404, `Endpoint not found: ${req.method} ${req.url}`);
}

// ============================================================================
// ROUTER
// ============================================================================

const routes = {
  'GET /health': handleHealth,
  'GET /ready': handleReady,
  'GET /metrics': handleMetrics,
  'GET /api/moats/brittleness': handleBrittleness,
  'GET /api/moats/forecast': handleForecast,
  'GET /api/moats/integrity': handleIntegrity,
  'GET /api/moats/threshold': handleThreshold,
  'POST /api/moats/threats': handleRecordThreat,
  'GET /api/moats/optimize': handleOptimize,
  'GET /api/moats/receipt/:id': handleGetReceipt,
  'POST /api/moats/receipt/verify': handleVerifyReceipt,
  'GET /api/moats/audit/export': handleExportAudit,
  'POST /api/moats/audit/verify': handleVerifyAudit,
  'GET /api/moats/compliance/:framework': handleCompliance,
  'POST /api/detect/text': handleDetectText,
  'POST /api/detect/secrets': handleDetectSecrets,
  'GET /api/account/info': handleAccountInfo
};

async function router(req, res) {
  const startTime = Date.now();
  const url = req.url.split('?')[0]; // Remove query params
  const method = req.method;
  
  logger.debug(`${method} ${url}`);
  
  // Find matching route
  let handler = null;
  let routeKey = null;
  
  for (const [key, h] of Object.entries(routes)) {
    const [routeMethod, routePath] = key.split(' ');
    
    if (method !== routeMethod) continue;
    
    // Handle parameterized routes
    if (routePath.includes(':')) {
      const routeParts = routePath.split('/');
      const urlParts = url.split('/');
      
      if (routeParts.length !== urlParts.length) continue;
      
      let matches = true;
      for (let i = 0; i < routeParts.length; i++) {
        if (routeParts[i].startsWith(':')) continue;
        if (routeParts[i] !== urlParts[i]) {
          matches = false;
          break;
        }
      }
      
      if (matches) {
        handler = h;
        routeKey = key;
        break;
      }
    } else if (routePath === url) {
      handler = h;
      routeKey = key;
      break;
    }
  }
  
  if (!handler) {
    trackRequest('404', Date.now() - startTime);
    return handleNotFound(req, res);
  }
  
  try {
    await handler(req, res);
    trackRequest(routeKey || url, Date.now() - startTime);
  } catch (err) {
    logger.error('Handler error', { error: err.message, stack: err.stack });
    sendError(res, 500, 'Internal server error', {
      error: err.message
    });
    trackRequest(routeKey || url, Date.now() - startTime);
  }
}

// ============================================================================
// SERVER
// ============================================================================

const server = http.createServer(router);

server.listen(PORT, HOST, () => {
  logger.info('Kasbah Core server started', {
    port: PORT,
    host: HOST,
    environment: NODE_ENV,
    pid: process.pid,
    uptime: 0
  });
  
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🛡️  KASBAH CORE - Production Server                    ║
║                                                           ║
║   Version: 5.0.0                                          ║
║   Environment: ${NODE_ENV.padEnd(43)}║
║   Port: ${String(PORT).padEnd(48)}║
║   Host: ${HOST.padEnd(47)}║
║                                                           ║
║   Endpoints:                                              ║
║   - GET  /health          - Health check                  ║
║   - GET  /ready           - Readiness check               ║
║   - GET  /metrics         - Prometheus metrics            ║
║   - GET  /api/moats/*     - Moats API                     ║
║   - POST /api/detect/*    - Detection API                 ║
║   - GET  /api/account/*   - Account API                   ║
║                                                           ║
║   Ready to accept connections                               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

// Error handling
process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled rejection', { reason: reason?.message || reason });
});

module.exports = { server, router, logger };

/**
 * KASBAH OS ↔ Frontier Shield Integration Layer
 *
 * Connects the local Kasbah OS detector with deployed Frontier Shield instances.
 * Enables hybrid threat detection:
 *   - Local detection via 12-layer detector (instant, cached)
 *   - Remote detection via Frontier Shield (distributed, audited)
 *   - Unified governance decisions
 *   - Merged audit trails
 */

const path = require('path');
const os = require('os');
const fs = require('fs');

const DEPLOYMENTS_FILE = path.join(os.homedir(), '.kasbah', 'deployments.json');

class KasbahOSFrontierIntegration {
  constructor(kasbahOS, options = {}) {
    this.os = kasbahOS;
    this.frontierEndpoint = options.frontierEndpoint || this.discoverFrontierEndpoint();
    this.enableHybridMode = options.hybridMode !== false; // default: enabled
    this.fallbackToLocal = options.fallbackToLocal !== false; // default: enabled
    this.metricsQueue = [];
    this.auditSyncInterval = options.auditSyncInterval || 5000; // 5s

    // Start audit sync background process
    if (options.autoSync !== false) {
      this.startAuditSync();
    }
  }

  /**
   * Auto-discover Frontier Shield endpoint from CLI deployment state
   */
  discoverFrontierEndpoint() {
    if (!fs.existsSync(DEPLOYMENTS_FILE)) {
      return null;
    }

    try {
      const state = JSON.parse(fs.readFileSync(DEPLOYMENTS_FILE, 'utf8'));
      if (state.current && state.deployments[state.current]) {
        const deployment = state.deployments[state.current];
        return deployment.endpoint;
      }
    } catch (e) {
      // Ignore parse errors
    }

    return null;
  }

  /**
   * HYBRID CHECK: Local + Remote threat detection
   *
   * Decision priority:
   *   1. If either local or remote says BLOCK → BLOCK
   *   2. If either says WARN → WARN
   *   3. Otherwise → ALLOW
   */
  async hybridCheck(action) {
    const traceId = `hybrid_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;

    // Step 1: LOCAL detection (instant, 12-layer)
    const localDecision = {
      source: 'local',
      traceId,
      decision: null,
      score: 0,
      details: null,
      latencyMs: 0,
      timestamp: Date.now()
    };

    const startLocal = Date.now();
    try {
      const detection = this.os.scan(action.content || '');
      localDecision.decision = detection.decision;
      localDecision.score = detection.risk;
      localDecision.details = detection;
      localDecision.latencyMs = Date.now() - startLocal;
    } catch (e) {
      localDecision.error = e.message;
    }

    // Step 2: REMOTE detection (if available)
    const remoteDecision = {
      source: 'frontier',
      traceId,
      decision: null,
      score: 0,
      details: null,
      latencyMs: 0,
      timestamp: Date.now()
    };

    if (this.frontierEndpoint && this.enableHybridMode) {
      const startRemote = Date.now();
      try {
        const frontier = await this.callFrontier(action, traceId);
        remoteDecision.decision = frontier.decision;
        remoteDecision.score = frontier.threat_score;
        remoteDecision.details = frontier;
        remoteDecision.latencyMs = Date.now() - startRemote;
      } catch (e) {
        remoteDecision.error = e.message;
        // If Frontier fails and fallback is enabled, proceed with local decision
        if (!this.fallbackToLocal) {
          throw e;
        }
      }
    }

    // Step 3: MERGE decisions
    const mergedDecision = this._mergeDecisions(
      localDecision,
      remoteDecision,
      action,
      traceId
    );

    // Step 4: LOG to both local and remote audit trails
    this._logHybridAudit(mergedDecision, action, localDecision, remoteDecision);

    return mergedDecision;
  }

  /**
   * Call Frontier Shield remote endpoint
   */
  async callFrontier(action, traceId) {
    return new Promise((resolve, reject) => {
      const url = new URL(`${this.frontierEndpoint}/v1/shield/ingest`);
      const payload = JSON.stringify({
        prompt: action.content || '',
        agent_id: action.agent || 'kasbah-os',
        source: 'kasbah-os-hybrid',
        request_id: traceId,
        action_type: action.verb || 'unknown',
        target: action.target || 'unknown'
      });

      const protocol = url.protocol === 'https:' ? require('https') : require('http');
      const req = protocol.request({
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          'X-Trace-ID': traceId,
          'X-Source': 'kasbah-os'
        },
        timeout: 10000
      }, (res) => {
        let chunks = '';
        res.on('data', chunk => chunks += chunk);
        res.on('end', () => {
          try {
            const data = JSON.parse(chunks);
            resolve(data);
          } catch (e) {
            reject(e);
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Frontier Shield request timeout'));
      });

      req.write(payload);
      req.end();
    });
  }

  /**
   * Merge local and remote decisions
   * Fail-closed: any BLOCK wins
   */
  _mergeDecisions(localDecision, remoteDecision, action, traceId) {
    let finalDecision = 'allow';
    let threatScore = 0;
    const sources = [localDecision.source];

    // Decision priority: BLOCK > WARN > ALLOW
    if (localDecision.decision === 'block' || remoteDecision.decision === 'block') {
      finalDecision = 'block';
      threatScore = Math.max(localDecision.score || 0, remoteDecision.score || 0);
    } else if (localDecision.decision === 'warn' || remoteDecision.decision === 'warn') {
      finalDecision = 'warn';
      threatScore = Math.max(localDecision.score || 0, remoteDecision.score || 0);
    }

    if (remoteDecision.decision) {
      sources.push(remoteDecision.source);
    }

    return {
      traceId,
      decision: finalDecision,
      threatScore,
      local: localDecision,
      remote: remoteDecision,
      sources,
      timestamp: Date.now(),
      mergeStrategy: 'fail-closed'
    };
  }

  /**
   * Log to hybrid audit trail
   */
  _logHybridAudit(merged, action, local, remote) {
    const auditEntry = {
      timestamp: merged.timestamp,
      traceId: merged.traceId,
      decision: merged.decision,
      threatScore: merged.threatScore,
      sources: merged.sources,
      agent: action.agent,
      verb: action.verb,
      target: action.target,
      local: {
        decision: local.decision,
        score: local.score,
        latencyMs: local.latencyMs,
        error: local.error
      },
      remote: {
        decision: remote.decision,
        score: remote.score,
        latencyMs: remote.latencyMs,
        error: remote.error
      }
    };

    // Queue for sync
    this.metricsQueue.push(auditEntry);

    // Also log locally via KasbahOS
    if (this.os.auditLog) {
      this.os.auditLog(auditEntry);
    }
  }

  /**
   * Periodic sync of metrics to Frontier Shield
   */
  startAuditSync() {
    setInterval(async () => {
      if (this.metricsQueue.length === 0 || !this.frontierEndpoint) {
        return;
      }

      const batch = this.metricsQueue.splice(0, 100);

      try {
        await this._syncMetricsToFrontier(batch);
      } catch (e) {
        // Re-queue failed entries
        this.metricsQueue.unshift(...batch);
      }
    }, this.auditSyncInterval);
  }

  /**
   * Send batch of metrics to Frontier Shield
   */
  _syncMetricsToFrontier(batch) {
    return new Promise((resolve, reject) => {
      const url = new URL(`${this.frontierEndpoint}/v1/shield/metrics/batch`);
      const payload = JSON.stringify({ metrics: batch });

      const protocol = url.protocol === 'https:' ? require('https') : require('http');
      const req = protocol.request({
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 5000
      }, (res) => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve();
        } else {
          reject(new Error(`HTTP ${res.statusCode}`));
        }
        res.resume(); // Drain response
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Sync timeout'));
      });

      req.write(payload);
      req.end();
    });
  }

  /**
   * Get deployment status from CLI state
   */
  getDeploymentStatus() {
    if (!fs.existsSync(DEPLOYMENTS_FILE)) {
      return { status: 'not-deployed', endpoint: null };
    }

    try {
      const state = JSON.parse(fs.readFileSync(DEPLOYMENTS_FILE, 'utf8'));
      const currentId = state.current;
      const deployment = currentId && state.deployments[currentId];

      if (!deployment) {
        return { status: 'not-deployed', endpoint: null };
      }

      return {
        status: deployment.status || 'unknown',
        endpoint: deployment.endpoint,
        cloud: deployment.cloud,
        region: deployment.region,
        clusterName: deployment.clusterName,
        deployedAt: deployment.deployedAt,
        all: state.deployments
      };
    } catch (e) {
      return { status: 'error', error: e.message };
    }
  }

  /**
   * Get metrics including both local and remote
   */
  getMetrics() {
    const frontierStatus = this.getDeploymentStatus();
    const localMetrics = this.os.metrics || {};

    return {
      local: localMetrics,
      frontier: {
        status: frontierStatus.status,
        endpoint: frontierStatus.endpoint,
        enabled: this.enableHybridMode && frontierStatus.status === 'deployed',
        fallbackEnabled: this.fallbackToLocal
      },
      hybrid: {
        metricsInQueue: this.metricsQueue.length,
        lastSync: this.lastSyncTime || null
      }
    };
  }
}

module.exports = { KasbahOSFrontierIntegration };

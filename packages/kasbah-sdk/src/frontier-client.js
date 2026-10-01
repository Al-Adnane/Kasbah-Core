/**
 * Kasbah Frontier Shield Client
 * Auto-discovers deployed Frontier Shield endpoints and sends requests
 *
 * Usage:
 *   const client = new FrontierClient();
 *   const decision = await client.ingestPrompt("user input", { agent_id: "agent-1" });
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');

const DEPLOYMENTS_FILE = path.join(os.homedir(), '.kasbah', 'deployments.json');

class FrontierClient {
  constructor(options = {}) {
    this.endpoint = options.endpoint || this.discoverEndpoint();
    this.timeout = options.timeout || 30000;
    this.retries = options.retries || 3;
  }

  /**
   * Auto-discover Frontier Shield endpoint from deployment state
   */
  discoverEndpoint() {
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
   * Check if endpoint is healthy
   */
  async checkHealth() {
    if (!this.endpoint) return false;

    try {
      const response = await this.request('GET', '/v1/shield/health');
      return response && response.status === 'healthy';
    } catch (e) {
      return false;
    }
  }

  /**
   * Ingest a prompt and get threat detection result
   */
  async ingestPrompt(prompt, metadata = {}) {
    if (!this.endpoint) {
      throw new Error(
        'No Frontier Shield endpoint discovered. ' +
        'Run: kasbah deploy init <cloud> && kasbah deploy apply'
      );
    }

    const payload = {
      prompt,
      agent_id: metadata.agent_id || 'sdk-client',
      source: metadata.source || 'sdk',
      request_id: metadata.request_id || this.generateId(),
      ...metadata
    };

    return this.request('POST', '/v1/shield/ingest', payload);
  }

  /**
   * Check multi-agent interaction for collusion
   */
  async checkInteraction(fromAgent, toAgent, message, allAgents = []) {
    if (!this.endpoint) {
      throw new Error(
        'No Frontier Shield endpoint discovered. ' +
        'Run: kasbah deploy init <cloud> && kasbah deploy apply'
      );
    }

    const payload = {
      from_agent: fromAgent,
      to_agent: toAgent,
      message,
      agents: allAgents
    };

    return this.request('POST', '/v1/shield/check-interaction', payload);
  }

  /**
   * Get audit chain root for compliance verification
   */
  async getAuditRoot() {
    if (!this.endpoint) {
      throw new Error('No Frontier Shield endpoint discovered');
    }

    return this.request('GET', '/v1/shield/audit/root');
  }

  /**
   * Get operational statistics
   */
  async getStats() {
    if (!this.endpoint) {
      throw new Error('No Frontier Shield endpoint discovered');
    }

    return this.request('GET', '/v1/shield/stats');
  }

  /**
   * Make HTTP request with retry logic
   */
  async request(method, path, body = null, attempt = 0) {
    return new Promise((resolve, reject) => {
      try {
        const url = new URL(this.endpoint + path);
        const lib = url.protocol === 'https:' ? https : http;
        const data = body ? JSON.stringify(body) : null;

        const req = lib.request({
          hostname: url.hostname,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: url.pathname + (url.search || ''),
          method,
          headers: {
            'Accept': 'application/json',
            ...(data ? {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(data)
            } : {})
          },
          timeout: this.timeout
        }, (res) => {
          let chunks = '';
          res.on('data', chunk => chunks += chunk);
          res.on('end', () => {
            try {
              const parsed = chunks ? JSON.parse(chunks) : null;
              if (res.statusCode >= 200 && res.statusCode < 300) {
                resolve(parsed);
              } else {
                const error = new Error(`HTTP ${res.statusCode}`);
                error.status = res.statusCode;
                error.body = parsed;
                reject(error);
              }
            } catch (e) {
              reject(e);
            }
          });
        });

        req.on('error', (error) => {
          if (attempt < this.retries) {
            setTimeout(() => {
              this.request(method, path, body, attempt + 1)
                .then(resolve)
                .catch(reject);
            }, Math.pow(2, attempt) * 1000);
          } else {
            reject(error);
          }
        });

        req.on('timeout', () => {
          req.destroy();
          reject(new Error('Request timeout'));
        });

        if (data) req.write(data);
        req.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Generate unique request ID
   */
  generateId() {
    return `req-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  }
}

module.exports = { FrontierClient };

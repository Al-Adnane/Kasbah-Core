/**
 * ============================================================================
 * KASBAH CORE - JavaScript Wrapper
 * ============================================================================
 * 
 * JavaScript/Node.js wrapper for kasbah-core Python engine.
 * Provides seamless integration between Node.js and Python core.
 * 
 * Features:
 * - Python bridge via child_process
 * - Express server integration
 * - WebSocket support
 * - Promise-based API
 * - Error handling
 * 
 * Usage:
 *   const KasbahCore = require('@kasbah/core');
 *   const core = new KasbahCore();
 *   await core.initialize();
 *   const result = await core.detect({ text: 'content to analyze' });
 */

const { spawn } = require('child_process');
const path = require('path');
const EventEmitter = require('events');

// ============================================================================
// KASBAH CORE CLASS
// ============================================================================

class KasbahCore extends EventEmitter {
  constructor(config = {}) {
    super();
    
    this.config = {
      pythonPath: config.pythonPath || 'python3',
      corePath: config.corePath || path.join(__dirname, '..', 'kasbah-core-python'),
      timeout: config.timeout || 30000,
      maxRetries: config.maxRetries || 3,
      ...config
    };
    
    this.pythonBridge = null;
    this.initialized = false;
    this.requestId = 0;
    this.pendingRequests = new Map();
    this.retryCount = 0;
  }

  /**
   * Initialize Kasbah Core
   */
  async initialize() {
    return new Promise((resolve, reject) => {
      try {
        // Start Python bridge
        this.pythonBridge = spawn(this.config.pythonPath, [
          '-m', 'kasbah_core.bridge'
        ], {
          cwd: this.config.corePath,
          stdio: ['pipe', 'pipe', 'pipe']
        });

        // Handle Python stdout
        this.pythonBridge.stdout.on('data', (data) => {
          this._handlePythonResponse(data.toString());
        });

        // Handle Python stderr
        this.pythonBridge.stderr.on('data', (data) => {
          console.error('[KasbahCore] Python error:', data.toString());
        });

        // Handle process exit
        this.pythonBridge.on('exit', (code) => {
          this.initialized = false;
          this.emit('exit', code);
          if (code !== 0 && this.retryCount < this.config.maxRetries) {
            this._reconnect();
          }
        });

        // Wait for initialization
        const initTimeout = setTimeout(() => {
          reject(new Error('Initialization timeout'));
        }, this.config.timeout);

        this.once('ready', () => {
          clearTimeout(initTimeout);
          this.initialized = true;
          this.retryCount = 0;
          resolve(this);
        });

        // Send initialization request
        this._sendRequest({ action: 'init' });

      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Detect threats in content
   */
  async detect(content) {
    if (!this.initialized) {
      throw new Error('KasbahCore not initialized. Call initialize() first.');
    }

    const result = await this._sendRequest({
      action: 'detect',
      content
    });

    this.emit('detection', result);
    return result;
  }

  /**
   * Get moats status
   */
  async getMoatsStatus() {
    return await this._sendRequest({ action: 'moats_status' });
  }

  /**
   * Get system integrity index
   */
  async getIntegrityIndex() {
    return await this._sendRequest({ action: 'integrity_index' });
  }

  /**
   * Export audit ledger
   */
  async exportAuditLedger(options = {}) {
    return await this._sendRequest({
      action: 'export_audit',
      options
    });
  }

  /**
   * Shutdown Kasbah Core
   */
  async shutdown() {
    if (this.pythonBridge) {
      await this._sendRequest({ action: 'shutdown' });
      this.pythonBridge.kill();
      this.pythonBridge = null;
      this.initialized = false;
    }
  }

  /**
   * Send request to Python bridge
   */
  _sendRequest(request) {
    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error(`Request ${id} timeout`));
      }, this.config.timeout);

      this.pendingRequests.set(id, { resolve, reject, timeout });

      const message = JSON.stringify({ id, ...request });
      this.pythonBridge.stdin.write(message + '\n');
    });
  }

  /**
   * Handle Python response
   */
  _handlePythonResponse(data) {
    try {
      const response = JSON.parse(data.trim());
      
      if (response.id && this.pendingRequests.has(response.id)) {
        const { resolve, reject, timeout } = this.pendingRequests.get(response.id);
        clearTimeout(timeout);
        this.pendingRequests.delete(response.id);

        if (response.error) {
          reject(new Error(response.error));
        } else if (response.action === 'init' && response.status === 'ready') {
          this.emit('ready');
        } else {
          resolve(response);
        }
      } else if (response.event) {
        this.emit(response.event, response.data);
      }
    } catch (error) {
      console.error('[KasbahCore] Failed to parse response:', error);
    }
  }

  /**
   * Reconnect to Python bridge
   */
  _reconnect() {
    this.retryCount++;
    console.log(`[KasbahCore] Reconnecting (attempt ${this.retryCount}/${this.config.maxRetries})...`);
    
    setTimeout(() => {
      this.initialize().catch((error) => {
        console.error('[KasbahCore] Reconnection failed:', error);
      });
    }, 1000 * this.retryCount);
  }
}

// ============================================================================
// EXPRESS SERVER INTEGRATION
// ============================================================================

class KasbahServer {
  constructor(core, config = {}) {
    this.core = core;
    this.config = {
      port: config.port || 3000,
      host: config.host || 'localhost',
      ...config
    };
    
    this.app = null;
    this.server = null;
  }

  /**
   * Start Express server
   */
  async start() {
    const express = require('express');
    this.app = express();

    // Middleware
    this.app.use(express.json());
    this.app.use((req, res, next) => {
      req.startTime = Date.now();
      next();
    });

    // Routes
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        core: this.core.initialized ? 'online' : 'offline',
        uptime: process.uptime()
      });
    });

    this.app.post('/detect', async (req, res) => {
      try {
        const startTime = Date.now();
        const result = await this.core.detect(req.body);
        const latency = Date.now() - startTime;
        
        res.json({
          ...result,
          latency_ms: latency
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/moats', async (req, res) => {
      try {
        const status = await this.core.getMoatsStatus();
        res.json(status);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/integrity', async (req, res) => {
      try {
        const integrity = await this.core.getIntegrityIndex();
        res.json(integrity);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/audit', async (req, res) => {
      try {
        const audit = await this.core.exportAuditLedger(req.query);
        res.json(audit);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Start server
    this.server = this.app.listen(this.config.port, this.config.host, () => {
      console.log(`🛡️  Kasbah Server running at http://${this.config.host}:${this.config.port}`);
    });

    return this.server;
  }

  /**
   * Stop Express server
   */
  async stop() {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
  }
}

// ============================================================================
// WEBSOCKET INTEGRATION
// ============================================================================

class KasbahWebSocket {
  constructor(core, config = {}) {
    this.core = core;
    this.config = {
      port: config.wsPort || 3001,
      ...config
    };
    
    this.wss = null;
    this.clients = new Set();
  }

  /**
   * Start WebSocket server
   */
  async start() {
    const WebSocket = require('ws');
    this.wss = new WebSocket.Server({ port: this.config.port });

    this.wss.on('connection', (ws) => {
      this.clients.add(ws);
      console.log(`[WebSocket] Client connected. Total: ${this.clients.size}`);

      ws.on('close', () => {
        this.clients.delete(ws);
        console.log(`[WebSocket] Client disconnected. Total: ${this.clients.size}`);
      });

      ws.on('message', async (message) => {
        try {
          const data = JSON.parse(message);
          const result = await this.core.detect(data);
          ws.send(JSON.stringify(result));
        } catch (error) {
          ws.send(JSON.stringify({ error: error.message }));
        }
      });
    });

    // Forward detection events to all clients
    this.core.on('detection', (result) => {
      this.broadcast({
        type: 'detection',
        data: result
      });
    });

    console.log(`🔌 Kasbah WebSocket running on ws://localhost:${this.config.port}`);
    return this.wss;
  }

  /**
   * Broadcast message to all clients
   */
  broadcast(message) {
    const data = JSON.stringify(message);
    for (const client of this.clients) {
      if (client.readyState === 1) { // WebSocket.OPEN
        client.send(data);
      }
    }
  }

  /**
   * Stop WebSocket server
   */
  async stop() {
    if (this.wss) {
      this.wss.close();
      this.wss = null;
      this.clients.clear();
    }
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

// KasbahPipeline: alias used by Nexus/Forge/Cortex products
const KasbahPipeline = KasbahCore;

module.exports = {
  KasbahCore,
  KasbahPipeline,
  KasbahServer,
  KasbahWebSocket,

  // Convenience functions
  createKasbahCore: (config) => new KasbahCore(config),
  createKasbahPipeline: (config) => new KasbahCore(config)
};

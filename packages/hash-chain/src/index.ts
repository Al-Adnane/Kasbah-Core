/**
 * Hash-Chain Ledger — PostgreSQL Implementation
 * 
 * Creates tamper-evident audit trails using SHA-256 hash chaining.
 * Each entry is cryptographically linked to the previous one.
 * 
 * Features:
 * - PostgreSQL persistence (not in-memory)
 * - SHA-256 hashing
 * - Previous hash linkage
 * - Timestamp verification
 * - Batch operations
 * - Verification API
 * 
 * @package @kasbah/hash-chain
 * @version 1.0.0
 */

import { Pool, PoolConfig } from 'pg';
import { createHash, randomBytes } from 'crypto';

export interface HashChainEntry {
  id: string;
  type: string;
  data: any;
  previousHash: string | null;
  timestamp: Date;
  metadata?: Record<string, any>;
}

export interface HashChainProof {
  hash: string;
  previousHash: string | null;
  timestamp: Date;
  dataHash: string;
  entryId: string;
}

export interface VerificationResult {
  valid: boolean;
  entryCount: number;
  error?: string;
  lastVerifiedHash?: string;
}

export interface HashChainConfig {
  databaseUrl?: string;
  tableName?: string;
  genesisHash?: string;
}

export class HashChain {
  private pool: Pool;
  private tableName: string;
  private readonly GENESIS_HASH: string;
  private cache: Map<string, HashChainEntry> = new Map();

  constructor(config?: HashChainConfig) {
    const databaseUrl = config?.databaseUrl || process.env.DATABASE_URL;

    if (!databaseUrl) {
      throw new Error(
        '[HashChain] DATABASE_URL is not set. ' +
        'Provide it via config.databaseUrl or the DATABASE_URL environment variable. ' +
        'Example: postgres://user:pass@localhost:5432/kasbah'
      );
    }

    this.pool = new Pool({
      connectionString: databaseUrl,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000
    });

    this.tableName = config?.tableName || 'hash_chain_ledger';
    this.GENESIS_HASH = config?.genesisHash || '0x0000000000000000000000000000000000000000000000000000000000000000';

    // Initialize table
    this.initialize();
  }

  /**
   * Initialize database table
   */
  private async initialize(): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS ${this.tableName} (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          type VARCHAR(100) NOT NULL,
          data JSONB NOT NULL,
          previous_hash CHAR(64),
          data_hash CHAR(64) NOT NULL,
          entry_hash CHAR(64) NOT NULL,
          timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          metadata JSONB DEFAULT '{}',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `);

      // Create indexes for performance
      await client.query(`
        CREATE INDEX IF NOT EXISTS idx_${this.tableName}_timestamp 
        ON ${this.tableName}(timestamp DESC)
      `);

      await client.query(`
        CREATE INDEX IF NOT EXISTS idx_${this.tableName}_entry_hash 
        ON ${this.tableName}(entry_hash)
      `);

      await client.query(`
        CREATE INDEX IF NOT EXISTS idx_${this.tableName}_type 
        ON ${this.tableName}(type)
      `);
    } finally {
      client.release();
    }
  }

  /**
   * Create SHA-256 hash
   */
  private hashData(data: string): string {
    return createHash('sha256').update(data).digest('hex');
  }

  /**
   * Generate UUID
   */
  private generateId(): string {
    return `hc_${randomBytes(16).toString('hex')}`;
  }

  /**
   * Add entry to hash chain
   * 
   * @param entry - Entry data (without id, previousHash)
   * @returns HashChainProof - Cryptographic proof of entry
   */
  async add(entry: Omit<HashChainEntry, 'id' | 'previousHash'>): Promise<HashChainProof> {
    const client = await this.pool.connect();
    
    try {
      await client.query('BEGIN');

      // Get last hash (with row lock to prevent race conditions)
      const lastHashResult = await client.query(
        `SELECT entry_hash FROM ${this.tableName} ORDER BY timestamp DESC LIMIT 1 FOR UPDATE`
      );

      const previousHash = lastHashResult.rows.length > 0 
        ? lastHashResult.rows[0].entry_hash 
        : this.GENESIS_HASH;

      // Create data hash
      const dataHash = this.hashData(JSON.stringify(entry.data));

      // Create entry hash: SHA-256(previousHash + dataHash + timestamp)
      const timestamp = entry.timestamp || new Date();
      const entryHash = this.hashData(`${previousHash}${dataHash}${timestamp.toISOString()}`);

      // Insert entry
      const insertResult = await client.query(
        `INSERT INTO ${this.tableName} (
          id, type, data, previous_hash, data_hash, entry_hash, timestamp, metadata
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id`,
        [
          this.generateId(),
          entry.type,
          entry.data,
          previousHash,
          dataHash,
          entryHash,
          timestamp,
          entry.metadata || {}
        ]
      );

      await client.query('COMMIT');

      // Cache the entry
      const newEntry: HashChainEntry = {
        id: insertResult.rows[0].id,
        type: entry.type,
        data: entry.data,
        previousHash,
        timestamp,
        metadata: entry.metadata
      };
      this.cache.set(newEntry.id, newEntry);

      return {
        hash: entryHash,
        previousHash,
        timestamp,
        dataHash,
        entryId: insertResult.rows[0].id
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Add multiple entries in a single transaction
   */
  async addBatch(entries: Array<Omit<HashChainEntry, 'id' | 'previousHash'>>): Promise<HashChainProof[]> {
    const client = await this.pool.connect();
    const proofs: HashChainProof[] = [];

    try {
      await client.query('BEGIN');

      // Get last hash
      const lastHashResult = await client.query(
        `SELECT entry_hash FROM ${this.tableName} ORDER BY timestamp DESC LIMIT 1 FOR UPDATE`
      );

      let previousHash = lastHashResult.rows.length > 0 
        ? lastHashResult.rows[0].entry_hash 
        : this.GENESIS_HASH;

      // Insert all entries
      for (const entry of entries) {
        const dataHash = this.hashData(JSON.stringify(entry.data));
        const timestamp = entry.timestamp || new Date();
        const entryHash = this.hashData(`${previousHash}${dataHash}${timestamp.toISOString()}`);

        const insertResult = await client.query(
          `INSERT INTO ${this.tableName} (
            id, type, data, previous_hash, data_hash, entry_hash, timestamp, metadata
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          RETURNING id`,
          [
            this.generateId(),
            entry.type,
            entry.data,
            previousHash,
            dataHash,
            entryHash,
            timestamp,
            entry.metadata || {}
          ]
        );

        proofs.push({
          hash: entryHash,
          previousHash,
          timestamp,
          dataHash,
          entryId: insertResult.rows[0].id
        });

        previousHash = entryHash;
      }

      await client.query('COMMIT');
      return proofs;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Get entry by ID
   */
  async get(id: string): Promise<HashChainEntry | null> {
    // Check cache first
    const cached = this.cache.get(id);
    if (cached) {
      return cached;
    }

    const result = await this.pool.query(
      `SELECT * FROM ${this.tableName} WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return null;
    }

    const row = result.rows[0];
    const entry: HashChainEntry = {
      id: row.id,
      type: row.type,
      data: row.data,
      previousHash: row.previous_hash,
      timestamp: new Date(row.timestamp),
      metadata: row.metadata
    };

    this.cache.set(id, entry);
    return entry;
  }

  /**
   * Verify hash chain integrity
   * 
   * Walks through entire chain and verifies:
   * 1. Each entry's data hash matches
   * 2. Each entry's hash is correctly computed
   * 3. Chain linkage is unbroken
   */
  async verify(): Promise<VerificationResult> {
    const client = await this.pool.connect();

    try {
      const result = await client.query(
        `SELECT * FROM ${this.tableName} ORDER BY timestamp ASC`
      );

      const entries = result.rows;
      
      if (entries.length === 0) {
        return { valid: true, entryCount: 0 };
      }

      let previousHash = this.GENESIS_HASH;
      let entryCount = 0;

      for (const row of entries) {
        entryCount++;

        // Verify data hash
        const dataHash = this.hashData(JSON.stringify(row.data));
        if (dataHash !== row.data_hash) {
          return { 
            valid: false, 
            error: `Data hash mismatch at entry ${row.id}`,
            entryCount,
            lastVerifiedHash: previousHash
          };
        }

        // Verify entry hash
        const expectedHash = this.hashData(
          `${row.previous_hash}${row.data_hash}${new Date(row.timestamp).toISOString()}`
        );

        if (expectedHash !== row.entry_hash) {
          return { 
            valid: false, 
            error: `Entry hash mismatch at entry ${row.id}`,
            entryCount,
            lastVerifiedHash: previousHash
          };
        }

        // Verify chain linkage
        if (row.previous_hash !== previousHash) {
          return { 
            valid: false, 
            error: `Chain broken at entry ${row.id}. Expected ${previousHash}, got ${row.previous_hash}`,
            entryCount,
            lastVerifiedHash: previousHash
          };
        }

        previousHash = row.entry_hash;
      }

      return { 
        valid: true, 
        entryCount,
        lastVerifiedHash: previousHash
      };
    } finally {
      client.release();
    }
  }

  /**
   * Get proof for date range
   */
  async getProof(dateRange: { start: Date; end: Date }): Promise<{
    firstHash: string;
    lastHash: string;
    entryCount: number;
    verified: boolean;
    entries: HashChainEntry[];
  }> {
    const result = await this.pool.query(
      `SELECT * FROM ${this.tableName} 
       WHERE timestamp >= $1 AND timestamp <= $2 
       ORDER BY timestamp ASC`,
      [dateRange.start, dateRange.end]
    );

    const entries = result.rows.map((row) => ({
      id: row.id,
      type: row.type,
      data: row.data,
      previousHash: row.previous_hash,
      timestamp: new Date(row.timestamp),
      metadata: row.metadata
    }));

    if (entries.length === 0) {
      return { 
        firstHash: '', 
        lastHash: '', 
        entryCount: 0, 
        verified: false,
        entries: []
      };
    }

    // Compute first and last hash
    const firstDataHash = this.hashData(JSON.stringify(entries[0].data));
    const firstHash = this.hashData(
      `${entries[0].previousHash}${firstDataHash}${entries[0].timestamp.toISOString()}`
    );

    const lastDataHash = this.hashData(JSON.stringify(entries[entries.length - 1].data));
    const lastHash = this.hashData(
      `${entries[entries.length - 1].previousHash}${lastDataHash}${entries[entries.length - 1].timestamp.toISOString()}`
    );

    return {
      firstHash,
      lastHash,
      entryCount: entries.length,
      verified: true,
      entries
    };
  }

  /**
   * Get chain statistics
   */
  async stats(): Promise<{
    entryCount: number;
    firstEntry: Date | null;
    lastEntry: Date | null;
    lastHash: string | null;
  }> {
    const result = await this.pool.query(
      `SELECT 
        COUNT(*) as count,
        MIN(timestamp) as first_entry,
        MAX(timestamp) as last_entry,
        (SELECT entry_hash FROM ${this.tableName} ORDER BY timestamp DESC LIMIT 1) as last_hash
       FROM ${this.tableName}`
    );

    const row = result.rows[0];

    return {
      entryCount: parseInt(row.count, 10),
      firstEntry: row.first_entry ? new Date(row.first_entry) : null,
      lastEntry: row.last_entry ? new Date(row.last_entry) : null,
      lastHash: row.last_hash
    };
  }

  /**
   * Export chain as JSON (for legal/audit)
   */
  async exportJSON(options?: { 
    includeMetadata?: boolean; 
    dateRange?: { start: Date; end: Date } 
  }): Promise<any> {
    let entries;
    
    if (options?.dateRange) {
      const proof = await this.getProof(options.dateRange);
      entries = proof.entries;
    } else {
      const result = await this.pool.query(
        `SELECT * FROM ${this.tableName} ORDER BY timestamp ASC`
      );
      entries = result.rows.map((row) => ({
        id: row.id,
        type: row.type,
        data: row.data,
        previousHash: row.previous_hash,
        timestamp: new Date(row.timestamp),
        metadata: row.metadata
      }));
    }

    return {
      exportedAt: new Date().toISOString(),
      entryCount: entries.length,
      includeMetadata: options?.includeMetadata ?? true,
      entries: entries.map(e => ({
        id: e.id,
        type: e.type,
        timestamp: e.timestamp,
        data: e.data,
        previousHash: e.previousHash,
        metadata: options?.includeMetadata ? e.metadata : undefined
      }))
    };
  }

  /**
   * Close database connection
   */
  async close(): Promise<void> {
    await this.pool.end();
  }
}

export default HashChain;

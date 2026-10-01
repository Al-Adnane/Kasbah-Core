#!/usr/bin/env node
/**
 * Kasbah Deployment Manager
 * Integrates Terraform infrastructure with CLI/SDK/MCP
 *
 * Commands:
 *   kasbah deploy init <cloud> [--region REGION] [--config FILE]
 *   kasbah deploy apply [--auto-approve]
 *   kasbah deploy status
 *   kasbah deploy endpoint
 *   kasbah deploy logs [--pod POD] [--tail N]
 *   kasbah deploy scale --replicas N
 *   kasbah deploy destroy [--force]
 *   kasbah deploy verify
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const os = require('os');

const KASBAH_HOME = path.join(os.homedir(), '.kasbah');
const TERRAFORM_DIR = path.join(process.cwd(), 'terraform');
const DEPLOYMENT_STATE_FILE = path.join(KASBAH_HOME, 'deployments.json');
const MCP_CONFIG_FILE = path.join(os.homedir(), '.mcp.json');

class DeploymentManager {
  constructor() {
    this.state = this.loadState();
    this.ensureDirectories();
  }

  loadState() {
    if (!fs.existsSync(DEPLOYMENT_STATE_FILE)) {
      return { deployments: {}, current: null };
    }
    try {
      return JSON.parse(fs.readFileSync(DEPLOYMENT_STATE_FILE, 'utf8'));
    } catch (e) {
      return { deployments: {}, current: null };
    }
  }

  saveState() {
    fs.mkdirSync(KASBAH_HOME, { recursive: true });
    fs.writeFileSync(DEPLOYMENT_STATE_FILE, JSON.stringify(this.state, null, 2));
  }

  ensureDirectories() {
    fs.mkdirSync(KASBAH_HOME, { recursive: true });
    if (!fs.existsSync(TERRAFORM_DIR)) {
      throw new Error(`Terraform directory not found: ${TERRAFORM_DIR}`);
    }
  }

  async init(cloud, options = {}) {
    console.log(`🚀 Initializing Kasbah deployment on ${cloud.toUpperCase()}...`);

    const deploymentName = options.name || `${cloud}-${Date.now()}`;
    const region = options.region || this.getDefaultRegion(cloud);
    const configFile = options.config || `${cloud}.tfvars`;

    // Create tfvars file if not exists
    const tfvarsPath = path.join(TERRAFORM_DIR, configFile);
    if (!fs.existsSync(tfvarsPath)) {
      const examplePath = path.join(TERRAFORM_DIR, `${cloud}.tfvars.example`);
      if (!fs.existsSync(examplePath)) {
        throw new Error(`No example config found: ${examplePath}`);
      }
      console.log(`📝 Creating ${configFile} from template...`);
      let config = fs.readFileSync(examplePath, 'utf8');
      config = config.replace(/region = .*/, `region = "${region}"`);
      if (cloud === 'gcp') {
        config = config.replace(/gcp_project_id = .*/, `gcp_project_id = "${process.env.GCP_PROJECT_ID || 'your-project'}"`);
      }
      fs.writeFileSync(tfvarsPath, config);
      console.log(`✅ Created: ${tfvarsPath}`);
    }

    // Initialize Terraform
    console.log('📦 Initializing Terraform...');
    this.exec(`cd "${TERRAFORM_DIR}" && terraform init`, {
      timeout: 300000,
      stdio: 'inherit'
    });

    // Store deployment metadata
    this.state.deployments[deploymentName] = {
      cloud,
      region,
      configFile,
      tfvarsPath,
      status: 'initialized',
      createdAt: new Date().toISOString(),
      endpoint: null,
      kubeconfig: null,
    };
    this.state.current = deploymentName;
    this.saveState();

    console.log(`\n✨ Deployment '${deploymentName}' initialized!`);
    console.log(`   Cloud: ${cloud}`);
    console.log(`   Region: ${region}`);
    console.log(`   Config: ${tfvarsPath}`);
    console.log(`\nNext: kasbah deploy apply\n`);

    return deploymentName;
  }

  async apply(options = {}) {
    const deployment = this.getCurrentDeployment();
    console.log(`🚀 Applying infrastructure for '${deployment.cloud}' deployment...`);
    console.log(`   Config: ${deployment.configFile}`);

    const tfvarsPath = path.join(TERRAFORM_DIR, deployment.configFile);
    const autoApprove = options.autoApprove ? '-auto-approve' : '';

    try {
      this.exec(
        `cd "${TERRAFORM_DIR}" && terraform apply ${autoApprove} -var-file="${deployment.configFile}"`,
        { timeout: 1800000, stdio: 'inherit' }
      );

      // Get outputs
      console.log('\n📊 Retrieving deployment information...');
      const outputs = JSON.parse(
        this.exec(`cd "${TERRAFORM_DIR}" && terraform output -json`, { timeout: 60000 })
      );

      // Update deployment state
      deployment.status = 'deployed';
      deployment.endpoint = outputs.frontier_shield?.value?.service_endpoint;
      deployment.kubeconfig = outputs.kubeconfig_command?.value;
      deployment.clusterName = outputs.cluster_info?.value?.name;
      deployment.deployedAt = new Date().toISOString();

      this.saveState();

      // Update MCP config
      await this.updateMCPConfig(deployment, outputs);

      // Print summary
      console.log('\n' + '='.repeat(60));
      console.log('✅ DEPLOYMENT SUCCESSFUL');
      console.log('='.repeat(60));
      console.log(`Cluster: ${deployment.clusterName}`);
      console.log(`Endpoint: ${deployment.endpoint}`);
      console.log(`Region: ${deployment.cloud}`);
      console.log('');
      console.log('Next steps:');
      console.log(`  1. Update kubeconfig: ${deployment.kubeconfig}`);
      console.log(`  2. Verify deployment: kasbah deploy verify`);
      console.log(`  3. View logs: kasbah deploy logs`);
      console.log(`  4. Scale pods: kasbah deploy scale --replicas 5`);
      console.log('');

    } catch (error) {
      deployment.status = 'failed';
      deployment.error = error.message;
      this.saveState();
      throw error;
    }
  }

  async updateMCPConfig(deployment, outputs) {
    console.log('🔗 Updating MCP configuration...');

    let mcp = {};
    if (fs.existsSync(MCP_CONFIG_FILE)) {
      mcp = JSON.parse(fs.readFileSync(MCP_CONFIG_FILE, 'utf8'));
    }

    // Add/update Frontier Shield server
    if (!mcp.mcpServers) mcp.mcpServers = {};

    const endpoint = deployment.endpoint || outputs.frontier_shield?.value?.service_endpoint;

    mcp.mcpServers['kasbah-frontier-shield'] = {
      command: 'curl',
      args: [`--unix-socket`, `/tmp/kasbah-${deployment.cloud}.sock`, `http://localhost/v1/shield`],
      environment: {
        FRONTIER_SHIELD_ENDPOINT: endpoint,
        KASBAH_DEPLOYMENT: deployment.cloud,
        KASBAH_CLUSTER: deployment.clusterName,
      }
    };

    fs.mkdirSync(path.dirname(MCP_CONFIG_FILE), { recursive: true });
    fs.writeFileSync(MCP_CONFIG_FILE, JSON.stringify(mcp, null, 2));
    console.log(`✅ Updated MCP config: ${MCP_CONFIG_FILE}`);
  }

  async verify() {
    const deployment = this.getCurrentDeployment();
    console.log(`🔍 Verifying deployment '${deployment.cloud}'...`);

    try {
      // Execute kubeconfig command
      if (deployment.kubeconfig) {
        console.log('Setting up kubeconfig...');
        this.exec(deployment.kubeconfig, { timeout: 30000 });
      }

      // Check cluster
      console.log('Checking cluster health...');
      const nodes = JSON.parse(
        this.exec('kubectl get nodes -o json', { timeout: 30000 })
      );
      console.log(`  ✅ Nodes: ${nodes.items.length}`);

      // Check Frontier Shield pods
      console.log('Checking Frontier Shield pods...');
      const pods = JSON.parse(
        this.exec('kubectl get pods -n kasbah-frontier -o json', { timeout: 30000 })
      );
      const readyPods = pods.items.filter(p =>
        p.status.conditions.some(c => c.type === 'Ready' && c.status === 'True')
      );
      console.log(`  ✅ Ready pods: ${readyPods.length}/${pods.items.length}`);

      // Health check
      if (deployment.endpoint) {
        console.log('Testing health endpoint...');
        try {
          const health = JSON.parse(
            this.execHttp('GET', `${deployment.endpoint}/v1/shield/health`)
          );
          console.log(`  ✅ Health: ${health.status}`);
          console.log(`  ✅ Requests: ${health.requests_processed}`);
          console.log(`  ✅ Threats detected: ${health.threats_detected}`);
        } catch (e) {
          console.log(`  ⚠️  Health check failed: ${e.message}`);
        }
      }

      console.log('\n✨ Deployment verified!\n');

    } catch (error) {
      console.error(`\n❌ Verification failed: ${error.message}\n`);
      throw error;
    }
  }

  async status() {
    if (Object.keys(this.state.deployments).length === 0) {
      console.log('No deployments found. Run: kasbah deploy init <cloud>\n');
      return;
    }

    console.log('\n📋 DEPLOYMENTS\n');
    console.log('Name'.padEnd(30) + 'Cloud'.padEnd(10) + 'Status'.padEnd(15) + 'Region');
    console.log('-'.repeat(70));

    for (const [name, dep] of Object.entries(this.state.deployments)) {
      const current = name === this.state.current ? '→ ' : '  ';
      console.log(
        current + name.padEnd(28) +
        dep.cloud.padEnd(10) +
        dep.status.padEnd(15) +
        dep.region
      );
    }

    const current = this.state.deployments[this.state.current];
    if (current) {
      console.log('\n📌 Current:');
      console.log(`  Name: ${this.state.current}`);
      console.log(`  Cloud: ${current.cloud}`);
      console.log(`  Status: ${current.status}`);
      console.log(`  Endpoint: ${current.endpoint || 'N/A'}`);
      console.log(`  Created: ${current.createdAt}`);
      if (current.deployedAt) {
        console.log(`  Deployed: ${current.deployedAt}`);
      }
    }
    console.log('');
  }

  async endpoint() {
    const deployment = this.getCurrentDeployment();
    if (!deployment.endpoint) {
      console.error('❌ No endpoint available. Run: kasbah deploy apply\n');
      process.exit(1);
    }
    console.log(deployment.endpoint);
  }

  async logs(options = {}) {
    const pod = options.pod || '-l app=kasbah-frontier';
    const tail = options.tail || '50';

    const command = `kubectl logs -n kasbah-frontier ${pod} --tail=${tail} -f`;
    this.exec(command, { stdio: 'inherit' });
  }

  async scale(options = {}) {
    const deployment = this.getCurrentDeployment();
    const replicas = options.replicas || 5;

    console.log(`📈 Scaling Frontier Shield to ${replicas} replicas...`);

    const tfvarsPath = path.join(TERRAFORM_DIR, deployment.configFile);
    this.exec(
      `cd "${TERRAFORM_DIR}" && terraform apply -auto-approve ` +
      `-var-file="${deployment.configFile}" ` +
      `-var='initial_replicas=${replicas}' ` +
      `-var='min_replicas=${replicas}'`,
      { timeout: 600000, stdio: 'inherit' }
    );

    console.log(`✅ Scaled to ${replicas} replicas\n`);
  }

  async destroy(options = {}) {
    const deployment = this.getCurrentDeployment();

    if (!options.force) {
      console.log(`\n⚠️  This will DESTROY all resources for '${this.state.current}'`);
      console.log('Add --force to confirm\n');
      return;
    }

    console.log(`🗑️  Destroying deployment '${this.state.current}'...`);

    this.exec(
      `cd "${TERRAFORM_DIR}" && terraform destroy -auto-approve ` +
      `-var-file="${deployment.configFile}"`,
      { timeout: 600000, stdio: 'inherit' }
    );

    deployment.status = 'destroyed';
    deployment.destroyedAt = new Date().toISOString();
    this.saveState();

    console.log(`✅ Destroyed\n`);
  }

  getCurrentDeployment() {
    if (!this.state.current || !this.state.deployments[this.state.current]) {
      throw new Error('No active deployment. Run: kasbah deploy init <cloud>');
    }
    return this.state.deployments[this.state.current];
  }

  getDefaultRegion(cloud) {
    const regions = {
      aws: 'us-east-1',
      gcp: 'us-central1',
      azure: 'eastus'
    };
    return regions[cloud] || 'us-east-1';
  }

  exec(command, options = {}) {
    try {
      return execSync(command, {
        encoding: 'utf8',
        timeout: options.timeout || 60000,
        stdio: options.stdio || ['pipe', 'pipe', 'pipe'],
        shell: '/bin/bash',
        env: Object.assign({}, process.env, options.env || {})
      });
    } catch (error) {
      if (options.stdio === 'inherit') throw error;
      throw new Error(`Command failed: ${error.message}`);
    }
  }

  execHttp(method, url) {
    // Simple HTTP request for health check
    return new Promise((resolve, reject) => {
      const https = require('https');
      const http = require('http');
      const lib = url.startsWith('https') ? https : http;

      lib.get(url, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`HTTP ${res.statusCode}`));
          } else {
            resolve(data);
          }
        });
      }).on('error', reject);
    });
  }
}

// CLI entry point
async function main() {
  const command = process.argv[2];
  const subcommand = process.argv[3];
  const args = process.argv.slice(4);

  const manager = new DeploymentManager();
  const options = {};

  // Parse options
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      const value = args[i + 1]?.startsWith('--') ? true : args[i + 1];
      options[key.replace(/-/g, '_')] = value;
      if (value && !value.startsWith('--')) i++;
    }
  }

  try {
    if (command === 'deploy') {
      if (subcommand === 'init') {
        await manager.init(args[0], options);
      } else if (subcommand === 'apply') {
        await manager.apply(options);
      } else if (subcommand === 'status') {
        await manager.status();
      } else if (subcommand === 'endpoint') {
        await manager.endpoint();
      } else if (subcommand === 'logs') {
        await manager.logs(options);
      } else if (subcommand === 'scale') {
        await manager.scale(options);
      } else if (subcommand === 'verify') {
        await manager.verify();
      } else if (subcommand === 'destroy') {
        await manager.destroy(options);
      } else {
        console.log(`
Usage:
  kasbah deploy init <cloud> [--region REGION]
  kasbah deploy apply [--auto-approve]
  kasbah deploy status
  kasbah deploy endpoint
  kasbah deploy logs [--tail N]
  kasbah deploy scale --replicas N
  kasbah deploy verify
  kasbah deploy destroy [--force]

Supported clouds: aws, gcp, azure
        `);
      }
    }
  } catch (error) {
    console.error(`\n❌ Error: ${error.message}\n`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { DeploymentManager };

'use strict';

/**
 * deploy-manager.js — Kasbah Deployment Infrastructure Manager
 *
 * Wires the 20+ deployment files into the Kasbah API:
 *   - Terraform modules (AWS EKS, GCP GKE, Azure AKS)
 *   - Kubernetes manifests (deployment, HPA, ingress, RBAC, Prometheus)
 *   - Dockerfile (multi-stage, security-hardened)
 *   - Deploy scripts (production, health checks)
 *
 * Surfaces:
 *   - GET  /v1/deploy/status    — deployment readiness
 *   - GET  /v1/deploy/providers — supported cloud providers
 *   - GET  /v1/deploy/k8s       — Kubernetes manifest summary
 *   - POST /v1/deploy/validate  — validate deployment config
 *   - GET  /v1/deploy/estimate  — cost estimation
 */

const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const TERRAFORM_DIR = path.join(REPO_ROOT, 'terraform');
const K8S_DIR = path.join(REPO_ROOT, 'k8s');
const DOCKERFILE = path.join(REPO_ROOT, 'Dockerfile');
const DEPLOY_SCRIPT = path.join(REPO_ROOT, 'scripts', 'deploy-production.sh');

// ─── Deployment status ───────────────────────────────────────────────────────

function getStatus() {
  const terraformFiles = [];
  const k8sFiles = [];
  let dockerfileOk = false;
  let deployScriptOk = false;

  // Scan terraform
  if (fs.existsSync(TERRAFORM_DIR)) {
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir)) {
        const full = path.join(dir, entry);
        if (fs.statSync(full).isDirectory()) { walk(full); continue; }
        if (entry.endsWith('.tf') || entry.endsWith('.tfvars')) {
          terraformFiles.push(path.relative(TERRAFORM_DIR, full));
        }
      }
    };
    try { walk(TERRAFORM_DIR); } catch (_) {}
  }

  // Scan k8s
  if (fs.existsSync(K8S_DIR)) {
    try {
      for (const entry of fs.readdirSync(K8S_DIR)) {
        if (entry.endsWith('.yaml') || entry.endsWith('.yml')) {
          k8sFiles.push(entry);
        }
      }
    } catch (_) {}
  }

  dockerfileOk = fs.existsSync(DOCKERFILE);
  deployScriptOk = fs.existsSync(DEPLOY_SCRIPT);

  const ready = terraformFiles.length > 0 && k8sFiles.length > 0 && dockerfileOk;

  return {
    ready,
    terraform: {
      files: terraformFiles.length,
      modules: ['aws', 'gcp', 'azure'].filter(m =>
        fs.existsSync(path.join(TERRAFORM_DIR, m, 'main.tf'))
      ),
      configurable: 38, // from main.tf variables
    },
    kubernetes: {
      files: k8sFiles.length,
      manifests: k8sFiles,
      features: ['HPA 3-10 replicas', 'RBAC', 'NetworkPolicy', 'Prometheus', 'PVC 50GB'],
    },
    docker: {
      ready: dockerfileOk,
      type: 'multi-stage, security-hardened',
    },
    deployScript: {
      ready: deployScriptOk,
      path: 'scripts/deploy-production.sh',
    },
    providers: {
      aws: { estimatedMonthly: '$530', services: ['EKS', 'VPC', 'NAT', 'IAM', 'CloudWatch'] },
      gcp: { estimatedMonthly: '$380', services: ['GKE', 'VPC', 'Cloud NAT', 'Cloud Logging'] },
      azure: { estimatedMonthly: '$450', services: ['AKS', 'VNet', 'Log Analytics'] },
    },
    timeToProduction: '5-10 minutes',
    timestamp: new Date().toISOString(),
  };
}

// ─── Kubernetes manifest summary ─────────────────────────────────────────────

function getK8sSummary() {
  const manifests = {};
  if (!fs.existsSync(K8S_DIR)) return manifests;

  try {
    for (const entry of fs.readdirSync(K8S_DIR)) {
      if (!entry.endsWith('.yaml') && !entry.endsWith('.yml')) continue;
      const content = fs.readFileSync(path.join(K8S_DIR, entry), 'utf8');
      const lines = content.split('\n').length;
      const kinds = (content.match(/kind:\s*(\w+)/g) || []).map(k => k.replace('kind: ', ''));
      manifests[entry] = { lines, kinds };
    }
  } catch (_) {}

  return manifests;
}

// ─── Validate deployment config ──────────────────────────────────────────────

function validateConfig(provider, config = {}) {
  const errors = [];
  const warnings = [];

  if (!['aws', 'gcp', 'azure'].includes(provider)) {
    errors.push(`Unknown provider: ${provider}. Use aws, gcp, or azure.`);
  }

  if (!config.region) {
    warnings.push('No region specified. Will use default.');
  }

  if (provider === 'aws') {
    if (!fs.existsSync(path.join(TERRAFORM_DIR, 'aws', 'main.tf'))) {
      errors.push('AWS Terraform module not found.');
    }
  } else if (provider === 'gcp') {
    if (!config.project_id) {
      errors.push('GCP requires project_id in config.');
    }
  }

  if (config.replicas && (config.replicas < 1 || config.replicas > 20)) {
    errors.push('Replicas must be between 1 and 20.');
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    estimatedCost: getStatus().providers[provider]?.estimatedMonthly || 'unknown',
  };
}

// ─── Cost estimation ─────────────────────────────────────────────────────────

function estimateCost(provider, config = {}) {
  const base = getStatus().providers[provider];
  if (!base) return { error: `Unknown provider: ${provider}` };

  const nodes = config.nodes || 3;
  const replicas = config.replicas || 3;
  const storageGb = config.storageGb || 50;

  // Simplified cost model
  const nodeCost = provider === 'gcp' ? 100 : 150;
  const storageCost = storageGb * 0.10;

  return {
    provider,
    nodes,
    replicas,
    storageGb,
    estimatedMonthly: `$${(nodeCost * nodes + storageCost).toFixed(0)}`,
    breakdown: {
      compute: `$${nodeCost * nodes}/mo (${nodes} nodes)`,
      storage: `$${storageCost.toFixed(2)}/mo (${storageGb}GB)`,
      networking: '~$30/mo',
    },
    savings: {
      spotInstances: 'Save 60-70% with spot/preemptible instances',
      reservedInstances: 'Save 30-40% with 1-year commitment',
    },
  };
}

module.exports = {
  getStatus,
  getK8sSummary,
  validateConfig,
  estimateCost,
};

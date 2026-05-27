'use strict';

/**
 * @kasbah/control
 * Universal AI Governance Middleware
 *
 * Intercepts any LLM API call (OpenAI, Anthropic, Kimi, Grok, Ollama, etc.)
 * with 13-layer policy enforcement and cryptographic proof — zero agent code changes.
 *
 * Usage:
 *   const { KasbahAgentControl } = require('@kasbah/control');
 *   const control = new KasbahAgentControl({ mode: 'enforce' });
 *   control.installFetchProxy(); // all LLM calls now governed
 *
 * Fully self-contained — no monorepo paths required.
 * Works as a standalone npm install on any machine.
 */

// Load environment variables from .env / .env.local before anything else
require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });
require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env.local') });

const { KasbahAgentControl } = require('./kasbah-agent-control');

/**
 * protect(sdkInstance, config?) — one-line API
 *
 * The API shown on our product page:
 *   const { protect } = require('@kasbah/control');
 *   const openai = protect(new OpenAI());  // that's it
 *
 * Python equivalent (kasbah_control):
 *   from kasbah_control import protect
 *   client = protect(openai.OpenAI())
 *
 * Equivalent to: new KasbahAgentControl({ mode: 'enforce', ...config }).wrap(sdkInstance)
 */
function protect(sdkInstance, config = {}) {
  const control = new KasbahAgentControl({ mode: 'enforce', ...config });
  return control.wrap(sdkInstance);
}

module.exports = { KasbahAgentControl, protect };
module.exports.default = KasbahAgentControl;
module.exports.KasbahAgentControl = KasbahAgentControl;
module.exports.protect = protect;

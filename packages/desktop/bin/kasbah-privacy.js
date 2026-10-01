#!/usr/bin/env node
'use strict';

/**
 * kasbah-privacy — local CLI for the desktop privacy suite.
 * No cloud. Talks to the same ~/.kasbah-privacy state as the app.
 *
 *   kasbah-privacy proof mint [--location sin] [--ip 1.2.3.4]
 *   kasbah-privacy proof list
 *   kasbah-privacy proof export
 *   kasbah-privacy agent status|evaluate --tool rm
 *   kasbah-privacy shamir split "secret" [--n 5 --k 3]
 *   kasbah-privacy shamir combine '<json shares>'
 *   kasbah-privacy deadman status|check-in
 *   kasbah-privacy honey deploy [aws|github|slack|openai|stripe]
 *   kasbah-privacy honey check "text"
 *   kasbah-privacy audit append "event"
 *   kasbah-privacy audit verify
 *   kasbah-privacy leak
 */

const path = require('path');
const SRC = path.join(__dirname, '..', 'src');

const pop = require(path.join(SRC, 'proof-protection.js'));
const agent = require(path.join(SRC, 'agent-guard.js'));
const shamir = require(path.join(SRC, 'shamir-vault.js'));
const deadman = require(path.join(SRC, 'deadman.js'));
const honey = require(path.join(SRC, 'honeytokens.js'));
const privacy = require(path.join(SRC, 'privacy-engine.js'));
const fsAudit = require(path.join(SRC, 'fs-audit.js'));

const argv = process.argv.slice(2);
const [cmd, sub, ...rest] = argv;
const flag = (n, d) => {
  const i = argv.indexOf('--' + n);
  return i === -1 ? d : (argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true);
};

function out(o) { console.log(typeof o === 'string' ? o : JSON.stringify(o, null, 2)); }

(async () => {
  if (cmd === 'proof') {
    if (sub === 'mint') {
      return out(pop.mint({
        vpnOn: flag('vpn', true) !== 'false',
        location: flag('location', 'sin'),
        egressIp: flag('ip', null),
        egressLoc: flag('loc', null),
      }));
    }
    if (sub === 'list') return out(pop.list().slice(-20).reverse());
    if (sub === 'export') return out(pop.exportAll());
    if (sub === 'verify') return out(pop.verifyAll());
  }
  if (cmd === 'agent') {
    if (sub === 'status') return out(agent.status());
    if (sub === 'evaluate') {
      return out(agent.evaluate({ tool: String(flag('tool', 'read')), domain: flag('domain', '') }));
    }
  }
  if (cmd === 'shamir') {
    if (sub === 'split') {
      const secret = rest.join(' ') || String(flag('secret', ''));
      return out(shamir.splitString(secret, Number(flag('n', 5)), Number(flag('k', 3))));
    }
    if (sub === 'combine') {
      const shares = JSON.parse(rest.join(' ') || flag('shares', '[]'));
      return out({ secret: shamir.combineToString(shares) });
    }
  }
  if (cmd === 'deadman') {
    if (sub === 'status') return out(deadman.status());
    if (sub === 'check-in') return out(deadman.checkIn(rest.join(' ') || 'cli'));
  }
  if (cmd === 'honey') {
    if (sub === 'deploy') return out(honey.deploy(String(flag('service', rest[0] || 'custom'))));
    if (sub === 'list') return out(honey.list());
    if (sub === 'check') return out(honey.check(rest.join(' ')));
  }
  if (cmd === 'audit') {
    if (sub === 'append') {
      const a = new fsAudit.ForwardSecureAudit();
      const r = a.append({ event: rest.join(' ') || 'cli', ts: Date.now() });
      return out(r);
    }
    if (sub === 'verify') {
      const a = new fsAudit.ForwardSecureAudit();
      return out(a.verify ? a.verify() : { note: 'see module API' });
    }
  }
  if (cmd === 'leak') return out(privacy.dnsLeakCheck());
  if (cmd === 'scan') {
    const text = rest.join(' ');
    return out({
      secrets: privacy.scanSecrets(text),
      scam: privacy.analyzeScamMyanmar(text),
    });
  }
  out(`kasbah-privacy <proof|agent|shamir|deadman|honey|audit|leak|scan> …
  proof mint|list|export|verify
  agent status|evaluate --tool rm
  shamir split "secret" | combine 'json'
  deadman status|check-in
  honey deploy [aws] | check "text"
  leak
  scan "text"`);
})();

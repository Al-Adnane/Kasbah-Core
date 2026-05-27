'use strict';
/**
 * Email alerts for Kasbah governance events.
 * Uses nodemailer if available, falls back to raw SMTP via net.Socket,
 * then falls back to console.log in dev mode when SMTP is not configured.
 *
 * Env vars:
 *   SMTP_HOST     (default: localhost)
 *   SMTP_PORT     (default: 587)
 *   SMTP_USER
 *   SMTP_PASS
 *   SMTP_FROM     (default: noreply@bekasbah.com)
 *   ALERT_EMAIL   — where to send alerts (required to actually send)
 */

const net = require('net');
const tls = require('tls');

// ── Config helpers ─────────────────────────────────────────────────────────────

function _cfg() {
  return {
    host:  process.env.SMTP_HOST || 'localhost',
    port:  parseInt(process.env.SMTP_PORT || '587', 10),
    user:  process.env.SMTP_USER || '',
    pass:  process.env.SMTP_PASS || '',
    from:  process.env.SMTP_FROM || 'noreply@bekasbah.com',
    to:    process.env.ALERT_EMAIL || ''
  };
}

function _isConfigured() {
  const c = _cfg();
  return !!(c.to && c.host !== 'localhost' || (c.host === 'localhost' && c.to));
}

// ── Nodemailer loader (lazy, graceful) ────────────────────────────────────────

let _nodemailer = null;
function _tryNodemailer() {
  if (_nodemailer !== null) return _nodemailer;
  try { _nodemailer = require('nodemailer'); } catch { _nodemailer = false; }
  return _nodemailer;
}

// ── Raw SMTP via net.Socket (fallback when nodemailer unavailable) ────────────

function _rawSmtp({ host, port, user, pass, from, to, subject, body }) {
  return new Promise((resolve, reject) => {
    const isSecure = port === 465;
    const createConn = isSecure
      ? () => tls.connect(port, host, { rejectUnauthorized: false })
      : () => net.createConnection(port, host);

    const sock = createConn();
    const lines = [];
    let step = 0;

    const send = (cmd) => sock.write(cmd + '\r\n');

    const mimeBody = [
      `From: ${from}`,
      `To: ${to}`,
      `Subject: ${subject}`,
      `MIME-Version: 1.0`,
      `Content-Type: text/plain; charset=utf-8`,
      '',
      body
    ].join('\r\n');

    sock.setTimeout(15000);
    sock.on('timeout', () => { sock.destroy(); reject(new Error('SMTP timeout')); });
    sock.on('error', reject);

    sock.on('data', (chunk) => {
      const data = chunk.toString();
      lines.push(data);

      if (step === 0 && data.startsWith('220')) {
        step = 1;
        send(`EHLO kasbah`);
      } else if (step === 1 && data.includes('250')) {
        step = 2;
        if (user && pass) {
          send('AUTH LOGIN');
        } else {
          step = 3;
          send(`MAIL FROM:<${from}>`);
        }
      } else if (step === 2 && data.startsWith('334') && data.includes('VXNlcm5hbWU')) {
        // "Username:" in base64
        send(Buffer.from(user).toString('base64'));
      } else if (step === 2 && data.startsWith('334') && data.includes('UGFzc3dvcmQ')) {
        // "Password:" in base64
        send(Buffer.from(pass).toString('base64'));
      } else if (step === 2 && data.startsWith('235')) {
        // AUTH success
        step = 3;
        send(`MAIL FROM:<${from}>`);
      } else if (step === 3 && data.startsWith('250')) {
        step = 4;
        send(`RCPT TO:<${to}>`);
      } else if (step === 4 && data.startsWith('250')) {
        step = 5;
        send('DATA');
      } else if (step === 5 && data.startsWith('354')) {
        step = 6;
        send(mimeBody + '\r\n.');
      } else if (step === 6 && data.startsWith('250')) {
        step = 7;
        send('QUIT');
        sock.end();
        resolve({ sent: true });
      } else if (step === 7) {
        sock.destroy();
        resolve({ sent: true });
      } else if (data.startsWith('5')) {
        sock.destroy();
        reject(new Error('SMTP error: ' + data.trim()));
      }
    });
  });
}

// ── Core send function ────────────────────────────────────────────────────────

async function sendAlert({ subject, body, to }) {
  const cfg = _cfg();
  const recipient = to || cfg.to;

  if (!recipient) {
    console.log(`[email-alerts] ALERT_EMAIL not set — logging alert instead:\nSubject: ${subject}\n${body}`);
    return;
  }

  const nm = _tryNodemailer();
  if (nm) {
    try {
      const transporter = nm.createTransport({
        host: cfg.host,
        port: cfg.port,
        secure: cfg.port === 465,
        auth: cfg.user ? { user: cfg.user, pass: cfg.pass } : undefined,
        ignoreTLS: cfg.host === 'localhost'
      });
      await transporter.sendMail({ from: cfg.from, to: recipient, subject, text: body });
      return;
    } catch (e) {
      console.warn('[email-alerts] nodemailer failed, trying raw SMTP:', e.message);
    }
  }

  // Raw SMTP fallback
  try {
    await _rawSmtp({ host: cfg.host, port: cfg.port, user: cfg.user, pass: cfg.pass, from: cfg.from, to: recipient, subject, body });
  } catch (e) {
    console.warn('[email-alerts] Raw SMTP failed:', e.message);
    console.log(`[email-alerts] Fallback log — Subject: ${subject}\n${body}`);
  }
}

// ── Alert templates ───────────────────────────────────────────────────────────

async function alertBudgetWarning({ agentId, sessionId, spent, limit, pct }) {
  const subject = `[Kasbah] Budget warning — Agent ${agentId} at ${pct || Math.round((spent/limit)*100)}%`;
  const body = [
    `Kasbah Guard Budget Alert`,
    ``,
    `Agent ${agentId} has used ${pct || Math.round((spent/limit)*100)}% of its budget.`,
    ``,
    `Session: ${sessionId || 'N/A'}`,
    `Spent:   $${(spent || 0).toFixed(4)}`,
    `Limit:   $${(limit || 0).toFixed(4)}`,
    ``,
    `Review agent activity at https://bekasbah.com/dashboard`,
    ``,
    `— Kasbah Guard`
  ].join('\n');
  return sendAlert({ subject, body });
}

async function alertThreatBlocked({ agentId, sessionId, threats, verdict }) {
  const threatList = Array.isArray(threats) ? threats.join(', ') : (threats || 'unknown');
  const subject = `[Kasbah] Threat blocked — Agent ${agentId}`;
  const body = [
    `Kasbah Guard Threat Alert`,
    ``,
    `A threat was blocked for agent ${agentId}.`,
    ``,
    `Session:  ${sessionId || 'N/A'}`,
    `Verdict:  ${verdict || 'DENY'}`,
    `Threats:  ${threatList}`,
    ``,
    `Review audit log at https://bekasbah.com/dashboard`,
    ``,
    `— Kasbah Guard`
  ].join('\n');
  return sendAlert({ subject, body });
}

async function alertSessionKilled({ agentId, sessionId, reason }) {
  const subject = `[Kasbah] Session killed — Agent ${agentId}`;
  const body = [
    `Kasbah Guard Session Alert`,
    ``,
    `Agent session was killed.`,
    ``,
    `Agent:   ${agentId || 'N/A'}`,
    `Session: ${sessionId || 'N/A'}`,
    `Reason:  ${reason || 'Policy violation'}`,
    ``,
    `Review audit log at https://bekasbah.com/dashboard`,
    ``,
    `— Kasbah Guard`
  ].join('\n');
  return sendAlert({ subject, body });
}

module.exports = { sendAlert, alertBudgetWarning, alertThreatBlocked, alertSessionKilled };

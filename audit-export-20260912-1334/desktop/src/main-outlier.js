'use strict';

/**
 * Outlier product layer — situation report, exit market, claim ledger,
 * impact card, 7-day harden, commitment proofs, POP merkle batch.
 */

module.exports = function registerOutlierHandlers(ipcMain, ctx) {
  const { log, V, fs, path, os, safeExistingFile, vpnState,
          privacy, pop, merkleBatch, impact, sitrep, exitMarket,
          claimLedger, harden, commitProof, llmProxy } = ctx;

  // ─── Situation / Crisis (OCP sulfur pattern) ───────────────────────────────
  ipcMain.handle('sitrep:get', async (_e, body = {}) => {
    // Never trust a renderer-supplied `egress` object for a situation
    // report that claims to describe real protection state — always derive
    // it from an actual network probe (or leave it null while offline).
    let egress = null;
    if (vpnState.activeLocation) {
      const probe = await ctx.netIntel.realEgressProbe();
      egress = { ip: probe.ip, loc: probe.loc, colo: probe.colo };
    }
    return sitrep.sitrep({
      vpnOn: !!vpnState.activeLocation,
      egress,
      lastPings: body.lastPings || [],
    });
  });
  ipcMain.handle('sitrep:crisis', (_e, on) => {
    const s = sitrep.setCrisis(!!on);
    log.info('sitrep', on ? 'CRISIS MODE ON' : 'crisis off');
    return s;
  });
  ipcMain.handle('sitrep:history', () => sitrep.loadSitrep(48));

  // ─── Exit market (flight cards) ────────────────────────────────────────────
  ipcMain.handle('exit-market:list', async () => {
    const locs = ctx.vpnLoadLocations ? ctx.vpnLoadLocations() : [];
    return exitMarket.listExits(locs);
  });

  // ─── Claim ledger ──────────────────────────────────────────────────────────
  ipcMain.handle('claims:list', () => claimLedger.list());
  ipcMain.handle('claims:check', (_e, id) => claimLedger.markChecked(V.str(id, { max: 64, name: 'id' })));

  // ─── Impact card (outcomes) ────────────────────────────────────────────────
  ipcMain.handle('impact:snapshot', () => impact.snapshot());
  ipcMain.handle('impact:bump', (_e, key, n) => {
    try { return impact.bump(String(key || ''), Math.max(0, Number(n) || 1)); }
    catch (e) { return { error: e.message }; }
  });

  // ─── 7-day harden + commitment ─────────────────────────────────────────────
  ipcMain.handle('harden:status', () => harden.status());
  ipcMain.handle('harden:start', () => harden.start());
  ipcMain.handle('harden:step', (_e, id) => harden.completeStep(V.str(id, { max: 32, name: 'id' })));
  ipcMain.handle('harden:commit', (_e, note) => harden.commit(note));
  ipcMain.handle('harden:reset', () => harden.reset());

  // ─── Commitment proof (hide IP) ────────────────────────────────────────────
  ipcMain.handle('commit:create-hidden', async () => {
    // Real state only — a "hidden-IP" commitment proof is worthless if the
    // committed IP/location can simply be supplied by the caller. Ignore
    // renderer input entirely for the fields being attested.
    const probe = vpnState.activeLocation ? await ctx.netIntel.realEgressProbe() : { ip: null, colo: null };
    const pub = commitProof.create({
      egressIp: probe.ip || null,
      location: vpnState.activeLocation ? (vpnState.activeLocation.name || vpnState.activeLocation.id || null) : null,
      colo: probe.colo || null,
      claim: vpnState.activeLocation ? 'PROTECTED' : 'EXPOSED',
    });
    try { impact.bump('proofsMinted'); } catch (_) {}
    sitrep.appendSitrep({ type: 'commit_proof', location: pub.location });
    return pub;
  });
  ipcMain.handle('commit:list-hidden', () => commitProof.list());
  ipcMain.handle('commit:open-hidden', (_e, id) => commitProof.open(V.str(id, { max: 40, name: 'requestId' })));

  // ─── POP Merkle batch (UI name merkle.batchProofs) ─────────────────────────
  ipcMain.handle('merkle:batch-proofs', () => {
    const list = pop.list();
    const pairs = list.map((e) => ({ receipt: e.receipt, payload: e.payload, requestId: e.requestId }))
      .filter((x) => x.receipt && x.payload);
    if (!pairs.length) return { ok: false, error: 'no proofs yet — mint one first' };
    const tree = merkleBatch.buildMerkleTree(pairs.map((p) => ({ receipt: p.receipt, payload: p.payload })));
    const file = path.join(os.homedir(), 'Downloads', `kasbah-pop-merkle-${Date.now()}.json`);
    fs.writeFileSync(file, JSON.stringify({
      root: tree.root,
      count: pairs.length,
      exportedAt: new Date().toISOString(),
      proofs: pairs.map((p) => ({
        requestId: p.requestId,
        receipt: p.receipt,
        proof: tree.proofs.get(merkleBatch.sha256hex(p.receipt + '|' + p.payload)) || [],
      })),
    }, null, 2), { mode: 0o600 });
    return { ok: true, root: tree.root, count: pairs.length, file };
  });

  // ─── Wire impact on existing events (best-effort hooks) ────────────────────
  ipcMain.handle('outlier:wire-impact', () => {
    // Called from renderer after scan/secret/honey events
    return { ok: true };
  });

  log.info('outlier', 'outlier handlers registered');
};

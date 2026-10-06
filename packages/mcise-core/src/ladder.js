// Autonomy Ladder – simplified port
class AutonomyLadder {
  constructor() {
    this.agents = new Map();
    // rung thresholds
    this.thresholds = {
      1: { minAccuracy: 0.60, minTenureDays: 14 },
      2: { minAccuracy: 0.70, minTenureDays: 90 },
      3: { minAccuracy: 0.80, minTenureDays: 180 },
      4: { minAccuracy: 0.85, minTenureDays: 365 },
    };
  }

  register(agentId, rung = 1, createdAt = new Date()) {
    this.agents.set(agentId, { agentId, rung, createdAt, accuracy: 0, evaluations: [] });
  }

  recordEvaluation(agentId, accuracy) {
    const a = this.agents.get(agentId);
    if (!a) return;
    a.evaluations.push({ at: new Date(), accuracy });
    a.accuracy = this._rollingAvg(a.evaluations);
  }

  _rollingAvg(evals) {
    const n = Math.min(10, evals.length);
    const slice = evals.slice(-n);
    return slice.reduce((s, e) => s + e.accuracy, 0) / slice.length;
  }

  maybePromote(agentId) {
    const a = this.agents.get(agentId);
    if (!a) return;
    const current = a.rung;
    const next = current + 1;
    const t = this.thresholds[next];
    if (!t) return;
    const tenureDays = (Date.now() - new Date(a.createdAt).getTime()) / 86400000;
    if (a.accuracy >= t.minAccuracy && tenureDays >= t.minTenureDays) {
      a.rung = next;
      return { promoted: true, to: next };
    }
    return { promoted: false };
  }

  maybeDemote(agentId) {
    const a = this.agents.get(agentId);
    if (!a || a.rung <= 1) return;
    if (a.accuracy < 0.5) {
      a.rung = Math.max(1, a.rung - 1);
      return { demoted: true };
    }
  }

  status(agentId) {
    return this.agents.get(agentId);
  }
}

module.exports = { AutonomyLadder };

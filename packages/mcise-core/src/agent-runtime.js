// Adversarial agent runtime skeleton
class AgentRuntime {
  constructor(audit, ladder) {
    this.audit = audit;
    this.ladder = ladder;
    this.agents = new Map();
    this.pairs = new Map(); // primary -> adversary
  }

  registerAgent(id, spec) {
    this.agents.set(id, { id, spec, state: 'idle' });
    this.ladder.register(id);
  }

  setPair(primary, adversary) {
    this.pairs.set(primary, adversary);
  }

  async trigger(agentId, input) {
    const agent = this.agents.get(agentId);
    if (!agent) throw new Error('agent not found');
    await this.audit.append({ actorType: 'agent', actorId: agentId, action: 'trigger', payload: { input } });
    // Simulate reasoning
    const result = { verdict: 'pending', confidence: 0.5 };
    const adversaryId = this.pairs.get(agentId);
    if (adversaryId) {
      await this.trigger(adversaryId, { challenge: result.verdict });
    }
    await this.audit.append({ actorType: 'agent', actorId: agentId, action: 'decide', payload: result });
    return result;
  }
}

module.exports = { AgentRuntime };

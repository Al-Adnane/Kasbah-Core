/**
 * Panopticon Information Asymmetry Deception Detection (NEW Idea #1)
 *
 * The governance proxy sees EVERYTHING — all tool calls, reasoning traces,
 * multi-turn context. The LLM only sees what it's told. This creates a
 * quantifiable INFORMATION ASYMMETRY GAP.
 *
 * When the model's stated reasoning omits information it demonstrably had
 * access to, or claims ignorance of something the proxy knows it observed,
 * that's a deception signature no single-detector approach can catch.
 *
 * KEY METRIC:
 *   gap = H(model_stated_knowledge || proxy_observed_knowledge) -
 *         H(model_stated_knowledge)
 *
 *   where H is the size of the intersection of knowledge elements.
 *   A persistent gap > threshold → strategic ignorance / deception.
 *
 * PRIOR ART GAP:
 *   No existing guardrail system compares model's STATED ACCESS to
 *   information against its ACTUAL ACCESS. Existing lie detectors look
 *   for contradictions in output text; this detects EPISTEMIC GAPS.
 *
 * @module panopticon-asymmetry-detector
 */
'use strict';

class PanopticonAsymmetryDetector {
  constructor(opts = {}) {
    this.deceptionThreshold = opts.deceptionThreshold || 0.3;
    this.persistenceWindow = opts.persistenceWindow || 8;
    this.minGapSignificance = opts.minGapSignificance || 2;

    // Shadow knowledge graph: what the proxy OBSERVED the model was exposed to
    this.observedKnowledge = new Map();
    // Model's stated knowledge per turn
    this.statedKnowledgeHistory = [];
    // Track gap time series for persistence
    this.gapHistory = [];
    this.turnCount = 0;
  }

  /**
   * Register what the proxy made available to the model.
   *
   * @param {Object} exposure
   * @param {string[]} exposure.files     - file paths shown to model
   * @param {string[]} exposure.toolResults - tool call results returned to model
   * @param {Object[]} exposure.data      - structured data passed to model
   * @param {number} exposure.turnId      - which turn this was
   */
  registerExposure(exposure) {
    const { files = [], toolResults = [], data = [], turnId = this.turnCount } = exposure;

    // Build knowledge elements: hash-comparable facts
    const elements = new Set();

    for (const f of files) {
      elements.add(`file:${f}`);
    }
    for (const tr of toolResults) {
      if (typeof tr === 'string') {
        elements.add(`tool_result:${this._hashFragment(tr)}`);
      } else if (tr && typeof tr === 'object') {
        elements.add(`tool_result:${this._hashFragment(JSON.stringify(tr))}`);
      }
    }
    for (const d of data) {
      elements.add(`data:${this._hashFragment(JSON.stringify(d))}`);
    }

    this.observedKnowledge.set(turnId, {
      elements,
      elementCount: elements.size,
      timestamp: Date.now(),
    });

    // Prune old entries (> persistenceWindow * 2 turns back)
    const oldestKeep = turnId - this.persistenceWindow * 2;
    for (const [key] of this.observedKnowledge) {
      if (key < oldestKeep) this.observedKnowledge.delete(key);
    }
  }

  /**
   * Extract the model's stated knowledge from its response.
   *
   * We look for explicit references to information:
   *   - File names the model mentions using
   *   - Tool result content the model references
   *   - Data elements the model cites
   *
   * @param {string} modelResponse - Full text of model's response
   * @returns {Object} Extracted stated knowledge
   */
  extractStatedKnowledge(modelResponse) {
    const stated = {
      filesMentioned: [],
      toolResultsReferenced: [],
      claimsOfIgnorance: [],
      turnId: this.turnCount,
    };

    // Heuristic 1: Files mentioned by name
    const filePattern = /(?:reading|loaded|parsing|analyzing|in\s+)([\w\-./]+\.\w{1,8})/gi;
    let m;
    while ((m = filePattern.exec(modelResponse)) !== null) {
      stated.filesMentioned.push(m[1]);
    }

    // Heuristic 2: Claims of ignorance or inability
    const ignorancePatterns = [
      /I (?:don't|cannot|can't|do not) (?:have access to|see|find|know)/gi,
      /(?:no information|no data|no context|unable to determine)/gi,
      /(?:not provided|not available|not specified|is missing)/gi,
      /(?:I wasn't given|I have not been shown)/gi,
    ];
    for (const pat of ignorancePatterns) {
      let im;
      while ((im = pat.exec(modelResponse)) !== null) {
        stated.claimsOfIgnorance.push({
          match: im[0],
          position: im.index,
        });
      }
    }

    // Heuristic 3: Tool result references
    const toolRefPattern = /(?:the result|the output|returned|found|returned|shows)\s+(?:that|the\s+)?(\w[\w\s]{3,50})/gi;
    let tm;
    while ((tm = toolRefPattern.exec(modelResponse)) !== null) {
      stated.toolResultsReferenced.push(tm[1].trim());
    }

    return stated;
  }

  /**
   * Compute the epistemic gap: did the model claim ignorance of something
   * it was demonstrably shown?
   *
   * @param {Object} statedKnowledge - From extractStatedKnowledge()
   * @param {number} turnId - Which turn
   * @returns {Object} Gap analysis
   */
  computeEpistemicGap(statedKnowledge, turnId) {
    this.turnCount = turnId + 1;

    // Aggregate observed knowledge across recent turns
    const observedElements = new Set();
    let totalObserved = 0;
    for (let t = Math.max(0, turnId - this.persistenceWindow); t <= turnId; t++) {
      const obs = this.observedKnowledge.get(t);
      if (obs) {
        for (const el of obs.elements) {
          observedElements.add(el);
        }
        totalObserved += obs.elementCount;
      }
    }

    // Stated knowledge elements
    const statedElements = new Set();
    for (const f of statedKnowledge.filesMentioned) {
      statedElements.add(`file:${f}`);
    }
    for (const tr of statedKnowledge.toolResultsReferenced) {
      statedElements.add(`tool_ref:${this._hashFragment(tr)}`);
    }

    // Intersection: what the model acknowledged
    const acknowledged = new Set();
    for (const se of statedElements) {
      for (const oe of observedElements) {
        if (oe.startsWith(se.split(':')[0] + ':') && this._fuzzyMatch(se, oe)) {
          acknowledged.add(oe);
        }
      }
    }

    // Gap: observed but NOT acknowledged
    const gap = observedElements.size - acknowledged.size;
    const gapRatio = totalObserved > 0 ? gap / totalObserved : 0;

    // Ignorance claims about observed info
    const deceptiveIgnorance = [];
    for (const claim of statedKnowledge.claimsOfIgnorance) {
      if (observedElements.size > 0 && gapRatio > this.deceptionThreshold) {
        deceptiveIgnorance.push({
          claim: claim.match,
          context: `model claimed ignorance while having seen ${totalObserved} knowledge elements across ${this.persistenceWindow} turns, acknowledged only ${acknowledged.size}`,
        });
      }
    }

    // Persistence: track gap over time
    this.gapHistory.push({ turnId, gap, gapRatio, deceptiveCount: deceptiveIgnorance.length });
    if (this.gapHistory.length > this.persistenceWindow * 3) {
      this.gapHistory.shift();
    }

    const recentGaps = this.gapHistory.slice(-this.persistenceWindow);
    const persistentGap = recentGaps.filter(g => g.gapRatio > this.deceptionThreshold).length;
    const cumulativeGap = recentGaps.reduce((s, g) => s + g.gap, 0);

    // Stated knowledge history
    this.statedKnowledgeHistory.push({
      turnId,
      statedElements: statedElements.size,
      acknowledged: acknowledged.size,
      gap,
      deceptiveIgnorance,
    });

    return {
      turnId,
      observedElements: observedElements.size,
      statedElements: statedElements.size,
      acknowledgedElements: acknowledged.size,
      gap,
      gapRatio,
      deceptiveIgnorance,
      persistentGapCount: persistentGap,
      persistentGapWindow: this.persistenceWindow,
      persistenceRatio: persistentGap / this.persistenceWindow,
      cumulativeGap,
      isDeceptive: persistentGap >= this.minGapSignificance,
      verdict: persistentGap >= this.minGapSignificance
        ? 'DECEPTIVE_EPISTEMIC_GAP'
        : persistentGap >= this.minGapSignificance / 2
          ? 'SUSPICIOUS_STRATEGIC_IGNORANCE'
          : 'EPISTEMICALLY_CONSISTENT',
    };
  }

  /**
   * Full analysis of one turn: extract + compute gap.
   *
   * @param {string} modelResponse - Model's response text
   * @param {Object} exposure - What was shown to the model this turn
   * @returns {Object}
   */
  analyze(modelResponse, exposure) {
    this.registerExposure(exposure);
    const stated = this.extractStatedKnowledge(modelResponse);
    return this.computeEpistemicGap(stated, exposure.turnId || this.turnCount - 1);
  }

  /**
   * Reset state (e.g., new session).
   */
  reset() {
    this.observedKnowledge.clear();
    this.statedKnowledgeHistory = [];
    this.gapHistory = [];
    this.turnCount = 0;
  }

  dumpDiagnostics() {
    return {
      turnCount: this.turnCount,
      observedKnowledgeSize: this.observedKnowledge.size,
      gapHistory: this.gapHistory.slice(-10),
      statedHistory: this.statedKnowledgeHistory.slice(-10),
      deceptionThreshold: this.deceptionThreshold,
    };
  }

  // --- internal helpers ---

  _hashFragment(str) {
    let hash = 0;
    for (let i = 0; i < Math.min(str.length, 200); i++) {
      const c = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + c;
      hash = hash | 0;
    }
    return Math.abs(hash).toString(36);
  }

  _fuzzyMatch(a, b) {
    // Check if one is a substring of the other (simplified)
    const aBase = a.split(':')[1] || '';
    const bBase = b.split(':')[1] || '';
    return aBase.length > 0 && bBase.length > 0 &&
      (aBase.includes(bBase) || bBase.includes(aBase) || aBase === bBase);
  }
}

module.exports = { PanopticonAsymmetryDetector };

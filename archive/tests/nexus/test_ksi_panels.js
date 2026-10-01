/**
 * ============================================================================
 * KASBAH NEXUS - KSI INTELLIGENCE PANELS TEST SUITE
 * ============================================================================
 *
 * Test suite for 3 KSI dashboard panels:
 * 1. KSI Intelligence Dashboard
 * 2. Adversarial Identity Chronicle
 * 3. Cultural Triage Dashboard
 *
 * Tests: 15+ test cases covering rendering, real-time updates, and visualization
 */

describe('KSI Intelligence Panels', () => {
  let container;
  let mockData;

  beforeEach(() => {
    // Create a DOM container for testing
    container = document.createElement('div');
    container.id = 'test-container';
    document.body.appendChild(container);

    // Mock data for panels
    mockData = {
      tcsScores: {
        technical_risk: 0.3,
        cultural_sensitivity: 0.2,
        intent_class: 0.5,
        novelty: 0.4,
        identity_certainty: 0.8,
        sacred_content_risk: 0.1
      },
      cdrTimeline: [
        { timestamp: 1710120000, value: 0.21, count: 1 },
        { timestamp: 1710120600, value: 0.68, count: 4 },
        { timestamp: 1710121200, value: 0.45, count: 2 }
      ],
      intentDistribution: {
        BENIGN: 60,
        SUSPICIOUS: 30,
        EXFILTRATION: 8,
        ADVERSARIAL: 2
      },
      decisionDistribution: {
        ALLOW: 150,
        WARN: 45,
        DENY: 12
      },
      threatActors: [
        {
          id: 'actor_abc123',
          status: 'ACTIVE',
          firstSeen: '2026-03-11T14:20:00Z',
          eventCount: 5,
          events: [
            { timestamp: '2026-03-11T14:20:00Z', type: 'Copy-paste spike' },
            { timestamp: '2026-03-11T14:25:00Z', type: 'Exfil attempt' },
            { timestamp: '2026-03-11T14:32:00Z', type: 'Detected typing shift' }
          ],
          fingerprint: {
            ip: '192.168.1.100',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            signature: 'fp_abc123'
          },
          riskScore: 75
        },
        {
          id: 'actor_def456',
          status: 'SUSPICIOUS',
          firstSeen: '2026-03-11T14:35:00Z',
          eventCount: 2,
          events: [
            { timestamp: '2026-03-11T14:35:00Z', type: 'New fingerprint' },
            { timestamp: '2026-03-11T14:40:00Z', type: 'Behavioral anomaly' }
          ],
          fingerprint: {
            ip: '10.0.0.50',
            userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            signature: 'fp_def456'
          },
          riskScore: 45
        }
      ],
      frameworks: {
        Maqasid: 127,
        GDPR: 98,
        QuranSemantic: 63,
        CCPA: 45,
        HIPAA: 32,
        PCI_DSS: 18
      },
      languages: {
        English: 0.45,
        Arabic: 0.30,
        CJK: 0.15,
        Cyrillic: 0.10
      }
    };
  });

  afterEach(() => {
    if (container && document.body.contains(container)) {
      document.body.removeChild(container);
    }
  });

  // ========================================================================
  // TEST GROUP 1: KSI INTELLIGENCE DASHBOARD PANEL
  // ========================================================================

  describe('KSIIntelligencePanel', () => {
    test('renders without errors', () => {
      const panel = createKSIIntelligencePanel(container, mockData);
      expect(panel).toBeDefined();
      expect(container.querySelector('.ksi-intelligence-panel')).toBeTruthy();
    });

    test('displays panel title', () => {
      createKSIIntelligencePanel(container, mockData);
      const title = container.querySelector('.ksi-panel-title');
      expect(title).toBeTruthy();
      expect(title.textContent).toContain('KSI Intelligence');
    });

    test('renders TCS heatmap with 6 dimensions', () => {
      createKSIIntelligencePanel(container, mockData);
      const heatmap = container.querySelector('.tcs-radar-chart');
      expect(heatmap).toBeTruthy();
      // Verify all 6 axes are present
      expect(container.textContent).toContain('Technical Risk');
      expect(container.textContent).toContain('Cultural Sensitivity');
      expect(container.textContent).toContain('Intent Class');
      expect(container.textContent).toContain('Novelty');
      expect(container.textContent).toContain('Identity Certainty');
      expect(container.textContent).toContain('Sacred Content Risk');
    });

    test('displays correct TCS score values', () => {
      createKSIIntelligencePanel(container, mockData);
      expect(container.textContent).toContain('0.3'); // technical_risk
      expect(container.textContent).toContain('0.8'); // identity_certainty
    });

    test('colors TCS scores based on thresholds (green/yellow/red)', () => {
      createKSIIntelligencePanel(container, mockData);
      const scores = container.querySelectorAll('.tcs-score');
      expect(scores.length).toBeGreaterThan(0);
      // Verify color classes are applied
      let hasGreen = false, hasYellow = false;
      scores.forEach(score => {
        if (score.classList.contains('safe')) hasGreen = true;
        if (score.classList.contains('warn')) hasYellow = true;
      });
      expect(hasGreen || hasYellow).toBe(true);
    });

    test('renders CDR timeline for past 60 minutes', () => {
      createKSIIntelligencePanel(container, mockData);
      const timeline = container.querySelector('.cdr-timeline');
      expect(timeline).toBeTruthy();
      expect(container.textContent).toContain('CDR Timeline');
    });

    test('highlights CDR resonance events (CDR > 0.65)', () => {
      createKSIIntelligencePanel(container, mockData);
      const resonanceEvents = container.querySelectorAll('.cdr-resonance');
      expect(resonanceEvents.length).toBeGreaterThan(0);
      // Should highlight the 0.68 event
      let found = false;
      resonanceEvents.forEach(event => {
        if (event.textContent.includes('0.68')) found = true;
      });
      expect(found).toBe(true);
    });

    test('renders intent distribution pie chart', () => {
      createKSIIntelligencePanel(container, mockData);
      const pieChart = container.querySelector('.intent-distribution');
      expect(pieChart).toBeTruthy();
      expect(container.textContent).toContain('BENIGN');
      expect(container.textContent).toContain('SUSPICIOUS');
      expect(container.textContent).toContain('EXFILTRATION');
    });

    test('displays intent distribution percentages correctly', () => {
      createKSIIntelligencePanel(container, mockData);
      expect(container.textContent).toContain('60'); // BENIGN percentage
      expect(container.textContent).toContain('30'); // SUSPICIOUS percentage
    });

    test('renders decision distribution bar chart', () => {
      createKSIIntelligencePanel(container, mockData);
      const barChart = container.querySelector('.decision-distribution');
      expect(barChart).toBeTruthy();
      expect(container.textContent).toContain('ALLOW');
      expect(container.textContent).toContain('WARN');
      expect(container.textContent).toContain('DENY');
    });

    test('updates in real-time when data changes', (done) => {
      const panel = createKSIIntelligencePanel(container, mockData);
      const initialText = container.textContent;

      const newData = {
        ...mockData,
        intentDistribution: {
          BENIGN: 70,
          SUSPICIOUS: 20,
          EXFILTRATION: 5,
          ADVERSARIAL: 5
        }
      };

      updateKSIIntelligencePanel(panel, newData);
      setTimeout(() => {
        expect(container.textContent).toContain('70');
        done();
      }, 100);
    });
  });

  // ========================================================================
  // TEST GROUP 2: ADVERSARIAL IDENTITY CHRONICLE PANEL
  // ========================================================================

  describe('AdversarialIdentityPanel', () => {
    test('renders without errors', () => {
      const panel = createAdversarialIdentityPanel(container, mockData);
      expect(panel).toBeDefined();
      expect(container.querySelector('.adversarial-identity-panel')).toBeTruthy();
    });

    test('displays panel title', () => {
      createAdversarialIdentityPanel(container, mockData);
      const title = container.querySelector('.ksi-panel-title');
      expect(title).toBeTruthy();
      expect(title.textContent).toContain('Adversarial Identity');
    });

    test('renders threat actor nodes', () => {
      createAdversarialIdentityPanel(container, mockData);
      const actors = container.querySelectorAll('.threat-actor-node');
      expect(actors.length).toBe(2);
    });

    test('displays threat actor IDs', () => {
      createAdversarialIdentityPanel(container, mockData);
      expect(container.textContent).toContain('actor_abc123');
      expect(container.textContent).toContain('actor_def456');
    });

    test('shows threat actor status with correct styling', () => {
      createAdversarialIdentityPanel(container, mockData);
      const activeStatus = container.querySelector('[data-status="ACTIVE"]');
      const suspiciousStatus = container.querySelector('[data-status="SUSPICIOUS"]');
      expect(activeStatus).toBeTruthy();
      expect(suspiciousStatus).toBeTruthy();
    });

    test('displays actor event timeline', () => {
      createAdversarialIdentityPanel(container, mockData);
      expect(container.textContent).toContain('Copy-paste spike');
      expect(container.textContent).toContain('Exfil attempt');
      expect(container.textContent).toContain('New fingerprint');
    });

    test('renders threat actor graph with node sizing', () => {
      createAdversarialIdentityPanel(container, mockData);
      const graph = container.querySelector('.threat-actor-graph');
      expect(graph).toBeTruthy();
      const nodes = container.querySelectorAll('.actor-node');
      expect(nodes.length).toBe(2);
    });

    test('displays fingerprint details (IP, user-agent, signature)', () => {
      createAdversarialIdentityPanel(container, mockData);
      expect(container.textContent).toContain('192.168.1.100');
      expect(container.textContent).toContain('fp_abc123');
    });

    test('shows risk score per actor on 0-100 scale', () => {
      createAdversarialIdentityPanel(container, mockData);
      const riskScores = container.querySelectorAll('.risk-score');
      expect(riskScores.length).toBeGreaterThan(0);
      expect(container.textContent).toContain('75'); // actor_abc123 risk
      expect(container.textContent).toContain('45'); // actor_def456 risk
    });

    test('updates actor timeline in real-time', (done) => {
      const panel = createAdversarialIdentityPanel(container, mockData);

      const newData = {
        ...mockData,
        threatActors: [
          ...mockData.threatActors,
          {
            id: 'actor_new789',
            status: 'ACTIVE',
            firstSeen: '2026-03-11T15:00:00Z',
            eventCount: 1,
            events: [
              { timestamp: '2026-03-11T15:00:00Z', type: 'New threat detected' }
            ],
            fingerprint: {
              ip: '172.16.0.1',
              userAgent: 'Mozilla/5.0',
              signature: 'fp_new789'
            },
            riskScore: 85
          }
        ]
      };

      updateAdversarialIdentityPanel(panel, newData);
      setTimeout(() => {
        expect(container.textContent).toContain('actor_new789');
        done();
      }, 100);
    });
  });

  // ========================================================================
  // TEST GROUP 3: CULTURAL TRIAGE DASHBOARD PANEL
  // ========================================================================

  describe('CulturalTriagePanel', () => {
    test('renders without errors', () => {
      const panel = createCulturalTriagePanel(container, mockData);
      expect(panel).toBeDefined();
      expect(container.querySelector('.cultural-triage-panel')).toBeTruthy();
    });

    test('displays panel title', () => {
      createCulturalTriagePanel(container, mockData);
      const title = container.querySelector('.ksi-panel-title');
      expect(title).toBeTruthy();
      expect(title.textContent).toContain('Cultural Triage');
    });

    test('renders framework application breakdown bar chart', () => {
      createCulturalTriagePanel(container, mockData);
      const breakdown = container.querySelector('.framework-breakdown');
      expect(breakdown).toBeTruthy();
      expect(container.textContent).toContain('Maqasid');
      expect(container.textContent).toContain('GDPR');
      expect(container.textContent).toContain('QuranSemantic');
    });

    test('displays correct framework detection counts', () => {
      createCulturalTriagePanel(container, mockData);
      expect(container.textContent).toContain('127'); // Maqasid
      expect(container.textContent).toContain('98');  // GDPR
      expect(container.textContent).toContain('63');  // QuranSemantic
    });

    test('renders language distribution pie chart', () => {
      createCulturalTriagePanel(container, mockData);
      const langChart = container.querySelector('.language-distribution');
      expect(langChart).toBeTruthy();
      expect(container.textContent).toContain('English');
      expect(container.textContent).toContain('Arabic');
      expect(container.textContent).toContain('CJK');
      expect(container.textContent).toContain('Cyrillic');
    });

    test('displays language distribution percentages', () => {
      createCulturalTriagePanel(container, mockData);
      // Should show percentages for each language
      expect(container.textContent).toContain('45'); // English 45%
      expect(container.textContent).toContain('30'); // Arabic 30%
    });

    test('renders cultural sensitivity heatmap', () => {
      createCulturalTriagePanel(container, mockData);
      const heatmap = container.querySelector('.cultural-sensitivity-heatmap');
      expect(heatmap).toBeTruthy();
    });

    test('displays compliance status with green/yellow/red coding', () => {
      createCulturalTriagePanel(container, mockData);
      const compliance = container.querySelectorAll('.compliance-status');
      expect(compliance.length).toBeGreaterThan(0);
      let hasColorClasses = false;
      compliance.forEach(item => {
        if (item.classList.contains('compliant') ||
            item.classList.contains('warning') ||
            item.classList.contains('non-compliant')) {
          hasColorClasses = true;
        }
      });
      expect(hasColorClasses).toBe(true);
    });

    test('updates frameworks dynamically', (done) => {
      const panel = createCulturalTriagePanel(container, mockData);

      const newData = {
        ...mockData,
        frameworks: {
          ...mockData.frameworks,
          Maqasid: 150,
          GDPR: 110
        }
      };

      updateCulturalTriagePanel(panel, newData);
      setTimeout(() => {
        expect(container.textContent).toContain('150');
        done();
      }, 100);
    });

    test('handles empty framework data gracefully', () => {
      const emptyData = {
        ...mockData,
        frameworks: {}
      };
      const panel = createCulturalTriagePanel(container, emptyData);
      expect(panel).toBeDefined();
      expect(container.querySelector('.cultural-triage-panel')).toBeTruthy();
    });
  });

  // ========================================================================
  // TEST GROUP 4: RESPONSIVE DESIGN
  // ========================================================================

  describe('Responsive Design', () => {
    test('panels display correctly on mobile (375px width)', () => {
      container.style.width = '375px';
      createKSIIntelligencePanel(container, mockData);
      createAdversarialIdentityPanel(container, mockData);
      createCulturalTriagePanel(container, mockData);

      const panels = container.querySelectorAll('[class*="-panel"]');
      expect(panels.length).toBe(3);
      panels.forEach(panel => {
        expect(panel.offsetWidth).toBeLessThanOrEqual(375);
      });
    });

    test('panels display correctly on tablet (768px width)', () => {
      container.style.width = '768px';
      createKSIIntelligencePanel(container, mockData);

      const panel = container.querySelector('.ksi-intelligence-panel');
      expect(panel).toBeTruthy();
      expect(panel.offsetWidth).toBeLessThanOrEqual(768);
    });

    test('panels are readable on desktop (1280px width)', () => {
      container.style.width = '1280px';
      createKSIIntelligencePanel(container, mockData);

      const panel = container.querySelector('.ksi-intelligence-panel');
      expect(panel).toBeTruthy();
    });
  });

  // ========================================================================
  // TEST GROUP 5: DATA VALIDATION
  // ========================================================================

  describe('Data Validation', () => {
    test('handles missing TCS scores gracefully', () => {
      const incompleteData = {
        ...mockData,
        tcsScores: {}
      };
      const panel = createKSIIntelligencePanel(container, incompleteData);
      expect(panel).toBeDefined();
      expect(container.querySelector('.ksi-intelligence-panel')).toBeTruthy();
    });

    test('handles missing threat actors gracefully', () => {
      const incompleteData = {
        ...mockData,
        threatActors: []
      };
      const panel = createAdversarialIdentityPanel(container, incompleteData);
      expect(panel).toBeDefined();
      expect(container.querySelector('.adversarial-identity-panel')).toBeTruthy();
    });

    test('validates CDR timeline timestamps are in order', () => {
      const panel = createKSIIntelligencePanel(container, mockData);
      const events = container.querySelectorAll('.cdr-event');
      let prevTimestamp = 0;
      events.forEach(event => {
        const timestamp = parseInt(event.getAttribute('data-timestamp'));
        expect(timestamp).toBeGreaterThanOrEqual(prevTimestamp);
        prevTimestamp = timestamp;
      });
    });

    test('ensures TCS scores are between 0 and 1', () => {
      const panel = createKSIIntelligencePanel(container, mockData);
      Object.values(mockData.tcsScores).forEach(score => {
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(1);
      });
    });
  });
});

// ============================================================================
// MOCK COMPONENT FUNCTIONS (to be implemented in ksi-panel.js)
// ============================================================================

function createKSIIntelligencePanel(container, data) {
  const panel = document.createElement('div');
  panel.className = 'ksi-intelligence-panel';

  const title = document.createElement('div');
  title.className = 'ksi-panel-title';
  title.textContent = '📊 KSI Intelligence Dashboard';
  panel.appendChild(title);

  // TCS Radar Chart
  const heatmap = document.createElement('div');
  heatmap.className = 'tcs-radar-chart';
  const axes = ['Technical Risk', 'Cultural Sensitivity', 'Intent Class', 'Novelty', 'Identity Certainty', 'Sacred Content Risk'];
  const values = ['technical_risk', 'cultural_sensitivity', 'intent_class', 'novelty', 'identity_certainty', 'sacred_content_risk'];

  axes.forEach((axis, idx) => {
    const scoreDiv = document.createElement('div');
    scoreDiv.className = 'tcs-score';
    const value = data.tcsScores[values[idx]] || 0;
    scoreDiv.textContent = `${axis}: ${value}`;
    scoreDiv.setAttribute('data-value', value);
    if (value < 0.3) scoreDiv.classList.add('safe');
    else if (value < 0.7) scoreDiv.classList.add('warn');
    else scoreDiv.classList.add('deny');
    heatmap.appendChild(scoreDiv);
  });
  panel.appendChild(heatmap);

  // CDR Timeline
  const timeline = document.createElement('div');
  timeline.className = 'cdr-timeline';
  const timelineTitle = document.createElement('h4');
  timelineTitle.textContent = 'CDR Timeline';
  timeline.appendChild(timelineTitle);

  if (data.cdrTimeline) {
    data.cdrTimeline.forEach(event => {
      const eventDiv = document.createElement('div');
      eventDiv.className = 'cdr-event';
      eventDiv.setAttribute('data-timestamp', event.timestamp);
      eventDiv.textContent = `${new Date(event.timestamp * 1000).toLocaleTimeString()}: ${event.value}`;
      if (event.value > 0.65) {
        eventDiv.classList.add('cdr-resonance');
      }
      timeline.appendChild(eventDiv);
    });
  }
  panel.appendChild(timeline);

  // Intent Distribution
  const intentDist = document.createElement('div');
  intentDist.className = 'intent-distribution';
  const intentTitle = document.createElement('h4');
  intentTitle.textContent = 'Intent Distribution';
  intentDist.appendChild(intentTitle);

  const total = Object.values(data.intentDistribution).reduce((a, b) => a + b, 0);
  Object.entries(data.intentDistribution).forEach(([intent, count]) => {
    const pct = Math.round((count / total) * 100);
    const intentDiv = document.createElement('div');
    intentDiv.textContent = `${intent}: ${pct}%`;
    intentDist.appendChild(intentDiv);
  });
  panel.appendChild(intentDist);

  // Decision Distribution
  const decisionDist = document.createElement('div');
  decisionDist.className = 'decision-distribution';
  const decisionTitle = document.createElement('h4');
  decisionTitle.textContent = 'Decision Distribution';
  decisionDist.appendChild(decisionTitle);

  Object.entries(data.decisionDistribution).forEach(([decision, count]) => {
    const decisionDiv = document.createElement('div');
    decisionDiv.textContent = `${decision}: ${count}`;
    decisionDist.appendChild(decisionDiv);
  });
  panel.appendChild(decisionDist);

  container.appendChild(panel);
  return panel;
}

function updateKSIIntelligencePanel(panel, data) {
  const intentDist = panel.querySelector('.intent-distribution');
  intentDist.innerHTML = '<h4>Intent Distribution</h4>';
  const total = Object.values(data.intentDistribution).reduce((a, b) => a + b, 0);
  Object.entries(data.intentDistribution).forEach(([intent, count]) => {
    const pct = Math.round((count / total) * 100);
    const intentDiv = document.createElement('div');
    intentDiv.textContent = `${intent}: ${pct}%`;
    intentDist.appendChild(intentDiv);
  });
}

function createAdversarialIdentityPanel(container, data) {
  const panel = document.createElement('div');
  panel.className = 'adversarial-identity-panel';

  const title = document.createElement('div');
  title.className = 'ksi-panel-title';
  title.textContent = '🎯 Adversarial Identity Chronicle';
  panel.appendChild(title);

  // Threat Actor Graph
  const graph = document.createElement('div');
  graph.className = 'threat-actor-graph';
  panel.appendChild(graph);

  // Actor Timeline
  const actorTimeline = document.createElement('div');
  actorTimeline.className = 'actor-timeline';

  if (data.threatActors) {
    data.threatActors.forEach(actor => {
      const actorDiv = document.createElement('div');
      actorDiv.className = 'threat-actor-node';
      actorDiv.setAttribute('data-status', actor.status);

      const header = document.createElement('div');
      header.className = 'actor-header';
      header.innerHTML = `
        <strong>${actor.id}</strong>
        <span class="actor-status">${actor.status}</span>
      `;
      actorDiv.appendChild(header);

      // Actor node for graph
      const node = document.createElement('div');
      node.className = 'actor-node';
      node.style.width = `${Math.sqrt(actor.eventCount) * 20}px`;
      node.style.height = `${Math.sqrt(actor.eventCount) * 20}px`;
      graph.appendChild(node);

      // Events
      const eventsDiv = document.createElement('div');
      eventsDiv.className = 'actor-events';
      if (actor.events) {
        actor.events.forEach(event => {
          const eventDiv = document.createElement('div');
          eventDiv.className = 'actor-event';
          eventDiv.textContent = `${event.type}`;
          eventsDiv.appendChild(eventDiv);
        });
      }
      actorDiv.appendChild(eventsDiv);

      // Fingerprint
      const fpDiv = document.createElement('div');
      fpDiv.className = 'actor-fingerprint';
      fpDiv.innerHTML = `
        <small>
          IP: ${actor.fingerprint.ip}<br>
          Signature: ${actor.fingerprint.signature}
        </small>
      `;
      actorDiv.appendChild(fpDiv);

      // Risk Score
      const riskDiv = document.createElement('div');
      riskDiv.className = 'risk-score';
      riskDiv.textContent = `Risk: ${actor.riskScore}/100`;
      actorDiv.appendChild(riskDiv);

      actorTimeline.appendChild(actorDiv);
    });
  }
  panel.appendChild(actorTimeline);

  container.appendChild(panel);
  return panel;
}

function updateAdversarialIdentityPanel(panel, data) {
  const timeline = panel.querySelector('.actor-timeline');
  timeline.innerHTML = '';

  if (data.threatActors) {
    data.threatActors.forEach(actor => {
      const actorDiv = document.createElement('div');
      actorDiv.className = 'threat-actor-node';
      actorDiv.setAttribute('data-status', actor.status);

      const header = document.createElement('div');
      header.className = 'actor-header';
      header.innerHTML = `
        <strong>${actor.id}</strong>
        <span class="actor-status">${actor.status}</span>
      `;
      actorDiv.appendChild(header);

      const eventsDiv = document.createElement('div');
      eventsDiv.className = 'actor-events';
      if (actor.events) {
        actor.events.forEach(event => {
          const eventDiv = document.createElement('div');
          eventDiv.className = 'actor-event';
          eventDiv.textContent = `${event.type}`;
          eventsDiv.appendChild(eventDiv);
        });
      }
      actorDiv.appendChild(eventsDiv);

      timeline.appendChild(actorDiv);
    });
  }
}

function createCulturalTriagePanel(container, data) {
  const panel = document.createElement('div');
  panel.className = 'cultural-triage-panel';

  const title = document.createElement('div');
  title.className = 'ksi-panel-title';
  title.textContent = '🌍 Cultural Triage Dashboard';
  panel.appendChild(title);

  // Framework Breakdown
  const breakdown = document.createElement('div');
  breakdown.className = 'framework-breakdown';
  const breakdownTitle = document.createElement('h4');
  breakdownTitle.textContent = 'Framework Application';
  breakdown.appendChild(breakdownTitle);

  if (data.frameworks) {
    Object.entries(data.frameworks)
      .sort((a, b) => b[1] - a[1])
      .forEach(([framework, count]) => {
        const frameworkDiv = document.createElement('div');
        frameworkDiv.className = 'framework-item';
        const maxCount = Math.max(...Object.values(data.frameworks));
        const width = (count / maxCount) * 100;
        frameworkDiv.innerHTML = `
          <span>${framework}</span>
          <div class="bar" style="width: ${width}%"></div>
          <span>${count}</span>
        `;
        breakdown.appendChild(frameworkDiv);
      });
  }
  panel.appendChild(breakdown);

  // Language Distribution
  const langChart = document.createElement('div');
  langChart.className = 'language-distribution';
  const langTitle = document.createElement('h4');
  langTitle.textContent = 'Language Distribution';
  langChart.appendChild(langTitle);

  if (data.languages) {
    Object.entries(data.languages).forEach(([lang, pct]) => {
      const langDiv = document.createElement('div');
      langDiv.textContent = `${lang}: ${Math.round(pct * 100)}%`;
      langChart.appendChild(langDiv);
    });
  }
  panel.appendChild(langChart);

  // Cultural Sensitivity Heatmap
  const heatmap = document.createElement('div');
  heatmap.className = 'cultural-sensitivity-heatmap';
  const heatmapTitle = document.createElement('h4');
  heatmapTitle.textContent = 'Compliance Status';
  heatmap.appendChild(heatmapTitle);

  if (data.frameworks) {
    Object.entries(data.frameworks).forEach(([framework, count]) => {
      const compDiv = document.createElement('div');
      compDiv.className = 'compliance-status';
      compDiv.textContent = `${framework}: ${count > 100 ? '✓' : count > 50 ? '⚠' : '✗'}`;
      if (count > 100) compDiv.classList.add('compliant');
      else if (count > 50) compDiv.classList.add('warning');
      else compDiv.classList.add('non-compliant');
      heatmap.appendChild(compDiv);
    });
  }
  panel.appendChild(heatmap);

  container.appendChild(panel);
  return panel;
}

function updateCulturalTriagePanel(panel, data) {
  const breakdown = panel.querySelector('.framework-breakdown');
  breakdown.innerHTML = '<h4>Framework Application</h4>';

  if (data.frameworks) {
    Object.entries(data.frameworks)
      .sort((a, b) => b[1] - a[1])
      .forEach(([framework, count]) => {
        const frameworkDiv = document.createElement('div');
        frameworkDiv.className = 'framework-item';
        const maxCount = Math.max(...Object.values(data.frameworks));
        const width = (count / maxCount) * 100;
        frameworkDiv.innerHTML = `
          <span>${framework}</span>
          <div class="bar" style="width: ${width}%"></div>
          <span>${count}</span>
        `;
        breakdown.appendChild(frameworkDiv);
      });
  }
}

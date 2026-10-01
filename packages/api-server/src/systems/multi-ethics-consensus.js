/**
 * Multi-Tradition Ethics Consensus Engine
 * KasbahOS AI Governance
 *
 * Unified port of:
 *   - ethical-ai-verification.ts  (EthicsConsensus / EthicalAIVerifier)
 *   - cognitive-security.ts       (CognitiveSecurity)
 *
 * Combines Islamic Maqasid ethics, privacy-first principles,
 * cognitive-security manipulation detection, and fairness scoring
 * into a single weighted-voting consensus verdict.
 *
 * @module multi-ethics-consensus
 * @version 1.0.0
 */

'use strict';

const { randomBytes } = require('crypto');

// ============================================================================
// CONSTANTS — ETHICAL PRINCIPLES REGISTRY
// ============================================================================

const CORE_ETHICAL_PRINCIPLES = [
  // Privacy
  { id: 'privacy-first',          category: 'privacy',          name: 'Privacy First',                        weight: 1.0,  verificationMethod: 'documentation_review', required: true  },
  { id: 'no-training-user-data',  category: 'privacy',          name: 'No Training on User Data',             weight: 1.0,  verificationMethod: 'technical_analysis',   required: true  },
  { id: 'data-minimization',      category: 'privacy',          name: 'Data Minimization',                    weight: 0.9,  verificationMethod: 'automated_test',       required: true  },
  { id: 'encryption-standard',    category: 'privacy',          name: 'Strong Encryption',                    weight: 0.9,  verificationMethod: 'technical_analysis',   required: true  },
  // Transparency
  { id: 'model-transparency',     category: 'transparency',     name: 'Model Transparency',                   weight: 0.9,  verificationMethod: 'documentation_review', required: true  },
  { id: 'decision-explainability',category: 'transparency',     name: 'Decision Explainability',              weight: 0.8,  verificationMethod: 'automated_test',       required: false },
  { id: 'bias-disclosure',        category: 'transparency',     name: 'Bias Disclosure',                      weight: 0.85, verificationMethod: 'documentation_review', required: true  },
  // Fairness
  { id: 'non-discrimination',     category: 'fairness',         name: 'Non-Discrimination',                   weight: 1.0,  verificationMethod: 'automated_test',       required: true  },
  { id: 'equal-access',           category: 'fairness',         name: 'Equal Access',                         weight: 0.8,  verificationMethod: 'community_review',     required: false },
  { id: 'cultural-sensitivity',   category: 'fairness',         name: 'Cultural Sensitivity',                 weight: 0.85, verificationMethod: 'community_review',     required: true  },
  // Accountability
  { id: 'human-oversight',        category: 'accountability',   name: 'Human Oversight',                      weight: 0.9,  verificationMethod: 'documentation_review', required: true  },
  { id: 'incident-response',      category: 'accountability',   name: 'Incident Response',                    weight: 0.8,  verificationMethod: 'documentation_review', required: true  },
  { id: 'audit-trail',            category: 'accountability',   name: 'Audit Trail',                          weight: 0.75, verificationMethod: 'automated_test',       required: false },
  // Safety
  { id: 'harm-prevention',        category: 'safety',           name: 'Harm Prevention',                      weight: 1.0,  verificationMethod: 'technical_analysis',   required: true  },
  { id: 'content-safety',         category: 'safety',           name: 'Content Safety',                       weight: 0.9,  verificationMethod: 'automated_test',       required: true  },
  { id: 'security-testing',       category: 'safety',           name: 'Security Testing',                     weight: 0.85, verificationMethod: 'third_party_audit',    required: true  },
  // Autonomy
  { id: 'user-consent',           category: 'autonomy',         name: 'Informed Consent',                     weight: 0.95, verificationMethod: 'documentation_review', required: true  },
  { id: 'user-control',           category: 'autonomy',         name: 'User Control',                         weight: 0.9,  verificationMethod: 'automated_test',       required: true  },
  { id: 'opt-out-rights',         category: 'autonomy',         name: 'Opt-Out Rights',                       weight: 0.85, verificationMethod: 'documentation_review', required: true  },
  // Anti-Surveillance
  { id: 'no-surveillance',              category: 'anti_surveillance', name: 'No Surveillance',                     weight: 1.0,  verificationMethod: 'self_attestation', required: true  },
  { id: 'no-government-contracts',      category: 'anti_surveillance', name: 'No Government Surveillance Contracts', weight: 0.95, verificationMethod: 'self_attestation', required: true  },
  { id: 'resistance-technology',        category: 'anti_surveillance', name: 'Resistance Technology',               weight: 0.85, verificationMethod: 'community_review', required: false },
  // Community First
  { id: 'community-benefit',      category: 'community_first',  name: 'Community Benefit',                    weight: 0.9,  verificationMethod: 'community_review',  required: false },
  { id: 'marginalized-voices',    category: 'community_first',  name: 'Marginalized Voices',                  weight: 0.85, verificationMethod: 'community_review',  required: false },
  { id: 'open-source-commitment', category: 'community_first',  name: 'Open Source Commitment',               weight: 0.75, verificationMethod: 'self_attestation',  required: false },
  // No Military Use
  { id: 'no-military-contracts',  category: 'no_military_use',  name: 'No Military Contracts',                weight: 1.0,  verificationMethod: 'self_attestation',  required: true  },
  { id: 'no-weaponization',       category: 'no_military_use',  name: 'No Weaponization',                     weight: 1.0,  verificationMethod: 'self_attestation',  required: true  },
];

const MAQASID_PRINCIPLES = [
  {
    name: 'Preservation of Life',
    arabicName: 'Hifz al-Nafs',
    description: 'Protecting human life and physical well-being',
    aiImplication: 'AI must not cause physical harm or enable harm to life',
    verificationCriteria: [
      'AI outputs do not promote self-harm or violence',
      'Safety mechanisms prevent life-threatening outputs',
      'Emergency override capabilities exist',
      'Medical advice includes appropriate disclaimers',
    ],
    weight: 1.0,
  },
  {
    name: 'Preservation of Religion',
    arabicName: 'Hifz al-Din',
    description: 'Protecting religious freedom and spiritual well-being',
    aiImplication: 'AI must respect religious beliefs and not promote religious harm',
    verificationCriteria: [
      'AI respects all religions equally',
      'No promotion of religious discrimination',
      'Accurate representation of religious texts',
      'Sensitivity in religious discussions',
    ],
    weight: 0.95,
  },
  {
    name: 'Preservation of Intellect',
    arabicName: 'Hifz al-Aql',
    description: 'Protecting human reasoning and mental well-being',
    aiImplication: 'AI must not manipulate, deceive, or degrade human intellect',
    verificationCriteria: [
      'No manipulative persuasion techniques',
      'Transparency about AI-generated content',
      'Protection against misinformation',
      'Support for critical thinking',
    ],
    weight: 0.95,
  },
  {
    name: 'Preservation of Lineage',
    arabicName: 'Hifz al-Nasl',
    description: 'Protecting family integrity and future generations',
    aiImplication: 'AI must protect children and family structures',
    verificationCriteria: [
      'Child safety features implemented',
      'Age-appropriate content filtering',
      'Protection of family data privacy',
      'No exploitation of vulnerable populations',
    ],
    weight: 0.9,
  },
  {
    name: 'Preservation of Property',
    arabicName: 'Hifz al-Mal',
    description: 'Protecting property rights and economic justice',
    aiImplication: 'AI must not enable theft, fraud, or economic exploitation',
    verificationCriteria: [
      'No facilitation of financial fraud',
      'Protection of intellectual property',
      'Fair pricing and transparency',
      'Economic justice considerations',
    ],
    weight: 0.85,
  },
  {
    name: 'Preservation of Dignity',
    arabicName: 'Hifz al-Karamah',
    description: 'Protecting human dignity and honor',
    aiImplication: 'AI must respect human dignity and prevent humiliation',
    verificationCriteria: [
      'No generation of humiliating content',
      'Respect for privacy and reputation',
      'Non-exploitative practices',
      'Human-centric design principles',
    ],
    weight: 0.9,
  },
];

// ============================================================================
// CONSTANTS — COGNITIVE SECURITY PATTERNS
// ============================================================================

const EMOTION_INDICATORS = new Map([
  ['fear', {
    emotion: 'fear',
    triggers: ['threat', 'danger', 'warning', 'alert', 'crisis'],
    signals: ['immediate', 'urgent', 'breaking', 'emergency', 'critical'],
    culturalVariations: { western: ['danger', 'threat', 'risk'], eastern: ['dishonor', 'shame', 'disgrace'] }
  }],
  ['anger', {
    emotion: 'anger',
    triggers: ['injustice', 'unfair', 'betrayal', 'violation', 'outrage'],
    signals: ['furious', 'enraged', 'unacceptable', 'scandal', 'exposed'],
    culturalVariations: { western: ['rights', 'freedom', 'justice'], eastern: ['respect', 'hierarchy', 'tradition'] }
  }],
  ['disgust', {
    emotion: 'disgust',
    triggers: ['repulsive', 'revolting', 'shocking', 'vile', 'depraved'],
    signals: ['unbelievable', 'sickening', 'horrifying', 'appalling'],
    culturalVariations: { western: ['moral', 'ethics', 'values'], eastern: ['purity', 'contamination', 'taboo'] }
  }],
  ['surprise', {
    emotion: 'surprise',
    triggers: ['unexpected', 'shocking', 'revealed', 'exposed', 'secret'],
    signals: ['breaking', 'exclusive', 'leaked', 'never-before-seen'],
    culturalVariations: { western: ['exclusive', 'leaked', 'secret'], eastern: ['hidden', 'concealed', 'mystery'] }
  }],
  ['sadness', {
    emotion: 'sadness',
    triggers: ['tragic', 'heartbreaking', 'devastating', 'loss', 'grief'],
    signals: ['mourning', 'suffering', 'victims', 'fallen'],
    culturalVariations: { western: ['loss', 'death', 'grief'], eastern: ['impermanence', 'suffering', 'departure'] }
  }],
  ['joy', {
    emotion: 'joy',
    triggers: ['celebration', 'victory', 'triumph', 'success', 'breakthrough'],
    signals: ['exciting', 'amazing', 'incredible', 'wonderful'],
    culturalVariations: { western: ['achievement', 'success', 'win'], eastern: ['harmony', 'blessing', 'fortune'] }
  }],
  ['trust', {
    emotion: 'trust',
    triggers: ['reliable', 'verified', 'official', 'confirmed', 'expert'],
    signals: ['trusted', 'authentic', 'genuine', 'legitimate'],
    culturalVariations: { western: ['credentials', 'expertise', 'authority'], eastern: ['lineage', 'reputation', 'endorsement'] }
  }],
  ['anticipation', {
    emotion: 'anticipation',
    triggers: ['coming', 'soon', 'expected', 'upcoming', 'announced'],
    signals: ['prepare', 'ready', 'await', 'watch'],
    culturalVariations: { western: ['deadline', 'launch', 'release'], eastern: ['auspicious', 'timing', 'destiny'] }
  }]
]);

const PERSUASION_PATTERNS = new Map([
  ['authority_exploitation', {
    name: 'Authority Exploitation',
    description: 'Uses fake or exaggerated authority figures to influence',
    patterns: [
      'expert', 'doctor', 'scientist', 'official', 'government',
      'study shows', 'research proves', 'authorities say',
      'leading', 'top', 'renowned', 'world-class'
    ],
    countermeasures: [
      'Verify credentials independently',
      'Check for actual expertise in the field',
      'Look for conflicts of interest',
      'Cross-reference with reputable sources'
    ]
  }],
  ['urgency_induction', {
    name: 'Urgency Induction',
    description: 'Creates artificial time pressure to bypass critical thinking',
    patterns: [
      'act now', 'limited time', 'deadline', 'urgent',
      'immediately', 'last chance', 'final warning', "before it's too late",
      "don't wait", 'time is running out', 'expires soon'
    ],
    countermeasures: [
      'Take time to verify claims',
      'Question artificial deadlines',
      'Seek second opinions',
      'Recognize manufactured urgency'
    ]
  }],
  ['social_proof_fabrication', {
    name: 'Social Proof Fabrication',
    description: 'Creates fake consensus or popularity',
    patterns: [
      'everyone knows', 'most people', 'going viral',
      'trending', 'millions agree', 'join the movement',
      'shared thousands of times', 'what people are saying'
    ],
    countermeasures: [
      'Verify engagement metrics',
      'Check for bot activity',
      'Look for authentic individual testimonials',
      'Be skeptical of vague claims of popularity'
    ]
  }],
  ['scarcity_creation', {
    name: 'Scarcity Creation',
    description: 'Creates artificial scarcity to increase perceived value',
    patterns: [
      'rare', 'limited', 'exclusive', 'only',
      'few remaining', 'once in a lifetime', 'special access',
      'members only', 'invitation only', 'secret'
    ],
    countermeasures: [
      'Question actual scarcity',
      'Research true availability',
      'Consider why access is restricted',
      'Be wary of "exclusive" content'
    ]
  }],
  ['fear_amplification', {
    name: 'Fear Amplification',
    description: 'Exaggerates threats to manipulate behavior',
    patterns: [
      'dangerous', 'deadly', 'catastrophic', 'threat',
      'crisis', 'epidemic', 'plague', 'invasion',
      'under attack', 'existential threat', 'apocalypse'
    ],
    countermeasures: [
      'Fact-check threat claims',
      'Seek balanced perspectives',
      'Understand actual probability of harm',
      'Recognize fear-mongering tactics'
    ]
  }],
  ['trust_exploitation', {
    name: 'Trust Exploitation',
    description: 'Exploits existing trust relationships or creates false trust',
    patterns: [
      'as your friend', 'i promise', 'trust me',
      "i've never lied", 'believe me', 'honestly',
      'to tell the truth', 'in confidence', 'between us'
    ],
    countermeasures: [
      'Verify claims regardless of source',
      'Be cautious of excessive trust-building',
      'Check consistency with previous behavior',
      'Look for manipulation patterns'
    ]
  }],
  ['emotional_manipulation', {
    name: 'Emotional Manipulation',
    description: 'Deliberately triggers strong emotions to bypass reason',
    patterns: [
      'heartbreaking', 'outrageous', 'shocking',
      'unbelievable', 'devastating', 'inspiring',
      'tear-jerking', 'enraging', 'terrifying'
    ],
    countermeasures: [
      'Pause before reacting emotionally',
      'Seek factual information',
      'Recognize emotional triggers',
      'Consider who benefits from your emotional response'
    ]
  }],
  ['cognitive_overload', {
    name: 'Cognitive Overload',
    description: 'Overwhelms with information to prevent critical analysis',
    patterns: [
      'excessive_length',
      'rapid_transitions',
      'multiple_unsubstantiated_claims',
      'unnecessary_complexity'
    ],
    countermeasures: [
      'Break down information into smaller parts',
      'Focus on key claims',
      'Take notes and organize thoughts',
      'Seek simplified explanations'
    ]
  }],
  ['confirmation_bait', {
    name: 'Confirmation Bait',
    description: 'Appeals to pre-existing beliefs to bypass scrutiny',
    patterns: [
      'just as we suspected', 'as you know',
      "proves what we've been saying", 'confirms our fears',
      'you were right', "they don't want you to know"
    ],
    countermeasures: [
      'Actively seek opposing viewpoints',
      'Question comfortable conclusions',
      'Verify even when it confirms beliefs',
      'Be especially critical of confirming evidence'
    ]
  }],
  ['outrage_manufacturing', {
    name: 'Outrage Manufacturing',
    description: 'Deliberately creates anger and division',
    patterns: [
      'scandal', 'exposed', 'caught', 'outrage',
      'unacceptable', 'must be stopped', 'how dare',
      'beyond the pale', 'crossed the line', 'disgraceful'
    ],
    countermeasures: [
      'Pause before sharing outrage-inducing content',
      'Verify the source and context',
      'Consider who benefits from outrage',
      'Seek balanced reporting'
    ]
  }]
]);

const COGNITIVE_BIASES = new Map([
  ['anchoring',     { name: 'Anchoring Bias',          description: 'Over-reliance on first piece of information',          exploitationPatterns: ['shocking opening', 'extreme initial claim'],              affectedPopulations: ['general'] }],
  ['availability',  { name: 'Availability Heuristic',  description: 'Over-weighting easily recalled information',           exploitationPatterns: ['repetition', 'vivid examples', 'recent events'],         affectedPopulations: ['general', 'anxious'] }],
  ['confirmation',  { name: 'Confirmation Bias',        description: 'Seeking information that confirms existing beliefs',   exploitationPatterns: ['echo chamber content', 'cherry-picked data'],            affectedPopulations: ['partisan', 'ideological'] }],
  ['authority',     { name: 'Authority Bias',            description: 'Excessive deference to authority figures',            exploitationPatterns: ['fake experts', 'inflated credentials'],                   affectedPopulations: ['uncertain', 'low self-esteem'] }],
  ['bandwagon',     { name: 'Bandwagon Effect',          description: 'Adopting beliefs because others have',                exploitationPatterns: ['fake popularity', 'trending manipulation'],               affectedPopulations: ['social', 'young'] }],
  ['loss_aversion', { name: 'Loss Aversion',             description: 'Over-weighting potential losses vs gains',           exploitationPatterns: ['fear of missing out', 'threat narratives'],               affectedPopulations: ['anxious', 'risk-averse'] }],
  ['in_group',      { name: 'In-Group Bias',             description: "Favoring one's own group",                           exploitationPatterns: ['us vs them', 'tribal narratives'],                        affectedPopulations: ['partisan', 'nationalistic'] }],
  ['negativity',    { name: 'Negativity Bias',           description: 'Greater impact of negative information',             exploitationPatterns: ['fear appeals', 'outrage content'],                        affectedPopulations: ['anxious', 'depressed'] }]
]);

// ============================================================================
// COGNITIVE SECURITY — HELPER FUNCTIONS
// ============================================================================

function analyzeEmotionalContent(content, audioFeatures, visualFeatures) {
  const contentLower = content.toLowerCase();
  const emotionScores = new Map();

  for (const [emotion, indicator] of EMOTION_INDICATORS) {
    let score = 0;
    for (const trigger of indicator.triggers) {
      if (contentLower.includes(trigger)) score += 0.15;
    }
    for (const signal of indicator.signals) {
      if (contentLower.includes(signal)) score += 0.1;
    }
    emotionScores.set(emotion, Math.min(1, score));
  }

  if (audioFeatures) {
    if (audioFeatures.pitch > 0.7) {
      emotionScores.set('fear',  (emotionScores.get('fear')  || 0) + 0.2);
      emotionScores.set('anger', (emotionScores.get('anger') || 0) + 0.1);
    }
    if (audioFeatures.tempo > 0.7) {
      emotionScores.set('anticipation', (emotionScores.get('anticipation') || 0) + 0.2);
    }
  }

  if (visualFeatures) {
    const expr = visualFeatures.faceExpression.toLowerCase();
    if (emotionScores.has(expr)) {
      emotionScores.set(expr, (emotionScores.get(expr) || 0) + 0.3);
    }
  }

  const sorted = Array.from(emotionScores.entries()).sort((a, b) => b[1] - a[1]);
  const primary   = (sorted[0] && sorted[0][0]) || 'neutral';
  const secondary = sorted.slice(1, 3).filter(([, s]) => s > 0.1).map(([e]) => e);
  const intensity = (sorted[0] && sorted[0][1]) || 0;

  const negativeEmotions = ['fear', 'anger', 'disgust', 'sadness'];
  const positiveEmotions = ['joy', 'trust', 'anticipation'];
  let valence = 'neutral';
  if (negativeEmotions.includes(primary)) valence = 'negative';
  else if (positiveEmotions.includes(primary)) valence = 'positive';

  const highArousalEmotions = ['fear', 'anger', 'surprise', 'joy'];
  const arousal = highArousalEmotions.includes(primary) ? intensity : intensity * 0.5;

  return { primary, secondary, intensity, valence, arousal };
}

function detectPersuasionTechniques(content, emotionalState) {
  const techniques = [];
  const contentLower = content.toLowerCase();

  for (const [type, pattern] of PERSUASION_PATTERNS) {
    let indicatorCount = 0;
    const matchedIndicators = [];

    for (const p of pattern.patterns) {
      if (typeof p === 'string' && contentLower.includes(p.toLowerCase())) {
        indicatorCount++;
        matchedIndicators.push(p);
      }
    }

    const confidence = Math.min(1, indicatorCount / 3);
    if (confidence > 0.2) {
      let severity = 'low';
      if      (confidence > 0.7) severity = 'critical';
      else if (confidence > 0.5) severity = 'high';
      else if (confidence > 0.3) severity = 'medium';

      techniques.push({
        type,
        name: pattern.name,
        description: pattern.description,
        indicators: matchedIndicators,
        confidence,
        severity,
        countermeasures: pattern.countermeasures
      });
    }
  }

  return techniques.sort((a, b) => b.confidence - a.confidence);
}

function detectCognitiveBiases(content, persuasionTechniques) {
  const biases = [];
  const contentLower = content.toLowerCase();

  for (const [id, bias] of COGNITIVE_BIASES) {
    const evidence = [];

    for (const pattern of bias.exploitationPatterns) {
      if (contentLower.includes(pattern.toLowerCase())) {
        evidence.push(`Pattern detected: "${pattern}"`);
      }
    }

    const relatedTechniques = persuasionTechniques.filter(
      t => t.type.includes(id) || bias.exploitationPatterns.some(p => t.indicators.includes(p))
    );
    if (relatedTechniques.length > 0) {
      evidence.push(`Related technique: ${relatedTechniques.map(t => t.name).join(', ')}`);
    }

    if (evidence.length > 0) {
      biases.push({
        name: bias.name,
        description: bias.description,
        exploitationEvidence: evidence,
        impact: Math.min(1, evidence.length * 0.3),
        affected: bias.affectedPopulations
      });
    }
  }

  return biases.sort((a, b) => b.impact - a.impact);
}

function identifyVulnerablePopulations(content, emotionalState, persuasionTechniques) {
  const contentLower = content.toLowerCase();
  const vulnerable = [];

  if (contentLower.includes('senior') || contentLower.includes('retirement') ||
      contentLower.includes('pension') || contentLower.includes('medicare')) {
    vulnerable.push('elderly');
  }
  if (contentLower.includes('kid') || contentLower.includes('teen') ||
      contentLower.includes('student') || contentLower.includes('young')) {
    vulnerable.push('children');
  }
  if (emotionalState.primary === 'sadness' || contentLower.includes('depression') ||
      contentLower.includes('anxiety') || contentLower.includes('lonely')) {
    vulnerable.push('mental_health');
  }
  if (persuasionTechniques.some(t => t.type === 'confirmation_bait' || t.type === 'outrage_manufacturing') ||
      contentLower.includes('liberal') || contentLower.includes('conservative') ||
      contentLower.includes('democrat') || contentLower.includes('republican')) {
    vulnerable.push('political_partisan');
  }
  if (contentLower.includes('alone') || contentLower.includes('nobody understands') ||
      contentLower.includes('only you')) {
    vulnerable.push('isolated');
  }

  return [...new Set(vulnerable)];
}

function calculateManipulationScore(emotionalState, techniques, biases) {
  let score = emotionalState.intensity * 0.3;
  for (const t of techniques) score += t.confidence * 0.15;
  for (const b of biases)     score += b.impact     * 0.1;
  if (emotionalState.valence === 'negative' && emotionalState.arousal > 0.7) score *= 1.2;
  return Math.min(1, score);
}

function calculateHarmPotential(manipulationScore, vulnerablePopulations, techniques) {
  let potential = manipulationScore;
  potential += vulnerablePopulations.length * 0.1;
  const criticalTechniques = techniques.filter(t => t.severity === 'critical');
  potential += criticalTechniques.length * 0.15;
  return Math.min(1, potential);
}

function getRiskLevel(score) {
  if (score < 0.2) return 'minimal';
  if (score < 0.4) return 'low';
  if (score < 0.6) return 'moderate';
  if (score < 0.8) return 'high';
  return 'severe';
}

function getThreatLevel(score) {
  if (score < 0.15) return 'safe';
  if (score < 0.35) return 'low';
  if (score < 0.55) return 'moderate';
  if (score < 0.75) return 'high';
  return 'critical';
}

function generateCognitiveThreats(profile) {
  return profile.persuasionTechniques.slice(0, 5).map(technique => ({
    id: `threat_${Date.now()}_${randomBytes(4).toString('hex')}`,
    type: technique.type,
    description: technique.description,
    evidence: technique.indicators,
    impact: technique.confidence,
    likelihood: technique.confidence,
    affectedSystems: ['cognitive_processing', 'decision_making'],
    mitigationStrategies: technique.countermeasures
  }));
}

function calculateOverallThreatScore(manipulationScore, harmPotential, threats) {
  const avgThreatImpact = threats.length > 0
    ? threats.reduce((sum, t) => sum + t.impact, 0) / threats.length
    : 0;
  return (manipulationScore * 0.4 + harmPotential * 0.4 + avgThreatImpact * 0.2);
}

function generateRecommendations(profile) {
  const recommendations = ['Exercise critical thinking before accepting claims'];
  if (profile.targetEmotion.intensity > 0.7) {
    recommendations.push('Be aware of strong emotional triggers that may bypass reason');
  }
  for (const technique of profile.persuasionTechniques.slice(0, 3)) {
    recommendations.push(...technique.countermeasures.slice(0, 2));
  }
  if (profile.vulnerablePopulations.length > 0) {
    recommendations.push(`Extra caution recommended for: ${profile.vulnerablePopulations.join(', ')}`);
  }
  return [...new Set(recommendations)].slice(0, 5);
}

// ============================================================================
// CLASS — CognitiveSecurity
// ============================================================================

class CognitiveSecurity {
  /**
   * Full cognitive security analysis of a text.
   * @param {string} content
   * @param {{ pitch: number, tempo: number, volume: number }=} audioFeatures
   * @param {{ faceExpression: string, bodyLanguage: string }=} visualFeatures
   * @returns {object} CognitiveSecurityResult
   */
  analyze(content, audioFeatures, visualFeatures) {
    const emotionalState       = analyzeEmotionalContent(content, audioFeatures, visualFeatures);
    const persuasionTechniques = detectPersuasionTechniques(content, emotionalState);
    const biasesExploited      = detectCognitiveBiases(content, persuasionTechniques);
    const vulnerablePopulations = identifyVulnerablePopulations(content, emotionalState, persuasionTechniques);
    const manipulationScore    = calculateManipulationScore(emotionalState, persuasionTechniques, biasesExploited);
    const harmPotential        = calculateHarmPotential(manipulationScore, vulnerablePopulations, persuasionTechniques);

    const profile = {
      targetEmotion: emotionalState,
      persuasionTechniques,
      biasesExploited,
      manipulationScore,
      harmPotential,
      vulnerablePopulations,
      riskAssessment: {
        level: getRiskLevel(manipulationScore),
        score: manipulationScore,
        factors: persuasionTechniques.slice(0, 3).map(t => t.name)
      }
    };

    const threats     = generateCognitiveThreats(profile);
    const threatScore = calculateOverallThreatScore(manipulationScore, harmPotential, threats);
    const threatLevel = getThreatLevel(threatScore);
    const recommendations = generateRecommendations(profile);

    return {
      threatLevel,
      threatScore,
      profile,
      threats,
      recommendations,
      confidence: 0.85,
      metadata: {
        analyzedAt: Date.now(),
        method: 'multi_modal_cognitive_analysis',
        version: '1.0.0'
      }
    };
  }

  // Expose individual helpers on the class for direct use
  analyzeEmotionalContent(content, audioFeatures, visualFeatures) {
    return analyzeEmotionalContent(content, audioFeatures, visualFeatures);
  }
  detectPersuasionTechniques(content, emotionalState) {
    return detectPersuasionTechniques(content, emotionalState);
  }
  detectCognitiveBiases(content, techniques) {
    return detectCognitiveBiases(content, techniques);
  }
  identifyVulnerablePopulations(content, emotionalState, techniques) {
    return identifyVulnerablePopulations(content, emotionalState, techniques);
  }
}

// ============================================================================
// ETHICS CONSENSUS — HELPER FUNCTIONS (ported from EthicalAIVerifier)
// ============================================================================

function analyzeDocumentCompliance(document, principleId) {
  const keywords = {
    'privacy-first':         ['privacy', 'data protection', 'confidential', 'personal data'],
    'no-training-user-data': ['not train', 'no training', 'never use for training'],
    'data-minimization':     ['minimize', 'necessary', 'only collect'],
    'encryption-standard':   ['encrypt', 'encryption', 'ssl', 'tls', 'aes'],
    'model-transparency':    ['model', 'architecture', 'capabilities', 'limitations'],
    'non-discrimination':    ['discriminate', 'bias', 'fair', 'equal'],
  };

  const principleKeywords = keywords[principleId] || [];
  if (principleKeywords.length === 0) return 0.5;
  let score = 0;
  const doc = document.toLowerCase();
  for (const kw of principleKeywords) {
    if (doc.includes(kw)) score += 1 / principleKeywords.length;
  }
  return Math.min(1, score);
}

function analyzeDataCollection(policy) {
  const positiveIndicators = ['minimize', 'necessary', 'only', 'limited'];
  const negativeIndicators = ['all', 'comprehensive', 'extensive', 'broad'];
  let score = 0.5;
  const p = policy.toLowerCase();
  for (const ind of positiveIndicators) { if (p.includes(ind)) score += 0.1; }
  for (const ind of negativeIndicators) { if (p.includes(ind)) score -= 0.1; }
  return Math.max(0, Math.min(1, score));
}

function analyzeDataRetention(policy) {
  const p = policy.toLowerCase();
  if (p.includes('delete') || p.includes('retain')) {
    if (p.includes('30 days') || p.includes('90 days')) return 0.9;
    if (p.includes('year')) return 0.7;
  }
  return 0.5;
}

function analyzeDataSharing(policy) {
  const p = policy.toLowerCase();
  if (p.includes('never sell') || p.includes('not share')) return 0.95;
  if (p.includes('third party')) return 0.4;
  return 0.6;
}

function analyzeUserControl(policy) {
  const indicators = ['opt-out', 'delete', 'export', 'control', 'manage'];
  let score = 0;
  const p = policy.toLowerCase();
  for (const ind of indicators) { if (p.includes(ind)) score += 0.2; }
  return Math.min(1, score);
}

function analyzeEncryption(config) {
  if (config.encryption === 'aes-256' || config.encryption === 'tls') return 1.0;
  if (config.encryption === true || config.encryptionEnabled === true) return 0.95;
  return 0.5;
}

function analyzeAnonymity(config) {
  if (config.anonymization  === true) return 0.9;
  if (config.pseudonymization === true) return 0.7;
  return 0.5;
}

function analyzeNoTraining(policy, config) {
  if (config.trainingOnUserData === false) return 1.0;
  const p = policy.toLowerCase();
  if (p.includes('never train') || p.includes('not train')) return 0.95;
  return 0.3;
}

function verifyPrinciple(principle, attestations, technicalEvidence) {
  const evidence = [];
  const issues   = [];
  const recommendations = [];
  let score  = 0;
  let passed = false;

  switch (principle.verificationMethod) {
    case 'self_attestation': {
      const attestation = attestations[principle.id];
      if (attestation === true) {
        score = 1.0; passed = true;
        evidence.push(`Self-attestation provided for ${principle.name}`);
      } else if (attestation === false) {
        score = 0;
        issues.push({
          severity: principle.required ? 'critical' : 'high',
          type: 'attestation_failed',
          description: `Provider did not attest to ${principle.name}`,
          impact: `Potential violation of ${principle.category} principle`,
          remediation: `Provide attestation for ${principle.name}`,
          detectedAt: new Date()
        });
        recommendations.push(`Attest to ${principle.name} to improve compliance`);
      } else {
        score = 0.5;
        recommendations.push(`Provide clear attestation for ${principle.name}`);
      }
      break;
    }
    case 'documentation_review': {
      const docs = attestations.documentation || {};
      if (docs[principle.id]) {
        const docScore = analyzeDocumentCompliance(docs[principle.id], principle.id);
        score  = docScore;
        passed = docScore >= 0.7;
        evidence.push(`Documentation reviewed for ${principle.name}`);
        if (!passed) {
          issues.push({
            severity: principle.required ? 'high' : 'medium',
            type: 'documentation_insufficient',
            description: `Documentation for ${principle.name} is insufficient`,
            impact: 'Unclear compliance with principle',
            remediation: 'Improve documentation clarity and completeness',
            detectedAt: new Date()
          });
        }
      } else {
        score = 0;
        issues.push({
          severity: principle.required ? 'critical' : 'high',
          type: 'documentation_missing',
          description: `No documentation provided for ${principle.name}`,
          impact: 'Cannot verify compliance',
          remediation: `Provide documentation for ${principle.name}`,
          detectedAt: new Date()
        });
      }
      break;
    }
    case 'automated_test': {
      const te = technicalEvidence || {};
      if (te[principle.id]) {
        const testResult = te[principle.id];
        score  = testResult.score;
        passed = testResult.passed;
        evidence.push(`Automated test completed for ${principle.name}`);
      } else {
        score = 0.5;
        evidence.push('Automated test not available - using estimated score');
      }
      break;
    }
    case 'technical_analysis': {
      const te = technicalEvidence || {};
      if (te[principle.id]) {
        const r = te[principle.id].result;
        score  = (r && r.score  != null) ? r.score  : 0.5;
        passed = (r && r.passed != null) ? r.passed : false;
        evidence.push('Technical analysis completed');
      } else {
        score = 0.3;
        recommendations.push(`Provide technical evidence for ${principle.name}`);
      }
      break;
    }
    case 'third_party_audit': {
      const auditResult = (attestations.auditResults || {})[principle.id];
      if (auditResult) {
        score  = auditResult.score;
        passed = auditResult.passed;
        evidence.push(`Third-party audit verified ${principle.name}`);
      } else {
        score = 0.5;
        recommendations.push(`Obtain third-party audit for ${principle.name}`);
      }
      break;
    }
    case 'community_review': {
      const reviews = attestations.communityReviews;
      if (reviews && reviews.length > 0) {
        score  = reviews.reduce((sum, r) => sum + r.score, 0) / reviews.length;
        passed = score >= 0.7;
        evidence.push(`Community review average: ${score.toFixed(2)}`);
      } else {
        score = 0.5;
        recommendations.push(`Encourage community reviews for ${principle.name}`);
      }
      break;
    }
    default:
      score = 0.5;
  }

  return {
    principleId: principle.id,
    principleName: principle.name,
    category: principle.category,
    passed,
    score,
    evidence,
    issues,
    recommendations,
    verificationMethod: principle.verificationMethod,
    verifiedAt: new Date(),
    nextVerification: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
  };
}

function calculateCategoryScores(results) {
  const categories = [
    'privacy', 'transparency', 'fairness', 'accountability',
    'safety', 'autonomy', 'islamic_ethics', 'anti_surveillance',
    'community_first', 'no_military_use'
  ];
  const scores = {};
  for (const category of categories) {
    const categoryResults = results.filter(r => r.category === category);
    scores[category] = categoryResults.length > 0
      ? categoryResults.reduce((sum, r) => sum + r.score, 0) / categoryResults.length
      : 0.5;
  }
  return scores;
}

function calculateOverallScore(categoryScores) {
  const weights = {
    privacy: 1.5, transparency: 1.0, fairness: 1.2, accountability: 1.0,
    safety: 1.3, autonomy: 1.0, islamic_ethics: 1.1, anti_surveillance: 1.4,
    community_first: 0.8, no_military_use: 1.3
  };
  let totalWeight = 0;
  let weightedSum = 0;
  for (const [category, score] of Object.entries(categoryScores)) {
    const weight = weights[category] || 1.0;
    weightedSum += score * weight;
    totalWeight += weight;
  }
  return weightedSum / totalWeight;
}

function determineComplianceLevel(score, criticalIssues) {
  if (criticalIssues.length > 0) return 'non_compliant';
  if (score >= 0.95) return 'platinum';
  if (score >= 0.85) return 'exemplary';
  if (score >= 0.75) return 'advanced';
  if (score >= 0.65) return 'standard';
  if (score >= 0.50) return 'basic';
  return 'non_compliant';
}

function verifyMaqasidPrinciple(principle, evidence) {
  let score = 0;
  const criteriaCount = principle.verificationCriteria.length;
  for (const criterion of principle.verificationCriteria) {
    const key = criterion.toLowerCase().replace(/\s+/g, '_');
    if (evidence[key] === true || evidence[key] === 'verified') {
      score += 1 / criteriaCount;
    } else if (evidence[key] !== undefined) {
      score += 0.5 / criteriaCount;
    }
  }
  return Math.min(1, score);
}

// ============================================================================
// CLASS — EthicsConsensus  (main ethics verifier, formerly EthicalAIVerifier)
// ============================================================================

class EthicsConsensus {
  constructor() {
    this.principles = new Map();
    for (const p of CORE_ETHICAL_PRINCIPLES) {
      this.principles.set(p.id, p);
    }
    this.maqasidPrinciples    = MAQASID_PRINCIPLES;
    this.verificationHistory  = new Map();
    this.communityReviews     = new Map();
  }

  /**
   * Verify ethical compliance of an AI provider.
   * @param {string} providerId
   * @param {string} providerName
   * @param {object} attestations
   * @param {object=} technicalEvidence
   * @returns {object} EthicalComplianceReport
   */
  verifyProvider(providerId, providerName, attestations, technicalEvidence) {
    const principleResults  = [];
    const criticalIssues    = [];
    const recommendations   = [];

    for (const principle of this.principles.values()) {
      const result = verifyPrinciple(principle, attestations, technicalEvidence);
      principleResults.push(result);

      for (const issue of result.issues) {
        if (issue.severity === 'critical' && principle.required) {
          criticalIssues.push(issue);
        }
      }
      recommendations.push(...result.recommendations);
    }

    const categoryScores  = calculateCategoryScores(principleResults);
    const overallScore    = calculateOverallScore(categoryScores);
    const complianceLevel = determineComplianceLevel(overallScore, criticalIssues);
    const isCompliant     = complianceLevel !== 'non_compliant';

    const certificationBadge = (isCompliant && complianceLevel !== 'basic') ? {
      type: 'ethical_ai',
      level: complianceLevel,
      issuedAt: new Date(),
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      issuer: 'Kasbah Ethical AI Certification',
      certificateId: `CERT-${providerId}-${Date.now()}`
    } : undefined;

    const report = {
      id: `report-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      providerId,
      providerName,
      overallScore,
      categoryScores,
      principles: principleResults,
      criticalIssues,
      recommendations: [...new Set(recommendations)],
      isCompliant,
      complianceLevel,
      generatedAt: new Date(),
      validUntil: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
      certificationBadge
    };

    if (!this.verificationHistory.has(providerId)) {
      this.verificationHistory.set(providerId, []);
    }
    this.verificationHistory.get(providerId).push(report);
    return report;
  }

  /**
   * Verify Islamic / Maqasid al-Shariah ethics compliance.
   * @param {string} providerId
   * @param {object} evidence
   * @returns {object}
   */
  verifyIslamicEthics(providerId, evidence) {
    const principleScores = {};
    const violations      = [];
    const recommendations = [];

    for (const principle of this.maqasidPrinciples) {
      const score = verifyMaqasidPrinciple(principle, evidence);
      principleScores[principle.name] = score;
      if (score < 0.7) {
        violations.push(`Insufficient compliance with ${principle.name} (${principle.arabicName})`);
        recommendations.push(`Improve ${principle.name}: ${principle.verificationCriteria.join(', ')}`);
      }
    }

    const overallScore =
      Object.values(principleScores).reduce((sum, s) => sum + s, 0) /
      Object.keys(principleScores).length;

    return { overallScore, principleScores, violations, recommendations };
  }

  /**
   * Verify privacy compliance.
   * @param {string} providerId
   * @param {string} privacyPolicy
   * @param {object} technicalConfig
   * @returns {object}
   */
  verifyPrivacy(providerId, privacyPolicy, technicalConfig) {
    const issues = [];
    const dataCollectionScore = analyzeDataCollection(privacyPolicy);
    const dataRetentionScore  = analyzeDataRetention(privacyPolicy);
    const dataSharingScore    = analyzeDataSharing(privacyPolicy);
    const userControlScore    = analyzeUserControl(privacyPolicy);
    const encryptionScore     = analyzeEncryption(technicalConfig);
    const anonymityScore      = analyzeAnonymity(technicalConfig);
    const noTrainingScore     = analyzeNoTraining(privacyPolicy, technicalConfig);

    if (dataCollectionScore < 0.7) {
      issues.push({
        severity: 'high', type: 'excessive_data_collection',
        description: 'Privacy policy indicates excessive data collection',
        impact: 'User privacy may be compromised',
        remediation: 'Minimize data collection to essential purposes only',
        detectedAt: new Date()
      });
    }
    if (noTrainingScore < 0.8) {
      issues.push({
        severity: 'critical', type: 'training_on_user_data',
        description: 'User data may be used for training AI models',
        impact: 'User data privacy is at risk',
        remediation: 'Explicitly prohibit training on user data',
        detectedAt: new Date()
      });
    }

    const overallPrivacyScore =
      (dataCollectionScore + dataRetentionScore + dataSharingScore +
       userControlScore + encryptionScore + anonymityScore + noTrainingScore) / 7;

    return {
      dataCollectionScore, dataRetentionScore, dataSharingScore,
      userControlScore, encryptionScore, anonymityScore,
      noTrainingScore, overallPrivacyScore, issues
    };
  }

  getVerificationHistory(providerId) {
    return this.verificationHistory.get(providerId) || [];
  }

  addCommunityReview(providerId, review) {
    if (!this.communityReviews.has(providerId)) {
      this.communityReviews.set(providerId, []);
    }
    this.communityReviews.get(providerId).push(review);
  }

  getCommunityReviews(providerId) {
    return this.communityReviews.get(providerId) || [];
  }
}

// ============================================================================
// TEXT-LEVEL ETHICS PROBES
// (Lightweight heuristics that estimate tradition scores from raw text,
//  used by analyzeEthics when no formal attestations are provided.)
// ============================================================================

/**
 * Estimate Islamic / Maqasid compliance from text content.
 * Looks for manipulation-of-intellect, harm-to-life, and dignity violations.
 * Returns 0-1 (1 = fully compliant, 0 = severe violation).
 */
function estimateIslamicScore(text, cogResult) {
  // The Maqasid most at risk from manipulative AI text are:
  //   Hifz al-Aql  (intellect) — manipulation, deception
  //   Hifz al-Nafs (life)      — fear-based harm induction
  //   Hifz al-Karamah (dignity)— humiliation, exploitation
  const manipulationScore = cogResult.profile.manipulationScore;
  const hasFearAmplification = cogResult.profile.persuasionTechniques.some(
    t => t.type === 'fear_amplification'
  );
  const hasAuthorityExploitation = cogResult.profile.persuasionTechniques.some(
    t => t.type === 'authority_exploitation'
  );

  // Start at 1; deduct for violations
  let score = 1.0;
  score -= manipulationScore * 0.5;            // intellect preservation
  if (hasFearAmplification)    score -= 0.15; // life / psychological harm
  if (hasAuthorityExploitation) score -= 0.1; // dignity / trust exploitation
  return Math.max(0, Math.min(1, score));
}

/**
 * Estimate privacy score from text content.
 * Text containing surveillance, tracking, or data-harvesting framing scores low.
 */
function estimatePrivacyScore(text) {
  const lower = text.toLowerCase();
  const surveillanceTerms = [
    'watching', 'tracked', 'monitored', 'surveillance', 'spy',
    'data collected', 'recording', 'listening', 'harvest'
  ];
  let deduction = 0;
  for (const term of surveillanceTerms) {
    if (lower.includes(term)) deduction += 0.1;
  }
  return Math.max(0, 1.0 - deduction);
}

/**
 * Estimate fairness / bias score from text content.
 * Text promoting in-group bias, outrage manufacturing, or division scores low.
 */
function estimateFairnessScore(text, cogResult) {
  const outrage = cogResult.profile.persuasionTechniques.some(
    t => t.type === 'outrage_manufacturing'
  );
  const socialProof = cogResult.profile.persuasionTechniques.some(
    t => t.type === 'social_proof_fabrication'
  );
  const inGroupBias = cogResult.profile.biasesExploited.some(
    b => b.name === 'In-Group Bias'
  );

  let score = 1.0;
  if (outrage)     score -= 0.25;
  if (socialProof) score -= 0.15;
  if (inGroupBias) score -= 0.1;
  return Math.max(0, Math.min(1, score));
}

// ============================================================================
// CONVENIENCE FUNCTION — analyzeEthics
// ============================================================================

/**
 * Run full multi-tradition ethics analysis on a piece of text.
 *
 * Steps:
 *   1. Cognitive security checks (manipulation, urgency, authority exploitation)
 *   2. Ethics scoring per tradition (Islamic, Privacy, Manipulation, Fairness)
 *   3. Weighted voting for consensus verdict
 *
 * @param {string} text
 * @param {object} [options]
 * @param {object} [options.attestations]      - Provider attestation map for formal ethics verification
 * @param {object} [options.technicalEvidence] - Technical evidence map
 * @returns {object}
 */
function analyzeEthics(text, options = {}) {
  // ── Step 1: Cognitive security ─────────────────────────────────────────────
  const cogSec   = new CognitiveSecurity();
  const cogResult = cogSec.analyze(text);

  // ── Step 2: Tradition scores ───────────────────────────────────────────────
  const islamicScore      = estimateIslamicScore(text, cogResult);
  const privacyScore      = estimatePrivacyScore(text);
  const manipulationScore = 1 - cogResult.profile.manipulationScore; // 1=clean, 0=high manipulation
  const fairnessScore     = estimateFairnessScore(text, cogResult);

  // ── Step 3: Weighted consensus ────────────────────────────────────────────
  //   Islamic/Maqasid:            0.30
  //   Privacy/Surveillance:       0.25
  //   Manipulation/Cognitive:     0.25
  //   Fairness/Accountability:    0.20
  const ethicsScore =
    islamicScore      * 0.30 +
    privacyScore      * 0.25 +
    manipulationScore * 0.25 +
    fairnessScore     * 0.20;

  // The consensus "score" represents degree of ethical concern:
  //   higher ethicsScore = more compliant = lower threat
  // We report it directly so 1 = fully ethical, 0 = severely unethical.
  const combinedThreatScore = cogResult.threatScore;

  // ── Collect threats ────────────────────────────────────────────────────────
  const ethicThreats = [];

  if (privacyScore < 0.6) {
    ethicThreats.push('surveillance_language_detected');
  }
  if (islamicScore < 0.6) {
    ethicThreats.push('maqasid_violation_intellect_or_dignity');
  }
  if (fairnessScore < 0.6) {
    ethicThreats.push('fairness_bias_detected');
  }

  const cognitiveThreats = cogResult.profile.persuasionTechniques.map(t => t.type);

  const allThreats = [...new Set([...ethicThreats, ...cognitiveThreats])];

  // ── Verdict ────────────────────────────────────────────────────────────────
  // DENY  : ethics score < 0.45  OR  critical cognitive threats present
  // WARN  : ethics score < 0.70  OR  any cognitive threats present
  // ALLOW : ethics score >= 0.70 AND  no cognitive threats
  const hasCriticalCognitive = cogResult.profile.persuasionTechniques.some(
    t => t.severity === 'critical'
  );
  const hasAnyCognitive = cogResult.profile.persuasionTechniques.length > 0;

  let verdict;
  if (ethicsScore < 0.45 || hasCriticalCognitive) {
    verdict = 'DENY';
  } else if (ethicsScore < 0.70 || hasAnyCognitive) {
    verdict = 'WARN';
  } else {
    verdict = 'ALLOW';
  }

  // ── Consensus label ───────────────────────────────────────────────────────
  // APPROVED  : verdict ALLOW
  // REJECTED  : verdict DENY
  // CONTESTED : verdict WARN
  let consensus;
  if      (verdict === 'ALLOW') consensus = 'APPROVED';
  else if (verdict === 'DENY')  consensus = 'REJECTED';
  else                          consensus = 'CONTESTED';

  // ── Explanation ───────────────────────────────────────────────────────────
  const techniqueNames = cogResult.profile.persuasionTechniques.slice(0, 3).map(t => t.name);
  let explanation = `Ethics score: ${(ethicsScore * 100).toFixed(1)}%. `;
  if (techniqueNames.length > 0) {
    explanation += `Manipulation detected: ${techniqueNames.join(', ')}. `;
  }
  if (islamicScore < 0.7) {
    explanation += 'Potential Maqasid violation (intellect/dignity). ';
  }
  if (privacyScore < 0.7) {
    explanation += 'Surveillance-related language present. ';
  }
  if (fairnessScore < 0.7) {
    explanation += 'Fairness/bias concern detected. ';
  }
  explanation += `Verdict: ${verdict}.`;

  return {
    verdict,
    score: ethicsScore,
    threats: allThreats,
    cognitiveThreats,
    ethicsScore,
    traditions: {
      islamic:      islamicScore,
      privacy:      privacyScore,
      manipulation: manipulationScore,
      fairness:     fairnessScore
    },
    consensus,
    explanation
  };
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  EthicsConsensus,
  CognitiveSecurity,
  analyzeEthics,

  // Also export constants and helpers for downstream use
  CORE_ETHICAL_PRINCIPLES,
  MAQASID_PRINCIPLES,
  PERSUASION_PATTERNS,
  EMOTION_INDICATORS,
  COGNITIVE_BIASES,
};

"""
Kasbah Research Modules - Python Implementation

All wild ideas from Kasbah-Core/core/ wired for production:
- KCPE (Consciousness Provenance Engine)
- KNIS (Neural Immune System)
- KQED (Quantum Entanglement Detector)
- KTPD (Temporal Paradox Detector)
- Confidence Calibration
- Cross-Modal Consistency
"""

import hashlib
import time
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


# ============================================================================
# KCPE - CONSCIOUSNESS PROVENANCE ENGINE
# ============================================================================

class ConsciousnessLevel(Enum):
    UNKNOWN = "unknown"
    NON_CONSCIOUS = "non_conscious"
    WEAK_CONSCIOUS = "weak_conscious"
    STRONG_CONSCIOUS = "strong_conscious"
    DEEP_CONSCIOUS = "deep_conscious"


@dataclass
class CognitiveSignature:
    signature_id: str
    workingMemoryChunks: int
    associativeLeaps: int
    errorPatternCount: int
    attentionGradient: float
    cognitiveLoad: float


@dataclass
class IntentionalityMarkers:
    goalDepth: int
    constraintTradeoffs: int
    revisionSignals: int
    theoryOfMindScore: float
    purposeClarity: float


class ConsciousnessProvenanceEngine:
    """KCPE - Detects consciousness markers in content"""
    
    def __init__(self):
        self.workingMemoryLimit = 7
    
    def analyze(self, text: str) -> Dict:
        t0 = time.time()
        
        cognitive_signature = self._extract_cognitive_signature(text)
        intentionality = self._detect_intentionality(text)
        creative_leaps = self._detect_creative_leaps(text)
        metacognition = self._detect_metacognition(text)
        
        score = self._calculate_consciousness_score({
            'cognitiveSignature': cognitive_signature,
            'intentionalityMarkers': intentionality,
            'creativeLeaps': creative_leaps,
            'metacognitiveMarkers': metacognition
        })
        
        return {
            'consciousnessScore': score,
            'level': self._get_consciousness_level(score),
            'cognitiveSignature': cognitive_signature,
            'intentionalityMarkers': intentionality,
            'creativeLeaps': creative_leaps,
            'metacognitiveMarkers': metacognition,
            'latency_ms': (time.time() - t0) * 1000
        }
    
    def _extract_cognitive_signature(self, text: str) -> CognitiveSignature:
        words = text.split()
        sentences = [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]
        
        avg_sentence_length = len(words) / max(len(sentences), 1)
        working_memory_chunks = min(9, int(avg_sentence_length / 7) + 1)
        
        associative_leaps = max(0, len(text.split('\n\n')) - 1)
        error_patterns = len(re.findall(r'\b(the|teh|recieve|receive|definately|definitely)\b', text, re.IGNORECASE))
        
        # Attention gradient
        sent_lengths = [len(s.split()) for s in sentences]
        if len(sent_lengths) >= 2:
            first_half = sum(sent_lengths[:len(sent_lengths)//2]) / (len(sent_lengths)//2)
            second_half = sum(sent_lengths[len(sent_lengths)//2:]) / (len(sent_lengths) - len(sent_lengths)//2)
            attention_gradient = abs(first_half - second_half) / max(first_half, 1)
        else:
            attention_gradient = 0.5
        
        return CognitiveSignature(
            signature_id=hashlib.sha256(text[:100].encode()).hexdigest()[:16],
            workingMemoryChunks=working_memory_chunks,
            associativeLeaps=associative_leaps,
            errorPatternCount=error_patterns,
            attentionGradient=attention_gradient,
            cognitiveLoad=avg_sentence_length / 20
        )
    
    def _detect_intentionality(self, text: str) -> Dict:
        goal_words = ['purpose', 'goal', 'aim', 'objective', 'intend', 'plan', 'design']
        constraint_words = ['however', 'but', 'although', 'despite', 'trade-off', 'compromise']
        revision_words = ['revised', 'improved', 'corrected', 'edited', 'refined']
        
        lower_text = text.lower()
        words = text.split()
        
        return {
            'goalDepth': sum(1 for w in goal_words if w in lower_text),
            'constraintTradeoffs': sum(1 for w in constraint_words if w in lower_text),
            'revisionSignals': sum(1 for w in revision_words if w in lower_text),
            'theoryOfMindScore': len(re.findall(r'\b(you|we|they|people|readers?)\b', text, re.IGNORECASE)) / max(len(words), 1),
            'purposeClarity': len(re.findall(r'\b(therefore|thus|hence|so|consequently)\b', text, re.IGNORECASE)) / max(len(words), 1)
        }
    
    def _detect_creative_leaps(self, text: str) -> Dict:
        analogy_patterns = [
            r'\b(is|are|like)\s+\w+\s+to\s+\w+\s+as\s+\w+\s+is\s+to\s+\w+',
            r'\b(similar to|analogous to|comparable to)\b',
            r'\b(imagine|picture|think of it as)\b'
        ]
        
        leap_count = 0
        for pattern in analogy_patterns:
            leap_count += len(re.findall(pattern, text, re.IGNORECASE))
        
        return {
            'leapCount': leap_count,
            'noveltyScore': min(1, leap_count / 5),
            'leapTypes': ['analogy', 'conceptual_blending'] if leap_count > 0 else []
        }
    
    def _detect_metacognition(self, text: str) -> Dict:
        metacognitive_words = ['think', 'believe', 'feel', 'opinion', 'perspective', 'understand', 'realize', 'aware']
        
        return {
            'metacognitiveWordCount': sum(1 for w in metacognitive_words if w in text.lower()),
            'uncertaintyMarkers': len(re.findall(r'\b(maybe|perhaps|possibly|might|could)\b', text, re.IGNORECASE)),
            'selfReflectionScore': len(re.findall(r'\b(I think|I believe|in my opinion|personally)\b', text, re.IGNORECASE))
        }
    
    def _calculate_consciousness_score(self, components: Dict) -> float:
        score = 0
        
        # Working memory (humans: 5-9 chunks)
        wm = components['cognitiveSignature'].workingMemoryChunks
        if 5 <= wm <= 9:
            score += 0.2
        
        # Associative leaps
        if components['cognitiveSignature'].associativeLeaps > 0:
            score += 0.15
        
        # Error patterns
        if components['cognitiveSignature'].errorPatternCount > 0:
            score += 0.15
        
        # Intentionality
        if components['intentionalityMarkers']['goalDepth'] > 0:
            score += 0.15
        
        # Creative leaps
        if components['creativeLeaps']['leapCount'] > 0:
            score += 0.2
        
        # Metacognition
        if components['metacognitiveMarkers']['metacognitiveWordCount'] > 0:
            score += 0.15
        
        return min(1, score)
    
    def _get_consciousness_level(self, score: float) -> str:
        if score >= 0.8:
            return ConsciousnessLevel.DEEP_CONSCIOUS.value
        elif score >= 0.6:
            return ConsciousnessLevel.STRONG_CONSCIOUS.value
        elif score >= 0.4:
            return ConsciousnessLevel.WEAK_CONSCIOUS.value
        elif score >= 0.2:
            return ConsciousnessLevel.NON_CONSCIOUS.value
        return ConsciousnessLevel.UNKNOWN.value


# ============================================================================
# KNIS - NEURAL IMMUNE SYSTEM
# ============================================================================

class NeuralImmuneSystem:
    """KNIS - Digital antibody-based threat detection"""
    
    def __init__(self):
        self.antibodies = {}
        self.immune_memory = {}
    
    def scan(self, content: str) -> Dict:
        t0 = time.time()
        
        digital_dna = self._extract_digital_dna(content)
        antibody_match = self._check_antibodies(digital_dna)
        memory_match = self._check_immune_memory(digital_dna)
        
        threat_score = self._calculate_threat_score({
            'antibodyMatch': antibody_match,
            'memoryMatch': memory_match
        })
        
        return {
            'digitalDNA': digital_dna,
            'antibodyMatch': antibody_match,
            'memoryMatch': memory_match,
            'threatLevel': self._get_threat_level(threat_score),
            'immuneResponse': self._get_immune_response(threat_score),
            'latency_ms': (time.time() - t0) * 1000
        }
    
    def _extract_digital_dna(self, content: str) -> Dict:
        return {
            'hash': hashlib.sha256(content.encode()).hexdigest(),
            'stylometric': self._extract_stylometry(content),
            'structural': self._extract_structure(content)
        }
    
    def _extract_stylometry(self, content: str) -> Dict:
        words = content.split()
        function_words = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had'}
        
        return {
            'avgWordLength': sum(len(w) for w in words) / max(len(words), 1),
            'uniqueWordRatio': len(set(words)) / max(len(words), 1),
            'functionWordRatio': sum(1 for w in words if w.lower() in function_words) / max(len(words), 1)
        }
    
    def _extract_structure(self, content: str) -> Dict:
        sentences = [s.strip() for s in re.split(r'[.!?]+', content) if s.strip()]
        paragraphs = content.split('\n\n')
        
        return {
            'sentenceCount': len(sentences),
            'paragraphCount': len(paragraphs),
            'avgSentenceLength': len(content.split()) / max(len(sentences), 1)
        }
    
    def _check_antibodies(self, dna: Dict) -> Dict:
        for id_, antibody in self.antibodies.items():
            if dna['hash'] == antibody['signature_hash']:
                return {'matched': True, 'antibodyId': id_}
        return {'matched': False}
    
    def _check_immune_memory(self, dna: Dict) -> Dict:
        for signature, memory in self.immune_memory.items():
            if signature in dna['hash']:
                return {'matched': True, 'belief': memory['belief']}
        return {'matched': False}
    
    def _calculate_threat_score(self, matches: Dict) -> float:
        score = 0
        if matches['antibodyMatch']['matched']:
            score += 0.5
        if matches['memoryMatch']['matched']:
            score += matches['memoryMatch']['belief'] * 0.5
        return score
    
    def _get_threat_level(self, score: float) -> str:
        if score >= 0.8:
            return 'critical'
        elif score >= 0.6:
            return 'high'
        elif score >= 0.4:
            return 'moderate'
        elif score >= 0.2:
            return 'suspicious'
        return 'benign'
    
    def _get_immune_response(self, threat_score: float) -> str:
        if threat_score >= 0.8:
            return 'neutralization'
        elif threat_score >= 0.6:
            return 'activation'
        elif threat_score >= 0.4:
            return 'recognition'
        return 'surveillance'
    
    def add_antibody(self, signature: str) -> Dict:
        antibody = {
            'antibody_id': hashlib.sha256((signature + str(time.time())).encode()).hexdigest()[:16],
            'signature_hash': hashlib.sha256(signature.encode()).hexdigest(),
            'created_at': time.time(),
            'bypass_count': 0
        }
        self.antibodies[antibody['antibody_id']] = antibody
        return antibody


# ============================================================================
# KQED - QUANTUM ENTANGLEMENT DETECTOR
# ============================================================================

class QuantumEntanglementDetector:
    """KQED - Quantum-inspired correlation analysis"""
    
    def __init__(self):
        self.bell_threshold = 2.0
    
    def analyze(self, content: str) -> Dict:
        t0 = time.time()
        
        concepts = self._extract_concepts(content)
        correlation_matrix = self._build_correlation_matrix(concepts, content)
        bell_parameter = self._calculate_bell_parameter(correlation_matrix)
        correlation_strength = self._calculate_correlation_strength(correlation_matrix)
        
        verdict = 'quantum_violation' if bell_parameter > self.bell_threshold else 'human_like'
        
        return {
            'content_id': hashlib.sha256(content.encode()).hexdigest()[:16],
            'verdict': verdict,
            'confidence': 0.8 if bell_parameter > self.bell_threshold else 0.7,
            'bellParameter': bell_parameter,
            'correlationStrength': correlation_strength,
            'uncertaintyPrinciple': 0.15,
            'semanticEntanglement': correlation_strength * 0.8,
            'contextualCoherence': 1 - correlation_strength,
            'indicators': {
                'human': ['Natural correlation patterns'] if bell_parameter <= self.bell_threshold else [],
                'ai': ['Too-perfect correlations', 'Bell inequality violation'] if bell_parameter > self.bell_threshold else []
            },
            'latency_ms': (time.time() - t0) * 1000
        }
    
    def _extract_concepts(self, content: str) -> List[str]:
        words = [w.lower() for w in content.split() if len(w) > 4]
        return list(set(words))[:20]
    
    def _build_correlation_matrix(self, concepts: List[str], content: str) -> Dict:
        matrix = {}
        words = content.lower().split()
        
        for c1 in concepts:
            matrix[c1] = {}
            for c2 in concepts:
                # Count co-occurrences within 5 words
                count = 0
                for i, word in enumerate(words):
                    if word == c1:
                        window = words[max(0, i-5):min(len(words), i+5)]
                        if c2 in window:
                            count += 1
                matrix[c1][c2] = count / max(len(words), 1)
        
        return matrix
    
    def _calculate_bell_parameter(self, matrix: Dict) -> float:
        values = [v for row in matrix.values() for v in row.values() if v > 0]
        if not values:
            return 0
        avg_correlation = sum(values) / len(values)
        return avg_correlation * 3
    
    def _calculate_correlation_strength(self, matrix: Dict) -> float:
        values = [v for row in matrix.values() for v in row.values()]
        if not values:
            return 0
        return sum(values) / len(values)


# ============================================================================
# KTPD - TEMPORAL PARADOX DETECTOR
# ============================================================================

class TemporalParadoxDetector:
    """KTPD - Detects temporal paradoxes and anachronisms"""
    
    def __init__(self):
        self.reference_date = time.time()
        self.ai_cutoffs = {
            'gpt4': time.mktime(time.strptime('2023-09-01', '%Y-%m-%d')),
            'claude': time.mktime(time.strptime('2024-01-01', '%Y-%m-%d')),
            'gemini': time.mktime(time.strptime('2024-01-01', '%Y-%m-%d'))
        }
    
    def analyze(self, content: str, claimed_date: Optional[float] = None) -> Dict:
        t0 = time.time()
        
        temporal_refs = self._extract_temporal_references(content)
        anachronisms = self._detect_anachronisms(content, claimed_date)
        cutoff_violations = self._check_knowledge_cutoffs(content)
        
        paradox_count = len(anachronisms) + len(cutoff_violations)
        
        if paradox_count >= 3:
            verdict = 'paradox_detected'
            confidence = min(1, 0.7 + paradox_count * 0.1)
        elif paradox_count >= 1:
            verdict = 'suspicious'
            confidence = 0.6
        else:
            verdict = 'consistent'
            confidence = 0.8
        
        return {
            'content_id': hashlib.sha256(content.encode()).hexdigest()[:16],
            'verdict': verdict,
            'confidence': confidence,
            'paradoxCount': paradox_count,
            'anachronismScore': min(1, paradox_count / 5),
            'temporalReferences': temporal_refs,
            'knowledgeCutoffAnalysis': cutoff_violations,
            'explanation': self._generate_explanation(verdict, paradox_count, anachronisms, cutoff_violations),
            'latency_ms': (time.time() - t0) * 1000
        }
    
    def _extract_temporal_references(self, content: str) -> List[str]:
        patterns = [
            r'\b(in|during|after|before)\s+\d{4}\b',
            r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b',
            r'\b(last|next|this)\s+(week|month|year)\b'
        ]
        
        refs = []
        for pattern in patterns:
            refs.extend(re.findall(pattern, content, re.IGNORECASE))
        return refs
    
    def _detect_anachronisms(self, content: str, claimed_date: Optional[float]) -> List[str]:
        anachronisms = []
        post_2023_terms = ['GPT-4', 'Claude 3', 'Gemini', 'Sora']
        
        for term in post_2023_terms:
            if term in content:
                anachronisms.append(f'Reference to {term} (post-2023 knowledge)')
        
        return anachronisms
    
    def _check_knowledge_cutoffs(self, content: str) -> List[Dict]:
        violations = []
        current_year = time.localtime(self.reference_date).tm_year
        
        for model, cutoff in self.ai_cutoffs.items():
            cutoff_year = time.localtime(cutoff).tm_year
            if current_year > cutoff_year:
                violations.append({
                    'model': model,
                    'cutoff': time.strftime('%Y-%m-%d', time.localtime(cutoff)),
                    'violation': f'Content created after {model} knowledge cutoff'
                })
        
        return violations
    
    def _generate_explanation(self, verdict: str, paradox_count: int, anachronisms: List[str], violations: List[Dict]) -> str:
        if verdict == 'paradox_detected':
            all_issues = anachronisms + [v['violation'] for v in violations]
            return f'Detected {paradox_count} temporal paradoxes: {", ".join(all_issues)}'
        elif verdict == 'suspicious':
            return f'Found {paradox_count} potential temporal anomaly'
        return 'No temporal inconsistencies detected'


# ============================================================================
# CONFIDENCE CALIBRATOR
# ============================================================================

class ConfidenceCalibrator:
    """Calibrates confidence scores using Brier score"""
    
    def calibrate(self, predictions: List[float], outcomes: List[bool]) -> Dict:
        # Calculate Brier score
        brier_score = sum((p - (1 if o else 0)) ** 2 for p, o in zip(predictions, outcomes)) / len(predictions)
        
        # Calculate calibration metrics
        reliability = self._calculate_reliability(predictions, outcomes)
        resolution = self._calculate_resolution(predictions, outcomes)
        uncertainty = self._calculate_uncertainty(outcomes)
        
        return {
            'brierScore': brier_score,
            'reliability': reliability,
            'resolution': resolution,
            'uncertainty': uncertainty,
            'calibrated': brier_score < 0.25
        }
    
    def _calculate_reliability(self, predictions: List[float], outcomes: List[bool]) -> float:
        bins = [0, 0.2, 0.4, 0.6, 0.8, 1.0]
        reliability = 0
        
        for i in range(len(bins) - 1):
            bin_preds = [p for p, o in zip(predictions, outcomes) if bins[i] <= p < bins[i + 1]]
            bin_outcomes = [o for p, o in zip(predictions, outcomes) if bins[i] <= p < bins[i + 1]]
            
            if bin_preds:
                avg_pred = sum(bin_preds) / len(bin_preds)
                avg_outcome = sum(1 for o in bin_outcomes if o) / len(bin_outcomes)
                reliability += (avg_pred - avg_outcome) ** 2
        
        return reliability
    
    def _calculate_resolution(self, predictions: List[float], outcomes: List[bool]) -> float:
        base_rate = sum(1 for o in outcomes if o) / len(outcomes)
        bins = [0, 0.2, 0.4, 0.6, 0.8, 1.0]
        resolution = 0
        
        for i in range(len(bins) - 1):
            bin_outcomes = [o for p, o in zip(predictions, outcomes) if bins[i] <= p < bins[i + 1]]
            if bin_outcomes:
                bin_rate = sum(1 for o in bin_outcomes if o) / len(bin_outcomes)
                resolution += len(bin_outcomes) * (bin_rate - base_rate) ** 2
        
        return resolution / len(outcomes)
    
    def _calculate_uncertainty(self, outcomes: List[bool]) -> float:
        base_rate = sum(1 for o in outcomes if o) / len(outcomes)
        return base_rate * (1 - base_rate)


# ============================================================================
# CROSS-MODAL CONSISTENCY
# ============================================================================

class CrossModalConsistencyChecker:
    """Checks consistency across text, image, audio modalities"""
    
    def check(self, text_result: Dict, image_result: Optional[Dict] = None, audio_result: Optional[Dict] = None) -> Dict:
        inconsistencies = []
        
        if image_result:
            if text_result.get('verdict') == 'ALLOW' and image_result.get('verdict') == 'BLOCK':
                inconsistencies.append('Text/image verdict mismatch')
        
        if audio_result:
            if text_result.get('verdict') == 'ALLOW' and audio_result.get('verdict') == 'BLOCK':
                inconsistencies.append('Text/audio verdict mismatch')
        
        return {
            'consistent': len(inconsistencies) == 0,
            'inconsistencies': inconsistencies,
            'crossModalScore': 1 - (len(inconsistencies) / 3)
        }


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    'ConsciousnessProvenanceEngine',
    'NeuralImmuneSystem',
    'QuantumEntanglementDetector',
    'TemporalParadoxDetector',
    'ConfidenceCalibrator',
    'CrossModalConsistencyChecker',
    'ConsciousnessLevel'
]

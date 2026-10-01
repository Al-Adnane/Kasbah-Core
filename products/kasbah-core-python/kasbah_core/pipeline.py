"""
Kasbah Pipeline v3.0 - Complete Detection Engine

Integrates all novel features:
- 13 Moats
- Spatial Intelligence
- Authority Protocol
- Core Detection
- E3 Telemetry
"""

import time
from typing import Dict, Any, Optional

from .moats import (
    CAILLedger,
    DynamicThresholds,
    BrittlenessMonitor,
    PredictiveForecaster,
    TOCTOUPrevention,
    ResourceMonitor,
    AdversarialDetector,
    QIFTDecoder
)
from .spatial import SpatialIntelligence
from .authority import AuthorityProtocol
from .telemetry import record_telemetry, get_telemetry


class KasbahPipeline:
    """Complete Kasbah detection pipeline with all novel features"""
    
    def __init__(self, options: Dict = None):
        self.options = options or {}
        self.cail = CAILLedger()
        self.thresholds = DynamicThresholds()
        self.brittleness = BrittlenessMonitor()
        self.forecaster = PredictiveForecaster()
        self.toctou = TOCTOUPrevention()
        self.resource_monitor = ResourceMonitor()
        self.adversarial = AdversarialDetector()
        self.qift = QIFTDecoder()
        self.spatial = SpatialIntelligence()
        self.authority = AuthorityProtocol()
        
        # Secret patterns (abbreviated)
        self.secret_patterns = [
            {'name': 'AWS Access Key', 'regex': r'AKIA[0-9A-Z]{16}', 'risk': 90},
            {'name': 'GitHub PAT', 'regex': r'gh[pousr]_[A-Za-z0-9]{36,}', 'risk': 95},
            {'name': 'Stripe Secret', 'regex': r'sk_live_[0-9a-zA-Z]{24,}', 'risk': 95},
            {'name': 'Private Key', 'regex': r'-----BEGIN .*PRIVATE KEY-----', 'risk': 100},
        ]
        
        self.resource_monitor.set_baseline()
    
    def detect_secrets(self, text: str) -> Dict:
        """Detect secrets in text"""
        start = time.time()
        matches = []
        
        import re
        for pattern in self.secret_patterns:
            found = re.search(pattern['regex'], text)
            if found:
                matches.append({
                    'name': pattern['name'],
                    'risk': pattern['risk'],
                    'match': found.group()[:8] + '...'
                })
        
        latency = (time.time() - start) * 1000
        result = {
            'secrets': matches,
            'risk_score': sum(m['risk'] for m in matches),
            'count': len(matches),
            'latency_ms': latency
        }
        
        record_telemetry('secret', latency)
        self.cail.add_entry('DETECT', 'secrets', 'BLOCKED' if matches else 'ALLOW')
        
        if matches:
            self.thresholds.record_threat_event('secret_leak', result['risk_score'])
            self.forecaster.record_threat('credential_exposure', 'secret_detection', result['risk_score'])
        
        return result
    
    def detect(self, input: Dict) -> Dict:
        """Run complete detection pipeline"""
        start = time.time()
        
        # TOCTOU stamp
        import hashlib
        input_hash = self.toctou.stamp(str(input))
        
        result = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'input': {
                'has_text': bool(input.get('text')),
                'has_code': bool(input.get('code')),
                'has_image': bool(input.get('image'))
            },
            'secrets': None,
            'obfuscation': None,
            'adversarial': None,
            'spatial': None,
            'overall_risk': 0,
            'decision': 'ALLOW',
            'latency_ms': 0,
            'moats': {}
        }
        
        # Secret detection
        if input.get('text'):
            result['secrets'] = self.detect_secrets(input['text'])
            result['overall_risk'] += result['secrets']['risk_score']
            
            # Obfuscation
            result['obfuscation'] = self.qift.detect_obfuscation(input['text'])
            if result['obfuscation']['is_obfuscated']:
                result['overall_risk'] += 30
            
            # Adversarial
            result['adversarial'] = self.adversarial.detect(input['text'])
            if result['adversarial']['detected']:
                result['overall_risk'] += result['adversarial']['risk_score']
        
        # Spatial analysis
        if input.get('image') and input.get('image_features'):
            result['spatial'] = self.spatial.analyze(input['image_features'])
            if not result['spatial']['is_spatially_consistent']:
                result['overall_risk'] += (1 - result['spatial']['confidence']) * 50
        
        # CAIL audit
        self.cail.add_entry(
            'DETECT', 'unified',
            'BLOCK' if result['overall_risk'] >= 70 else 'ALLOW',
            {'risk_score': result['overall_risk']}
        )
        
        # TOCTOU verification
        if not self.toctou.verify(input_hash, str(input)):
            result['moats']['toctou_violation'] = True
            result['overall_risk'] = 100
        
        # Resource check
        resource_check = self.resource_monitor.check_anomaly()
        if resource_check['memory_anomaly'] or resource_check['cpu_anomaly']:
            result['moats']['resource_anomaly'] = resource_check
            result['overall_risk'] += 20
        
        # Dynamic thresholds
        result['moats']['dynamic_threshold'] = self.thresholds.get_threat_level()
        result['moats']['threshold_applied'] = self.thresholds.get_threshold()
        
        # Cap risk
        result['overall_risk'] = min(100, result['overall_risk'])
        
        # Decision
        if result['overall_risk'] >= 70:
            result['decision'] = 'BLOCK'
        elif result['overall_risk'] >= 40:
            result['decision'] = 'WARN'
        elif result['overall_risk'] >= 10:
            result['decision'] = 'LOG'
        
        result['latency_ms'] = (time.time() - start) * 1000
        return result
    
    def get_system_status(self) -> Dict:
        """Get complete system status"""
        return {
            'threat_level': self.thresholds.get_threat_level(),
            'threshold_config': self.thresholds.get_config(),
            'system_brittleness': self.brittleness.get_system_brittleness(),
            'resource_anomaly': self.resource_monitor.check_anomaly(),
            'forecast': self.forecaster.generate_forecast(),
            'ledger_integrity': self.cail.verify_integrity(),
            'authority_chain': self.authority.verify_chain(),
            'telemetry': get_telemetry()
        }


__all__ = ['KasbahPipeline']

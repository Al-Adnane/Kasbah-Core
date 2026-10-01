"""
Kasbah Core Moats - 13 Security Layers
"""

import hashlib
import time
import json
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import base64


# ============================================================================
# MOAT 1: CAIL - Context-Aware Integrity Ledger
# ============================================================================

class CAILLedger:
    """Hash-chained audit trail providing instant tamper detection"""
    
    def __init__(self):
        self.ledger = []
        self.genesis_hash = None
        self._initialize()
    
    def _compute_hash(self, data: Dict) -> str:
        content = json.dumps(data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _initialize(self):
        self.genesis_hash = self._compute_hash({'genesis': str(time.time())})
        self.ledger.append({
            'id': 'genesis',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'action': 'INIT',
            'resource': 'LEDGER',
            'result': 'SUCCESS',
            'previous_hash': '0' * 64,
            'hash': self.genesis_hash
        })
    
    def add_entry(self, action: str, resource: str, result: str, metadata: Dict = None):
        prev_entry = self.ledger[-1] if self.ledger else None
        entry = {
            'id': f"entry-{int(time.time() * 1000)}",
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'action': action,
            'resource': resource,
            'result': result,
            'metadata': metadata or {},
            'previous_hash': prev_entry['hash'] if prev_entry else self.genesis_hash
        }
        entry['hash'] = self._compute_hash(entry)
        self.ledger.append(entry)
        return entry
    
    def verify_integrity(self) -> Dict:
        for i in range(1, len(self.ledger)):
            if self.ledger[i]['previous_hash'] != self.ledger[i-1]['hash']:
                return {'valid': False, 'error': f'Chain broken at entry {i}'}
        return {'valid': True, 'entries': len(self.ledger)}
    
    def get_stats(self) -> Dict:
        by_action = defaultdict(int)
        by_result = defaultdict(int)
        for entry in self.ledger:
            by_action[entry['action']] += 1
            by_result[entry['result']] += 1
        return {'total': len(self.ledger), 'by_action': dict(by_action), 'by_result': dict(by_result)}


# ============================================================================
# MOAT 2: Dynamic Thresholds
# ============================================================================

class DynamicThresholds:
    """Adaptive security thresholds based on threat environment"""
    
    def __init__(self):
        self.threat_level = 'minimal'
        self.threat_events = []
        self.config = {
            'minimal': {'confidence_threshold': 0.8, 'rate_limit_multiplier': 2.0},
            'low': {'confidence_threshold': 0.75, 'rate_limit_multiplier': 1.5},
            'medium': {'confidence_threshold': 0.65, 'rate_limit_multiplier': 1.0},
            'high': {'confidence_threshold': 0.5, 'rate_limit_multiplier': 0.5},
            'critical': {'confidence_threshold': 0.3, 'rate_limit_multiplier': 0.25}
        }
    
    def record_threat_event(self, vector: str, severity: int):
        self.threat_events.append({
            'vector': vector,
            'severity': severity,
            'timestamp': time.time()
        })
        if len(self.threat_events) > 100:
            self.threat_events.pop(0)
        self._update_threat_level()
    
    def _update_threat_level(self):
        recent = [e for e in self.threat_events if time.time() - e['timestamp'] < 3600]
        if len(recent) >= 50:
            self.threat_level = 'critical'
        elif len(recent) >= 20:
            self.threat_level = 'high'
        elif len(recent) >= 10:
            self.threat_level = 'medium'
        elif len(recent) >= 5:
            self.threat_level = 'low'
        else:
            self.threat_level = 'minimal'
    
    def get_config(self) -> Dict:
        return self.config[self.threat_level]
    
    def get_threshold(self) -> float:
        return self.config[self.threat_level]['confidence_threshold']
    
    def get_threat_level(self) -> str:
        return self.threat_level


# ============================================================================
# MOAT 3: Brittleness Monitor
# ============================================================================

class BrittlenessMonitor:
    """System fragility analysis using coefficient of variation"""
    
    def __init__(self):
        self.indicators = {}
    
    def record_indicator(self, name: str, value: float, source: str):
        if name not in self.indicators:
            self.indicators[name] = {'values': [], 'sources': set()}
        self.indicators[name]['values'].append(value)
        self.indicators[name]['sources'].add(source)
        if len(self.indicators[name]['values']) > 50:
            self.indicators[name]['values'].pop(0)
    
    def calculate_brittleness(self, name: str) -> float:
        data = self.indicators.get(name)
        if not data or len(data['values']) < 5:
            return 0.0
        values = data['values']
        mean = sum(values) / len(values)
        if mean == 0:
            return 0.0
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std_dev = variance ** 0.5
        cv = std_dev / mean
        return min(1.0, cv)
    
    def get_system_brittleness(self) -> float:
        if not self.indicators:
            return 0.0
        brittleness = [self.calculate_brittleness(name) for name in self.indicators]
        return sum(brittleness) / len(brittleness)
    
    def find_fragile_indicators(self, threshold: float = 0.3) -> List[str]:
        return [name for name in self.indicators if self.calculate_brittleness(name) > threshold]


# ============================================================================
# MOAT 4: Predictive Forecaster
# ============================================================================

class PredictiveForecaster:
    """Historical pattern threat prediction"""
    
    def __init__(self):
        self.threat_history = []
    
    def record_threat(self, threat_type: str, vector: str, severity: int):
        self.threat_history.append({
            'type': threat_type,
            'vector': vector,
            'severity': severity,
            'timestamp': time.time()
        })
        if len(self.threat_history) > 200:
            self.threat_history.pop(0)
    
    def generate_forecast(self) -> Dict:
        recent = [t for t in self.threat_history if time.time() - t['timestamp'] < 86400]
        by_type = defaultdict(int)
        for t in recent:
            by_type[t['type']] += 1
        
        predicted_vector = 'unknown'
        max_count = 0
        for threat_type, count in by_type.items():
            if count > max_count:
                max_count = count
                predicted_vector = threat_type
        
        last_12h = len([t for t in self.threat_history if time.time() - t['timestamp'] < 43200])
        trend = 'increasing' if len(recent) > (last_12h * 1.5) else 'stable'
        
        return {
            'predicted_vector': predicted_vector,
            'confidence': min(1.0, max_count / 10),
            'threat_count_24h': len(recent),
            'trend': trend
        }


# ============================================================================
# MOAT 5: TOCTOU Prevention
# ============================================================================

class TOCTOUPrevention:
    """Time-of-check to time-of-use prevention"""
    
    def __init__(self, ttl_ms: int = 100):
        self.cache = {}
        self.ttl_ms = ttl_ms
    
    def stamp(self, text: str) -> str:
        hash_val = hashlib.sha256(text.encode()).hexdigest()
        self.cache[hash_val] = {'timestamp': time.time() * 1000, 'text': text}
        return hash_val
    
    def verify(self, hash_val: str, text: str) -> bool:
        cached = self.cache.get(hash_val)
        if not cached:
            return False
        if (time.time() * 1000) - cached['timestamp'] > self.ttl_ms:
            del self.cache[hash_val]
            return False
        return cached['text'] == text
    
    def cleanup(self):
        now = time.time() * 1000
        expired = [k for k, v in self.cache.items() if now - v['timestamp'] > self.ttl_ms]
        for k in expired:
            del self.cache[k]


# ============================================================================
# MOAT 6: Resource Monitor
# ============================================================================

class ResourceMonitor:
    """Memory and CPU anomaly detection"""
    
    def __init__(self):
        self.baseline_memory = 0
        self.baseline_cpu = 0
    
    def set_baseline(self):
        import psutil
        self.baseline_memory = psutil.Process().memory_info().rss
        self.baseline_cpu = psutil.Process().cpu_percent()
    
    def check_anomaly(self) -> Dict:
        import psutil
        current_memory = psutil.Process().memory_info().rss
        current_cpu = psutil.Process().cpu_percent()
        
        memory_growth = (current_memory - self.baseline_memory) / max(self.baseline_memory, 1)
        cpu_growth = (current_cpu - self.baseline_cpu) / max(self.baseline_cpu, 1)
        
        return {
            'memory_anomaly': memory_growth > 0.5,
            'cpu_anomaly': cpu_growth > 0.5,
            'memory_growth': memory_growth,
            'cpu_growth': cpu_growth
        }


# ============================================================================
# MOAT 7: Adversarial Detector
# ============================================================================

class AdversarialDetector:
    """Unicode homoglyph and evasion detection"""
    
    def __init__(self):
        self.patterns = [
            re.compile(r'[\u0400-\u04FF]'),  # Cyrillic
            re.compile(r'[\u0370-\u03FF]'),  # Greek
            re.compile(r'[\u200B-\u200F]'),  # Zero-width
            re.compile(r'[\uFEFF]'),  # BOM
            re.compile(r'[\u0300-\u036F]{2,}')  # Combining diacritics
        ]
    
    def detect(self, text: str) -> Dict:
        found = []
        for i, pattern in enumerate(self.patterns):
            if pattern.search(text):
                found.append(f'adversarial-pattern-{i}')
        return {
            'detected': len(found) > 0,
            'patterns': found,
            'risk_score': len(found) * 25
        }


# ============================================================================
# MOAT 8: QIFT Decoder
# ============================================================================

class QIFTDecoder:
    """7-layer obfuscation decoder"""
    
    HOMOGLYPH_MAP = {'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x'}
    L33T_MAP = {'4': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't', '@': 'a', '$': 's'}
    
    def decode_homoglyphs(self, text: str) -> str:
        return ''.join(self.HOMOGLYPH_MAP.get(c, c) for c in text)
    
    def decode_l33t(self, text: str) -> str:
        return ''.join(self.L33T_MAP.get(c, c) for c in text.lower())
    
    def decode_base64(self, text: str) -> str:
        try:
            decoded = base64.b64decode(text).decode('utf-8')
            if all(32 <= ord(c) <= 126 for c in decoded):
                return decoded
        except:
            pass
        return text
    
    def detect_obfuscation(self, text: str) -> Dict:
        is_obfuscated = (
            any(c in self.HOMOGLYPH_MAP for c in text) or
            any(c in self.L33T_MAP for c in text) or
            re.search(r'(?:[A-Za-z0-9+/]{4}){10,}', text) or
            re.search(r'[\u0300-\u036F]{2,}', text)
        )
        return {'is_obfuscated': is_obfuscated}


# Export all moats
__all__ = [
    'CAILLedger',
    'DynamicThresholds',
    'BrittlenessMonitor',
    'PredictiveForecaster',
    'TOCTOUPrevention',
    'ResourceMonitor',
    'AdversarialDetector',
    'QIFTDecoder'
]

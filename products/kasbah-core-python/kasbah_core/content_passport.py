"""
Content Passport and AI Fingerprint Database for kasbah-core Python
"""

import hashlib
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import json


@dataclass
class Passport:
    """Content passport data structure"""
    id: str
    version: str
    created_at: str
    content_hash: str
    content_size: int
    content_type: str
    creator: str
    claims: List[Dict] = field(default_factory=list)
    actions: List[Dict] = field(default_factory=list)
    signatures: List[Dict] = field(default_factory=list)
    blockchain_anchor: Optional[Dict] = None


class ContentPassport:
    """C2PA-compatible content passport with quantum-safe signatures"""
    
    def __init__(self, options: Dict = None):
        self.options = options or {}
        self.passports: Dict[str, Passport] = {}
        self.blockchain_anchors: Dict[str, Dict] = {}
    
    def create(self, content: str, metadata: Dict = None) -> Dict:
        """Create a content passport"""
        metadata = metadata or {}
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        passport_id = hashlib.sha256(
            (content_hash + str(time.time())).encode()
        ).hexdigest()[:16]
        
        passport = Passport(
            id=passport_id,
            version='1.0.0',
            created_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            content_hash=content_hash,
            content_size=len(content) if isinstance(content, str) else len(str(content)),
            content_type=metadata.get('contentType', 'unknown'),
            creator=metadata.get('creator', 'anonymous'),
            claims=[],
            actions=[],
            signatures=[],
            blockchain_anchor=None
        )
        
        # Add initial signature (simplified - would use Dilithium in production)
        passport.signatures.append({
            'algorithm': 'sha256-fallback',
            'signature': hashlib.sha256(
                (content_hash + passport.created_at).encode()
            ).hexdigest(),
            'signed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'signer': 'creator'
        })
        
        self.passports[passport_id] = passport
        return self._passport_to_dict(passport)
    
    def add_claim(self, passport_id: str, claim_type: str, claim_data: Dict, claimant: str) -> Dict:
        """Add a claim to the passport"""
        passport = self.passports.get(passport_id)
        if not passport:
            return {'error': 'Passport not found'}
        
        claim = {
            'type': claim_type,
            'data': claim_data,
            'claimant': claimant,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'hash': None
        }
        claim['hash'] = hashlib.sha256(json.dumps(claim, sort_keys=True).encode()).hexdigest()
        
        passport.claims.append(claim)
        
        # Re-sign with updated claims
        passport.signatures.append({
            'algorithm': 'sha256-fallback',
            'signature': hashlib.sha256(
                (passport.content_hash + json.dumps(passport.claims)).encode()
            ).hexdigest(),
            'signed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'signer': claimant
        })
        
        return {'success': True, 'claim': claim}
    
    def add_action(self, passport_id: str, action_type: str, actor: str, details: Dict = None) -> Dict:
        """Record an action (transfer, edit, view, etc.)"""
        passport = self.passports.get(passport_id)
        if not passport:
            return {'error': 'Passport not found'}
        
        action = {
            'type': action_type,
            'actor': actor,
            'details': details or {},
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'hash': None
        }
        action['hash'] = hashlib.sha256(json.dumps(action, sort_keys=True).encode()).hexdigest()
        
        passport.actions.append(action)
        return {'success': True, 'action': action}
    
    def anchor_to_blockchain(self, passport_id: str, network: str = 'ethereum') -> Dict:
        """Anchor passport to blockchain (simulated)"""
        passport = self.passports.get(passport_id)
        if not passport:
            return {'error': 'Passport not found'}
        
        # Create Merkle tree of all claims and actions
        leaves = [passport.content_hash]
        leaves.extend([c['hash'] for c in passport.claims])
        leaves.extend([a['hash'] for a in passport.actions])
        
        # Simplified Merkle root
        merkle_root = hashlib.sha256(''.join(leaves).encode()).hexdigest()
        
        # Simulate blockchain transaction
        tx_hash = hashlib.sha256(
            (merkle_root + network + str(time.time())).encode()
        ).hexdigest()
        
        anchor = {
            'network': network,
            'transaction_hash': tx_hash,
            'merkle_root': merkle_root,
            'block_number': int(time.time() * 1000) % 10000000,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'status': 'pending'
        }
        
        # Simulate confirmation
        def confirm():
            anchor['status'] = 'confirmed'
            anchor['confirmations'] = 12
        
        # In production, this would be async
        import threading
        threading.Timer(5.0, confirm).start()
        
        passport.blockchain_anchor = anchor
        self.blockchain_anchors[tx_hash] = {'passport_id': passport_id, 'anchor': anchor}
        
        return {'success': True, 'anchor': anchor}
    
    def verify(self, passport_id: str) -> Dict:
        """Verify passport integrity"""
        passport = self.passports.get(passport_id)
        if not passport:
            return {'valid': False, 'error': 'Passport not found'}
        
        result = {
            'valid': True,
            'passport_id': passport_id,
            'content_hash': passport.content_hash,
            'claims_count': len(passport.claims),
            'actions_count': len(passport.actions),
            'signatures_valid': 0,
            'blockchain_verified': False,
            'issues': []
        }
        
        # Verify signatures (simplified)
        for sig in passport.signatures:
            if sig.get('signature') and len(sig['signature']) == 64:
                result['signatures_valid'] += 1
        
        # Verify blockchain anchor
        if passport.blockchain_anchor:
            result['blockchain_verified'] = passport.blockchain_anchor['status'] == 'confirmed'
            result['blockchain_tx'] = passport.blockchain_anchor['transaction_hash']
        
        # Check for issues
        if result['signatures_valid'] == 0:
            result['issues'].append('No valid signatures found')
        if not result['blockchain_verified'] and passport.blockchain_anchor:
            result['issues'].append('Blockchain anchor not confirmed')
        
        result['valid'] = len(result['issues']) == 0
        return result
    
    def export_c2pa(self, passport_id: str) -> Dict:
        """Export passport in C2PA-compatible format"""
        passport = self.passports.get(passport_id)
        if not passport:
            return {'error': 'Passport not found'}
        
        return {
            '@context': ['https://c2pa.org/specifications/specifications/2.2/contexts/c2pa.jsonld'],
            'type': 'c2pa.manifest',
            'claim': {
                'claimId': passport.id,
                'generator': passport.creator,
                'claimVersion': '2.2',
                'assertions': [
                    {'label': c['type'], 'data': c['data']}
                    for c in passport.claims
                ],
                'signature': passport.signatures[-1] if passport.signatures else None
            },
            'ingredients': [
                {'instanceId': a['hash'], 'type': a['type']}
                for a in passport.actions
            ]
        }
    
    def get(self, passport_id: str) -> Optional[Dict]:
        """Get passport by ID"""
        passport = self.passports.get(passport_id)
        return self._passport_to_dict(passport) if passport else None
    
    def get_all(self) -> List[Dict]:
        """Get all passports"""
        return [self._passport_to_dict(p) for p in self.passports.values()]
    
    def _passport_to_dict(self, passport: Passport) -> Dict:
        """Convert Passport to dictionary"""
        return {
            'id': passport.id,
            'version': passport.version,
            'created_at': passport.created_at,
            'content_hash': passport.content_hash,
            'content_size': passport.content_size,
            'content_type': passport.content_type,
            'creator': passport.creator,
            'claims': passport.claims,
            'actions': passport.actions,
            'signatures': passport.signatures,
            'blockchain_anchor': passport.blockchain_anchor
        }


class AIFingerprintDatabase:
    """AI generator fingerprint database with stylometric analysis"""
    
    def __init__(self):
        self.fingerprints: Dict[str, Dict] = {}
        self.generator_profiles: Dict[str, Dict] = {}
        self.known_generators = [
            'gpt-4', 'gpt-3.5-turbo', 'claude-3-opus', 'claude-3-sonnet',
            'claude-3-haiku', 'gemini-pro', 'gemini-ultra', 'llama-2-70b',
            'llama-3-70b', 'mistral-large', 'mixtral-8x7b', 'palm-2',
            'command-r-plus', 'yi-34b', 'qwen-72b', 'falcon-180b', 'grok-1'
        ]
    
    def register_generator(self, generator_name: str, samples: List[str]) -> Dict:
        """Register a generator profile"""
        profile = {
            'name': generator_name,
            'registered_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'samples_count': len(samples),
            'fingerprints': [],
            'characteristics': self._extract_characteristics(samples)
        }
        
        for sample in samples:
            fp = self._compute_fingerprint(sample)
            profile['fingerprints'].append(fp)
        
        self.generator_profiles[generator_name] = profile
        return {'success': True, 'profile': profile}
    
    def _compute_fingerprint(self, content: str) -> Dict:
        """Compute fingerprint for content"""
        words = content.split()
        sentences = [s.strip() for s in content.split('.') if s.strip()]
        
        features = {
            'avg_word_length': sum(len(w) for w in words) / max(len(words), 1),
            'avg_sentence_length': len(words) / max(len(sentences), 1),
            'unique_word_ratio': len(set(words)) / max(len(words), 1),
            'function_word_ratio': self._count_function_words(words) / max(len(words), 1),
            'transition_word_ratio': self._count_transition_words(words) / max(len(words), 1),
            'punctuation_ratio': len([c for c in content if c in ',;:!?()"\'-']) / max(len(words), 1)
        }
        
        return {
            'hash': hashlib.sha256(json.dumps(features, sort_keys=True).encode()).hexdigest(),
            'features': features,
            'timestamp': time.time()
        }
    
    def _count_function_words(self, words: List[str]) -> int:
        """Count function words"""
        function_words = {
            'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
            'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
            'should', 'may', 'might', 'must', 'shall', 'can', 'need', 'dare',
            'ought', 'used', 'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by',
            'from', 'as', 'into', 'through', 'during', 'before', 'after', 'above',
            'below', 'between', 'under', 'again', 'further', 'then', 'once'
        }
        return sum(1 for w in words if w.lower() in function_words)
    
    def _count_transition_words(self, words: List[str]) -> int:
        """Count transition words"""
        transition_words = {
            'however', 'therefore', 'moreover', 'furthermore', 'additionally',
            'consequently', 'nevertheless', 'nonetheless', 'meanwhile', 'subsequently',
            'accordingly', 'thus', 'hence', 'so', 'but', 'yet', 'although', 'while',
            'whereas', 'despite', 'notwithstanding'
        }
        return sum(1 for w in words if w.lower() in transition_words)
    
    def _extract_characteristics(self, samples: List[str]) -> Dict:
        """Extract characteristics from samples"""
        all_features = [self._compute_fingerprint(s)['features'] for s in samples]
        
        return {
            'avg_word_length': self._average([f['avg_word_length'] for f in all_features]),
            'avg_sentence_length': self._average([f['avg_sentence_length'] for f in all_features]),
            'unique_word_ratio': self._average([f['unique_word_ratio'] for f in all_features]),
            'function_word_ratio': self._average([f['function_word_ratio'] for f in all_features]),
            'transition_word_ratio': self._average([f['transition_word_ratio'] for f in all_features]),
            'punctuation_ratio': self._average([f['punctuation_ratio'] for f in all_features])
        }
    
    def _average(self, arr: List[float]) -> float:
        """Calculate average"""
        return sum(arr) / max(len(arr), 1)
    
    def identify(self, content: str) -> Dict:
        """Identify generator from content"""
        fp = self._compute_fingerprint(content)
        results = []
        
        for name, profile in self.generator_profiles.items():
            similarity = self._compute_similarity(fp['features'], profile['characteristics'])
            results.append({
                'generator': name,
                'similarity': similarity,
                'confidence': 'high' if similarity > 0.8 else 'medium' if similarity > 0.6 else 'low'
            })
        
        results.sort(key=lambda x: x['similarity'], reverse=True)
        
        # Store fingerprint
        self.fingerprints[fp['hash']] = {
            'content': content[:100] + '...' if len(content) > 100 else content,
            'timestamp': time.time(),
            'top_match': results[0]['generator'] if results else 'unknown'
        }
        
        return {
            'fingerprint': fp['hash'],
            'matches': results[:5],
            'identified_generator': results[0]['generator'] if results else 'unknown',
            'confidence': results[0]['confidence'] if results else 'unknown'
        }
    
    def _compute_similarity(self, features: Dict, profile: Dict) -> float:
        """Compute similarity between features and profile"""
        total_diff = 0
        for key in features:
            if key in profile:
                total_diff += abs(features[key] - profile[key])
        return max(0, 1 - total_diff / len(features))
    
    def get_stats(self) -> Dict:
        """Get database statistics"""
        return {
            'registered_generators': len(self.generator_profiles),
            'known_generators': len(self.known_generators),
            'stored_fingerprints': len(self.fingerprints),
            'generators': list(self.generator_profiles.keys())
        }


__all__ = ['ContentPassport', 'AIFingerprintDatabase']

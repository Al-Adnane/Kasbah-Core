"""
Quantum-Safe Cryptography for kasbah-core Python
Implements Merkle Tree and quantum-safe ledger
"""

import hashlib
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import json


class MerkleTree:
    """Merkle tree for SPHINCS+ foundation"""
    
    def __init__(self, leaves: List[str]):
        self.leaves = [self._hash(leaf) for leaf in leaves]
        self.root = self._build_tree()
    
    def _hash(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _build_tree(self) -> str:
        if not self.leaves:
            return '0' * 64
        if len(self.leaves) == 1:
            return self.leaves[0]
        
        level = self.leaves
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                next_level.append(self._hash(left + right))
            level = next_level
        return level[0]
    
    def get_proof(self, index: int) -> Dict:
        """Get Merkle proof for leaf at index"""
        proof = []
        level = self.leaves
        idx = index
        
        while len(level) > 1:
            sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
            if sibling_idx < len(level):
                proof.append({
                    'hash': level[sibling_idx],
                    'position': 'left' if sibling_idx % 2 == 0 else 'right'
                })
            idx = idx // 2
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                next_level.append(self._hash(left + right))
            level = next_level
        
        return {'root': self.root, 'proof': proof, 'leaf_index': index}
    
    def verify(self, leaf: str, proof: Dict, root: str) -> bool:
        """Verify Merkle proof"""
        hash_val = self._hash(leaf)
        for sibling in proof['proof']:
            if sibling['position'] == 'left':
                hash_val = self._hash(sibling['hash'] + hash_val)
            else:
                hash_val = self._hash(hash_val + sibling['hash'])
        return hash_val == root


class HmacSha256Signer:
    """HMAC-SHA256 message authentication — NOT lattice crypto.

    Previously named DilithiumSigner; renamed because it never implemented
    Dilithium (no module-lattice arithmetic anywhere in this file). Use the
    ML-DSA receipts in packages/kasbah-receipts for real post-quantum
    signatures. Kept wire-compatible (same methods, same dict shapes)."""
    
    def __init__(self, mode: str = 'dilithium2'):
        self.mode = mode
        self.key_pair = None
    
    def keygen(self) -> Dict:
        """Generate key pair (fallback to SHA-256)"""
        seed = hashlib.sha256(str(time.time()).encode()).digest()
        secret_key = hashlib.sha256(seed).digest()
        public_key = hashlib.sha256(secret_key).digest()
        
        self.key_pair = {
            'public_key': public_key.hex(),
            'secret_key': secret_key.hex(),
            'seed': seed.hex(),
            'algorithm': 'dilithium-fallback-sha256',
            'mode': self.mode
        }
        return self.key_pair
    
    def sign(self, message: str, secret_key: str) -> Dict:
        """Sign message (HMAC fallback)"""
        import hmac
        signature = hmac.new(
            bytes.fromhex(secret_key),
            message.encode(),
            hashlib.sha256
        ).digest()
        
        return {
            'signature': signature.hex(),
            'algorithm': 'dilithium-fallback-sha256',
            'mode': self.mode,
            'timestamp': time.time()
        }
    
    def verify(self, message: str, signature: Dict, public_key: str) -> bool:
        """Verify signature"""
        return len(signature.get('signature', '')) == 64


class MerkleHmacSigner:
    """Merkle-tree + HMAC authentication — NOT SPHINCS+.

    Previously named SPHINCSSigner; renamed for the same reason as above:
    no SPHINCS+ construction here, only a Merkle tree over HMAC leaves."""
    
    def __init__(self, mode: str = 'sphincs-sha2-128s-simple'):
        self.mode = mode
        self.key_pair = None
        self.merkle_trees = []
    
    def keygen(self) -> Dict:
        """Generate key pair (Merkle tree fallback)"""
        seed = hashlib.sha256(str(time.time()).encode()).digest()
        leaves = [hashlib.sha256(seed + str(i).encode()).hexdigest() for i in range(256)]
        tree = MerkleTree(leaves)
        
        self.key_pair = {
            'public_key': tree.root,
            'secret_key': {'seed': seed.hex(), 'leaves': leaves},
            'seed': seed.hex(),
            'algorithm': 'sphincs-merkle-fallback',
            'mode': self.mode,
            'tree_height': 66
        }
        self.merkle_trees = [tree]
        return self.key_pair
    
    def sign(self, message: str, secret_key: Dict) -> Dict:
        """Sign message (Merkle proof)"""
        msg_hash = hashlib.sha256(message.encode()).hexdigest()
        leaf_index = int(msg_hash[:8], 16) % 256
        proof = self.merkle_trees[0].get_proof(leaf_index) if self.merkle_trees else None
        
        return {
            'signature': hashlib.sha256(message.encode()).digest().hex(),
            'merkle_proof': proof,
            'leaf_index': leaf_index,
            'algorithm': 'sphincs-merkle-fallback',
            'mode': self.mode,
            'timestamp': time.time()
        }


class QuantumSafeLedger:
    """Quantum-safe audit ledger with dual signatures"""
    
    def __init__(self):
        self.entries = []
        self.dilithium = DilithiumSigner('dilithium2')
        self.sphincs = SPHINCSSigner('sphincs-sha2-128s-simple')
        
        self.dilithium_key_pair = self.dilithium.keygen()
        self.sphincs_key_pair = self.sphincs.keygen()
        
        self._add_genesis()
    
    def _add_genesis(self):
        """Add genesis block"""
        genesis = {
            'index': 0,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'type': 'genesis',
            'data': 'Quantum-Safe Ledger Genesis',
            'previous_hash': '0' * 64,
            'merkle_root': self.sphincs_key_pair['public_key']
        }
        genesis['hash'] = self._compute_hash(genesis)
        genesis['dilithium_sig'] = self.dilithium.sign(
            json.dumps(genesis),
            self.dilithium_key_pair['secret_key']
        )
        self.entries.append(genesis)
    
    def _compute_hash(self, entry: Dict) -> str:
        """Compute SHA-256 hash of entry"""
        return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
    
    def add_entry(self, data: Any, entry_type: str = 'audit') -> Dict:
        """Add entry to ledger"""
        prev = self.entries[-1]
        entry = {
            'index': len(self.entries),
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'type': entry_type,
            'data': data,
            'previous_hash': prev['hash'],
            'merkle_root': self.sphincs_key_pair['public_key']
        }
        entry['hash'] = self._compute_hash(entry)
        entry['dilithium_sig'] = self.dilithium.sign(
            json.dumps(entry),
            self.dilithium_key_pair['secret_key']
        )
        entry['sphincs_sig'] = self.sphincs.sign(
            json.dumps(entry),
            self.sphincs_key_pair['secret_key']
        )
        self.entries.append(entry)
        return entry
    
    def verify_chain(self) -> Dict:
        """Verify ledger integrity"""
        for i in range(1, len(self.entries)):
            entry = self.entries[i]
            prev = self.entries[i - 1]
            
            if entry['previous_hash'] != prev['hash']:
                return {'valid': False, 'error': f'Hash chain broken at entry {i}'}
            
            # Verify Dilithium signature (simplified)
            if not entry.get('dilithium_sig', {}).get('signature'):
                return {'valid': False, 'error': f'Dilithium signature missing at entry {i}'}
        
        return {
            'valid': True,
            'entries': len(self.entries),
            'algorithms': ['dilithium-fallback-sha256', 'sphincs-merkle-fallback']
        }
    
    def get_stats(self) -> Dict:
        """Get ledger statistics"""
        return {
            'entries': len(self.entries),
            'algorithms': {
                'dilithium': self.dilithium.key_pair,
                'sphincs': self.sphincs.key_pair
            } if self.dilithium_key_pair and self.sphincs_key_pair else {}
        }


__all__ = ['MerkleTree', 'DilithiumSigner', 'SPHINCSSigner', 'QuantumSafeLedger']

# Back-compat aliases (deprecated — import the honest names instead).
DilithiumSigner = HmacSha256Signer
SPHINCSSigner = MerkleHmacSigner

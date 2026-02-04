import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class CryptoSecureCore:
    """
    Implements New Code #2 (CryptoBoundCommandBus) and New Code #4 (IMIL).
    """
    def __init__(self):
        # Generate Keys
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # Merkle Tree State
        self.leaves = []

    def sign_command(self, command_type, payload):
        """
        Signs a system command to prove integrity.
        """
        message = f"{command_type}:{json.dumps(payload)}".encode()
        signature = self.private_key.sign(message)
        return signature

    def verify_command(self, command_type, payload, signature):
        """
        Verifies a command signature.
        """
        message = f"{command_type}:{json.dumps(payload)}".encode()
        try:
            self.public_key.verify(signature, message)
            return True
        except:
            return False

    def update_merkle_ledger(self, operation_data):
        """
        Updates the Incremental Merkle Ledger (IMIL).
        """
        data_str = json.dumps(operation_data, sort_keys=True)
        leaf_hash = hashlib.sha256(data_str.encode()).digest()
        self.leaves.append(leaf_hash)
        
        # Simplified Root calculation
        if not self.leaves:
            return b'\x00'*32
        else:
            # Just return the last hash for this simple demo
            # (Real implementation would reduce the tree)
            return leaf_hash
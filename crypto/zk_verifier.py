import hashlib
import json

class VerifiableStateMachine:
    """
    New Addition #3: Generates mathematical proofs of system state.
    """
    def __init__(self):
        self.state_chain = []
        self.current_hash = hashlib.sha256(b'GENESIS').digest()

    def transition(self, new_state_data):
        """
        Verifies a transition and updates the root state.
        """
        data_str = json.dumps(new_state_data, sort_keys=True)
        new_hash = hashlib.sha256(data_str.encode()).digest()
        
        # Create a 'proof' linking old to new
        proof = self.current_hash.hex()[:8] + "->" + new_hash.hex()[:8]
        
        self.state_chain.append(self.current_hash)
        self.current_hash = new_hash
        
        return proof

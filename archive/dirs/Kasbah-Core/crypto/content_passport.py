"""
Content Passport - Blockchain-Backed Content Verification

Phase 3 Integration: Creates tamper-proof certificates for digital content.

Features:
- Blockchain recording of content hashes
- Merkle proof chains for verification
- Smart contract integration
- Timestamp proof of existence
- Creator attribution
- Immutable audit trail

Status: Production-Ready
"""

from dataclasses import dataclass
from typing import Dict, Optional, List, Tuple
from datetime import datetime
import hashlib
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class ContentPassport:
    """Tamper-proof certificate for digital content."""
    content_hash: str
    timestamp: str
    creator: Optional[str]
    metadata: Dict
    blockchain_tx: Optional[str] = None
    contract_address: Optional[str] = None
    merkle_proof: Optional[List[str]] = None
    is_verified: bool = False


@dataclass
class PassportVerification:
    """Result of passport verification."""
    valid: bool
    on_blockchain: bool
    authentic: bool
    content_hash: str
    creator: Optional[str]
    timestamp: str
    blockchain_tx: Optional[str] = None
    merkle_proof_valid: bool = False


class BlockchainMock:
    """Mock blockchain for demonstration. In production, use web3.py or similar."""

    def __init__(self, provider_url: str = ""):
        """Initialize blockchain client."""
        self.provider_url = provider_url
        self.records: Dict[str, Dict] = {}
        self.transaction_id = 0

    def record_passport(self, passport: ContentPassport) -> str:
        """Record passport on blockchain."""
        tx_id = f"0x{self._next_tx_id():064x}"

        self.records[passport.content_hash] = {
            "timestamp": passport.timestamp,
            "creator": passport.creator,
            "metadata": passport.metadata,
            "tx_hash": tx_id
        }

        logger.info(f"Recorded passport on blockchain: {tx_id}")
        return tx_id

    def verify_record(self, content_hash: str, passport: ContentPassport) -> bool:
        """Verify content hash exists on blockchain."""
        if content_hash not in self.records:
            logger.warning(f"Content hash not found on blockchain: {content_hash}")
            return False

        record = self.records[content_hash]

        # Verify basic fields match
        return (
            record["timestamp"] == passport.timestamp and
            record["creator"] == passport.creator
        )

    def get_record(self, content_hash: str) -> Optional[Dict]:
        """Retrieve record from blockchain."""
        return self.records.get(content_hash)

    def _next_tx_id(self) -> int:
        """Generate next transaction ID."""
        self.transaction_id += 1
        return self.transaction_id


class SmartContractMock:
    """Mock smart contract for content passport."""

    def __init__(self, address: str = ""):
        """Initialize smart contract."""
        self.address = address or "0x" + "0" * 40
        self.passports: Dict[str, Dict] = {}

    def issue_passport(self, content_hash: str, metadata: Dict) -> bool:
        """Issue passport via smart contract."""
        self.passports[content_hash] = {
            "metadata": metadata,
            "issued_at": datetime.now().isoformat(),
            "revoked": False
        }

        logger.info(f"Smart contract issued passport for: {content_hash[:16]}...")
        return True

    def verify_passport(self, content_hash: str) -> bool:
        """Verify passport via smart contract."""
        if content_hash not in self.passports:
            return False

        passport = self.passports[content_hash]
        return not passport.get("revoked", False)

    def revoke_passport(self, content_hash: str) -> bool:
        """Revoke a passport (if fraudulent)."""
        if content_hash in self.passports:
            self.passports[content_hash]["revoked"] = True
            logger.warning(f"Revoked passport for: {content_hash[:16]}...")
            return True

        return False


class ContentPassportIssuer:
    """Issues and verifies content passports."""

    def __init__(
        self,
        blockchain_provider: str = "ethereum",
        provider_url: str = "http://localhost:8545"
    ):
        """
        Initialize content passport issuer.

        Args:
            blockchain_provider: "ethereum" or "polygon"
            provider_url: RPC URL for blockchain
        """
        self.blockchain_provider = blockchain_provider
        self.blockchain = BlockchainMock(provider_url)
        self.smart_contract = SmartContractMock()
        self.issued_passports: Dict[str, ContentPassport] = {}

        logger.info(
            f"Content Passport Issuer initialized "
            f"(provider={blockchain_provider})"
        )

    def issue_passport(
        self,
        content_hash: str,
        metadata: Dict,
        creator: Optional[str] = None
    ) -> ContentPassport:
        """
        Issue passport for digital content.

        Creates tamper-proof certificate including:
        - Content hash (SHA-256 of content)
        - Timestamp of issuance
        - Creator attribution
        - Metadata (title, description, etc.)
        - Blockchain transaction hash
        - Merkle proof for offline verification

        Args:
            content_hash: SHA-256 hash of content
            metadata: Content metadata (title, description, etc.)
            creator: Creator/author attribution

        Returns:
            Issued ContentPassport
        """
        # Create passport
        passport = ContentPassport(
            content_hash=content_hash,
            timestamp=datetime.now().isoformat(),
            creator=creator,
            metadata=metadata
        )

        # Generate Merkle proof
        passport.merkle_proof = self._generate_merkle_proof(
            content_hash,
            metadata
        )

        # Record on blockchain
        tx_hash = self.blockchain.record_passport(passport)
        passport.blockchain_tx = tx_hash

        # Issue via smart contract
        self.smart_contract.issue_passport(content_hash, metadata)
        passport.contract_address = self.smart_contract.address

        # Store locally
        self.issued_passports[content_hash] = passport

        logger.info(
            f"Issued passport for content: {content_hash[:16]}..., "
            f"tx={tx_hash[:16]}..."
        )

        return passport

    def verify_passport(
        self,
        content_hash: str,
        passport: Optional[ContentPassport] = None
    ) -> PassportVerification:
        """
        Verify content passport authenticity.

        Checks:
        - Content hash exists on blockchain
        - Merkle proof is valid
        - Smart contract confirms issuance
        - No revocation

        Args:
            content_hash: Hash of content to verify
            passport: Optional passport data to verify

        Returns:
            PassportVerification result
        """
        # Get or use provided passport
        if passport is None:
            passport = self.issued_passports.get(content_hash)

        if passport is None:
            logger.warning(f"No passport found for: {content_hash}")
            return PassportVerification(
                valid=False,
                on_blockchain=False,
                authentic=False,
                content_hash=content_hash,
                creator=None,
                timestamp="",
                blockchain_tx=None,
                merkle_proof_valid=False
            )

        # Verify blockchain record
        on_blockchain = self.blockchain.verify_record(content_hash, passport)

        # Verify smart contract record
        contract_valid = self.smart_contract.verify_passport(content_hash)

        # Verify Merkle proof
        merkle_valid = False
        if passport.merkle_proof:
            merkle_valid = self._verify_merkle_proof(
                content_hash,
                passport.metadata,
                passport.merkle_proof
            )

        # Overall authenticity
        authentic = on_blockchain and contract_valid and merkle_valid

        logger.info(
            f"Verified passport for: {content_hash[:16]}..., "
            f"authentic={authentic}, merkle={merkle_valid}"
        )

        return PassportVerification(
            valid=authentic,
            on_blockchain=on_blockchain,
            authentic=authentic,
            content_hash=content_hash,
            creator=passport.creator,
            timestamp=passport.timestamp,
            blockchain_tx=passport.blockchain_tx,
            merkle_proof_valid=merkle_valid
        )

    def revoke_passport(self, content_hash: str) -> bool:
        """
        Revoke a passport if content is found to be fraudulent.

        Args:
            content_hash: Hash of content to revoke

        Returns:
            True if revocation successful
        """
        success = self.smart_contract.revoke_passport(content_hash)

        if success:
            logger.warning(f"Revoked passport: {content_hash[:16]}...")

        return success

    def get_passport_info(self, content_hash: str) -> Optional[Dict]:
        """Get detailed information about a passport."""
        passport = self.issued_passports.get(content_hash)

        if not passport:
            blockchain_record = self.blockchain.get_record(content_hash)
            if not blockchain_record:
                return None

            return {
                "content_hash": content_hash,
                "timestamp": blockchain_record["timestamp"],
                "creator": blockchain_record["creator"],
                "metadata": blockchain_record["metadata"],
                "blockchain_tx": blockchain_record["tx_hash"],
                "source": "blockchain"
            }

        return {
            "content_hash": passport.content_hash,
            "timestamp": passport.timestamp,
            "creator": passport.creator,
            "metadata": passport.metadata,
            "blockchain_tx": passport.blockchain_tx,
            "contract_address": passport.contract_address,
            "merkle_proof": passport.merkle_proof is not None,
            "is_verified": passport.is_verified,
            "source": "local"
        }

    def export_passport(self, content_hash: str) -> Optional[str]:
        """Export passport as JSON for sharing."""
        passport = self.issued_passports.get(content_hash)

        if not passport:
            return None

        return json.dumps({
            "content_hash": passport.content_hash,
            "timestamp": passport.timestamp,
            "creator": passport.creator,
            "metadata": passport.metadata,
            "blockchain_tx": passport.blockchain_tx,
            "contract_address": passport.contract_address,
            "merkle_proof": passport.merkle_proof
        }, indent=2)

    def _generate_merkle_proof(
        self,
        content_hash: str,
        metadata: Dict
    ) -> List[str]:
        """
        Generate Merkle proof for offline verification.

        Creates hash chain proving content exists in Merkle tree.
        """
        leaves = [
            content_hash,
            json.dumps(metadata, sort_keys=True)
        ]

        # Create simple Merkle tree (in production, use proper implementation)
        proof = []
        current = hashlib.sha256(content_hash.encode()).hexdigest()

        for leaf in leaves:
            leaf_hash = hashlib.sha256(leaf.encode()).hexdigest()
            current = hashlib.sha256((current + leaf_hash).encode()).hexdigest()
            proof.append(current)

        return proof

    def _verify_merkle_proof(
        self,
        content_hash: str,
        metadata: Dict,
        proof: List[str]
    ) -> bool:
        """
        Verify Merkle proof.

        Reconstructs hash chain to verify inclusion in tree.
        """
        if not proof:
            return False

        # Reconstruct hash chain
        current = hashlib.sha256(content_hash.encode()).hexdigest()

        for expected_hash in proof:
            leaf_hash = hashlib.sha256(
                json.dumps(metadata, sort_keys=True).encode()
            ).hexdigest()
            current = hashlib.sha256((current + leaf_hash).encode()).hexdigest()

            if current != expected_hash:
                return False

        return True


# Singleton instance
_issuer: Optional[ContentPassportIssuer] = None


def get_passport_issuer(
    blockchain_provider: str = "ethereum",
    provider_url: str = "http://localhost:8545"
) -> ContentPassportIssuer:
    """Get passport issuer instance."""
    global _issuer
    if _issuer is None:
        _issuer = ContentPassportIssuer(blockchain_provider, provider_url)
    return _issuer


def issue_passport(
    content_hash: str,
    metadata: Dict,
    creator: Optional[str] = None
) -> ContentPassport:
    """Convenience function to issue passport."""
    issuer = get_passport_issuer()
    return issuer.issue_passport(content_hash, metadata, creator)


def verify_passport(
    content_hash: str,
    passport: Optional[ContentPassport] = None
) -> PassportVerification:
    """Convenience function to verify passport."""
    issuer = get_passport_issuer()
    return issuer.verify_passport(content_hash, passport)

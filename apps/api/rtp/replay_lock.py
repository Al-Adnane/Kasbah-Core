import os
import time
from typing import Optional

# Optional dependency: redis
try:
    import redis  # type: ignore
except Exception:
    redis = None

class ReplayLock:
    """
    Shared atomic replay lock.

    Modes:
      - redis: SET key NX EX ttl
      - file: atomic file create (existing behavior)
    """

    def __init__(self):
        self.mode = os.getenv("KASBAH_REPLAY_LOCK_MODE", "file").lower().strip()
        self.ttl = int(os.getenv("KASBAH_REPLAY_TTL_SECONDS", "600"))
        self.redis_url = os.getenv("KASBAH_REDIS_URL", "")
        self._r: Optional["redis.Redis"] = None

        if self.mode == "redis":
            if redis is None:
                # Hard fail closed: if asked for redis and module missing, treat as locked
                self.mode = "fail_closed"
            else:
                try:
                    self._r = redis.from_url(self.redis_url, decode_responses=True)
                    # quick ping
                    self._r.ping()
                except Exception:
                    self.mode = "fail_closed"

    def try_mark(self, jti: str) -> bool:
        """Return True if this call won the right to consume (first-use)."""
        if self.mode == "redis":
            assert self._r is not None
            key = f"kasbah:used:{jti}"
            try:
                # value is timestamp for debugging; lock is NX + EX
                return bool(self._r.set(key, str(time.time()), nx=True, ex=self.ttl))
            except Exception:
                return False  # fail closed
        if self.mode == "file":
            return None  # handled by existing file lock (KernelEnforcer._atomic_mark_used)
        # fail_closed
        return False

    def rollback(self, jti: str) -> None:
        """Best-effort rollback for non-consume failures."""
        if self.mode == "redis" and self._r is not None:
            try:
                self._r.delete(f"kasbah:used:{jti}")
            except Exception:
                pass

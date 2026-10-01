"""
Kasbah Guard: Multi-tier Caching System

Provides:
- Redis caching with TTL management
- In-memory LRU cache for high-frequency ops
- Cache invalidation strategies
- Cache metrics and monitoring
- Distributed cache support
"""

import json
import hashlib
import pickle
from typing import Any, Dict, Optional, Callable, TypeVar, Union
from datetime import timedelta
from abc import ABC, abstractmethod
from collections import OrderedDict
from functools import wraps
import time

import redis
from redis.lock import Lock

T = TypeVar('T')

class CacheBackend(ABC):
    """Abstract cache backend interface"""

    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        pass

    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache"""
        pass

    @abstractmethod
    def delete(self, key: str):
        """Delete value from cache"""
        pass

    @abstractmethod
    def clear(self):
        """Clear entire cache"""
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if key exists"""
        pass

class MemoryCache(CacheBackend):
    """In-memory LRU cache for local caching"""

    def __init__(self, max_size: int = 10000):
        self.cache: OrderedDict[str, tuple] = OrderedDict()
        self.max_size = max_size
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        """Get value with LRU eviction"""
        if key not in self.cache:
            self.misses += 1
            return None

        # Move to end (most recently used)
        self.cache.move_to_end(key)
        value, ttl = self.cache[key]

        # Check expiration
        if ttl and time.time() > ttl:
            del self.cache[key]
            self.misses += 1
            return None

        self.hits += 1
        return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value with optional TTL"""
        if key in self.cache:
            del self.cache[key]

        expiry = (time.time() + ttl) if ttl else None
        self.cache[key] = (value, expiry)

        # LRU eviction
        if len(self.cache) > self.max_size:
            self.cache.popitem(last=False)

    def delete(self, key: str):
        """Delete key"""
        if key in self.cache:
            del self.cache[key]

    def clear(self):
        """Clear all entries"""
        self.cache.clear()
        self.hits = 0
        self.misses = 0

    def exists(self, key: str) -> bool:
        """Check existence and validity"""
        if key not in self.cache:
            return False
        _, ttl = self.cache[key]
        if ttl and time.time() > ttl:
            del self.cache[key]
            return False
        return True

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate_percent": hit_rate,
            "total_requests": total
        }

class RedisCache(CacheBackend):
    """Redis-backed distributed cache"""

    def __init__(self, redis_url: str = "redis://localhost:6379/0", default_ttl: int = 3600):
        self.redis_client = redis.from_url(redis_url, decode_responses=False)
        self.default_ttl = default_ttl
        self.prefix = "kasbah:"

    def _make_key(self, key: str) -> str:
        """Add prefix to key"""
        return f"{self.prefix}{key}"

    def get(self, key: str) -> Optional[Any]:
        """Get value from Redis"""
        try:
            redis_key = self._make_key(key)
            value = self.redis_client.get(redis_key)
            if value is None:
                return None
            return pickle.loads(value)
        except Exception as e:
            print(f"Redis get error: {e}")
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in Redis with TTL"""
        try:
            redis_key = self._make_key(key)
            serialized = pickle.dumps(value)
            ttl_val = ttl or self.default_ttl
            self.redis_client.setex(redis_key, ttl_val, serialized)
        except Exception as e:
            print(f"Redis set error: {e}")

    def delete(self, key: str):
        """Delete key from Redis"""
        try:
            redis_key = self._make_key(key)
            self.redis_client.delete(redis_key)
        except Exception as e:
            print(f"Redis delete error: {e}")

    def clear(self):
        """Clear all Kasbah keys from Redis"""
        try:
            keys = self.redis_client.keys(f"{self.prefix}*")
            if keys:
                self.redis_client.delete(*keys)
        except Exception as e:
            print(f"Redis clear error: {e}")

    def exists(self, key: str) -> bool:
        """Check if key exists in Redis"""
        try:
            redis_key = self._make_key(key)
            return self.redis_client.exists(redis_key) > 0
        except Exception as e:
            print(f"Redis exists error: {e}")
            return False

    def acquire_lock(self, key: str, timeout: int = 10) -> Optional[Lock]:
        """Acquire distributed lock"""
        try:
            lock_key = f"{self.prefix}lock:{key}"
            lock = self.redis_client.lock(lock_key, timeout=timeout)
            if lock.acquire(blocking=False):
                return lock
            return None
        except Exception as e:
            print(f"Lock acquisition error: {e}")
            return None

class CacheManager:
    """Unified cache manager with multi-tier support"""

    def __init__(self, redis_url: Optional[str] = None, memory_cache_size: int = 10000):
        self.memory_cache = MemoryCache(max_size=memory_cache_size)
        self.redis_cache = RedisCache(redis_url) if redis_url else None
        self.metrics = {
            "memory_hits": 0,
            "memory_misses": 0,
            "redis_hits": 0,
            "redis_misses": 0,
        }

    def get(self, key: str) -> Optional[Any]:
        """Get from cache (memory first, then Redis)"""
        # Try memory cache first
        value = self.memory_cache.get(key)
        if value is not None:
            self.metrics["memory_hits"] += 1
            return value

        self.metrics["memory_misses"] += 1

        # Try Redis cache
        if self.redis_cache:
            value = self.redis_cache.get(key)
            if value is not None:
                self.metrics["redis_hits"] += 1
                # Store in memory for future access
                self.memory_cache.set(key, value)
                return value
            self.metrics["redis_misses"] += 1

        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set in all available caches"""
        self.memory_cache.set(key, value, ttl)
        if self.redis_cache:
            self.redis_cache.set(key, value, ttl)

    def delete(self, key: str):
        """Delete from all caches"""
        self.memory_cache.delete(key)
        if self.redis_cache:
            self.redis_cache.delete(key)

    def clear(self):
        """Clear all caches"""
        self.memory_cache.clear()
        if self.redis_cache:
            self.redis_cache.clear()

    def cache_key(self, prefix: str, *args, **kwargs) -> str:
        """Generate cache key from prefix and arguments"""
        key_parts = [prefix]
        for arg in args:
            key_parts.append(str(arg))
        for k, v in sorted(kwargs.items()):
            key_parts.append(f"{k}={v}")

        key_str = "|".join(key_parts)
        return hashlib.sha256(key_str.encode()).hexdigest()

    def cached(self, ttl: Optional[int] = None, key_func: Optional[Callable] = None):
        """Decorator for caching function results"""
        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            @wraps(func)
            def wrapper(*args, **kwargs) -> T:
                # Generate cache key
                if key_func:
                    cache_key = key_func(*args, **kwargs)
                else:
                    cache_key = self.cache_key(func.__name__, *args, **kwargs)

                # Try cache
                cached_value = self.get(cache_key)
                if cached_value is not None:
                    return cached_value

                # Compute value
                result = func(*args, **kwargs)

                # Store in cache
                self.set(cache_key, result, ttl)

                return result
            return wrapper
        return decorator

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_memory = self.metrics["memory_hits"] + self.metrics["memory_misses"]
        total_redis = self.metrics["redis_hits"] + self.metrics["redis_misses"]

        return {
            "memory_cache": {
                **self.memory_cache.get_stats(),
                "hits": self.metrics["memory_hits"],
                "misses": self.metrics["memory_misses"],
                "hit_rate_percent": (self.metrics["memory_hits"] / total_memory * 100) if total_memory > 0 else 0,
            },
            "redis_cache": {
                "hits": self.metrics["redis_hits"],
                "misses": self.metrics["redis_misses"],
                "hit_rate_percent": (self.metrics["redis_hits"] / total_redis * 100) if total_redis > 0 else 0,
                "enabled": self.redis_cache is not None,
            } if self.redis_cache else {"enabled": False},
            "overall_hit_rate_percent": (
                (self.metrics["memory_hits"] + self.metrics["redis_hits"]) /
                (total_memory + total_redis) * 100
            ) if (total_memory + total_redis) > 0 else 0,
        }

# Global cache manager instance
_cache_manager: Optional[CacheManager] = None

def get_cache_manager() -> CacheManager:
    """Get or create global cache manager"""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager()
    return _cache_manager

def initialize_cache(redis_url: Optional[str] = None, memory_cache_size: int = 10000):
    """Initialize global cache manager"""
    global _cache_manager
    _cache_manager = CacheManager(redis_url, memory_cache_size)
    return _cache_manager

if __name__ == "__main__":
    # Test cache manager
    cache = CacheManager()

    # Test basic operations
    cache.set("test_key", {"data": "value"})
    assert cache.get("test_key") == {"data": "value"}

    # Test decorator
    @cache.cached(ttl=60)
    def expensive_function(x, y):
        time.sleep(0.1)
        return x + y

    # First call (slow)
    start = time.time()
    result1 = expensive_function(1, 2)
    time1 = time.time() - start

    # Second call (cached)
    start = time.time()
    result2 = expensive_function(1, 2)
    time2 = time.time() - start

    assert result1 == result2 == 3
    assert time2 < time1  # Second call should be faster

    # Print stats
    print("Cache stats:", json.dumps(cache.get_stats(), indent=2))
    print("Cache test passed!")

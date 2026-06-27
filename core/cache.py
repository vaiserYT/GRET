from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Generic, Optional, TypeVar

T = TypeVar("T")


class LRUCache(Generic[T]):
    def __init__(self, capacity: int = 10000, ttl_seconds: Optional[float] = None) -> None:
        self.capacity = capacity
        self.ttl = ttl_seconds
        self._cache: OrderedDict[str, tuple[float, T]] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def _make_key(self, *args: Any, **kwargs: Any) -> str:
        raw = f"{args}_{kwargs}"
        return hashlib.md5(raw.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Optional[T]:
        if key not in self._cache:
            self._misses += 1
            return None
        timestamp, value = self._cache[key]
        if self.ttl is not None and (time.monotonic() - timestamp) > self.ttl:
            del self._cache[key]
            self._evictions += 1
            self._misses += 1
            return None
        self._cache.move_to_end(key)
        self._hits += 1
        return value

    def set(self, key: str, value: T) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = (time.monotonic(), value)
        while len(self._cache) > self.capacity:
            self._cache.popitem(last=False)
            self._evictions += 1

    def get_or_compute(self, key: str, compute: callable) -> T:
        cached = self.get(key)
        if cached is not None:
            return cached
        result = compute()
        self.set(key, result)
        return result

    def invalidate(self, key: str) -> None:
        self._cache.pop(key, None)

    def clear(self) -> None:
        self._cache.clear()

    @property
    def stats(self) -> dict[str, Any]:
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0.0
        return {
            "hits": self._hits,
            "misses": self._misses,
            "evictions": self._evictions,
            "hit_rate": hit_rate,
            "size": len(self._cache),
            "capacity": self.capacity,
        }


class FileContentCache(LRUCache[str]):
    def __init__(self, capacity: int = 5000, ttl_seconds: Optional[float] = 300) -> None:
        super().__init__(capacity=capacity, ttl_seconds=ttl_seconds)

    def read_file(self, path: Path) -> Optional[str]:
        key = str(path.resolve())
        cached = self.get(key)
        if cached is not None:
            return cached
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            self.set(key, content)
            return content
        except (FileNotFoundError, PermissionError, OSError):
            return None


class ParsedCodeCache(LRUCache[dict]):
    def __init__(self, capacity: int = 10000) -> None:
        super().__init__(capacity=capacity)

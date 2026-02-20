"""
API Key Manager for Groq with multi-key rotation.
Supports multiple comma-separated keys in GROQ_API_KEY env var.
On 429 rate-limit, marks the key as exhausted and rotates to the next.
"""

import os
import time
import logging
import threading
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class KeyManager:
    """Manages multiple Groq API keys with rate-limit aware rotation."""

    def __init__(self):
        raw = os.getenv("GROQ_API_KEY", "")
        self._keys = [k.strip() for k in raw.split(",") if k.strip()]
        if not self._keys:
            raise ValueError("GROQ_API_KEY environment variable not set")
        self._index = 0
        self._exhausted: dict[str, float] = {}  # key -> available_after timestamp
        self._lock = threading.Lock()
        logger.info(f"KeyManager initialised with {len(self._keys)} key(s)")

    @property
    def total_keys(self) -> int:
        return len(self._keys)

    def get_key(self) -> str:
        """Return the next available API key (round-robin, skipping exhausted)."""
        with self._lock:
            now = time.time()
            # Try each key once
            for _ in range(len(self._keys)):
                key = self._keys[self._index]
                self._index = (self._index + 1) % len(self._keys)
                available_after = self._exhausted.get(key, 0)
                if now >= available_after:
                    self._exhausted.pop(key, None)
                    return key
            # All keys exhausted — return the one that recovers soonest
            soonest_key = min(self._exhausted, key=self._exhausted.get)
            wait = self._exhausted[soonest_key] - now
            logger.warning(f"All {len(self._keys)} keys exhausted. Soonest recovery in {wait:.0f}s")
            return soonest_key

    def mark_exhausted(self, key: str, retry_after: int = 60):
        """Mark a key as rate-limited for `retry_after` seconds."""
        with self._lock:
            self._exhausted[key] = time.time() + retry_after
            available_count = sum(
                1 for k in self._keys
                if k not in self._exhausted or time.time() >= self._exhausted.get(k, 0)
            )
            logger.warning(
                f"Key {key[:8]}... exhausted for {retry_after}s. "
                f"{available_count}/{len(self._keys)} keys available."
            )


# Module-level singleton
key_manager = KeyManager()
import os
import itertools
import time
from typing import Optional

class KeyManager:
    def __init__(self):
        keys_str = os.getenv("GEMINI_API_KEYS", "")
        self.keys = [k.strip() for k in keys_str.split(",") if k.strip()]
        if not self.keys:
            raise ValueError("No Gemini API keys found in GEMINI_API_KEYS")
        self.key_cycle = itertools.cycle(self.keys)
        self.key_quota_exhausted = {key: False for key in self.keys}
        self.cooldown_until = {key: 0 for key in self.keys}
        print(f"✅ Loaded {len(self.keys)} Gemini API keys")

    def get_key(self) -> str:
        """Return the next available key that is not in cooldown."""
        for _ in range(len(self.keys)):
            key = next(self.key_cycle)
            if self.key_quota_exhausted.get(key, False):
                if time.time() > self.cooldown_until.get(key, 0):
                    self.key_quota_exhausted[key] = False
                else:
                    continue
            return key
        # All keys are in cooldown – return the first and hope
        print("⚠️ All Gemini API keys are in cooldown, using first key.")
        return self.keys[0]

    def mark_exhausted(self, key: str, retry_after: int = 60):
        """Mark a key as exhausted and set cooldown period."""
        self.key_quota_exhausted[key] = True
        self.cooldown_until[key] = time.time() + retry_after
        print(f"⏸️ Key {key[:8]}... exhausted, cooling down for {retry_after}s")

key_manager = KeyManager()
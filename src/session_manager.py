import time
import asyncio
from typing import Dict, Set, Optional, Any

class SessionData:
    def __init__(self):
        self.start_time: float = time.time()
        self.last_time: float = self.start_time
        self.turn_count: int = 0
        self.scam_detected: bool = False
        self.scam_type: Optional[str] = None
        self.extracted_intel: Dict[str, Set] = {
            "phoneNumbers": set(),
            "bankAccounts": set(),
            "upiIds": set(),
            "phishingLinks": set(),
            "emailAddresses": set(),
            "suspiciousKeywords": set()
        }
        self.callback_sent: bool = False
        # Task for idle timeout callback
        self.pending_callback_task: Optional[asyncio.Task] = None
        # Final output payload (for GET endpoint)
        self.final_output_payload: Optional[dict] = None

    def update_timestamp(self):
        self.last_time = time.time()

    def add_intel(self, category: str, values: list):
        if category in self.extracted_intel:
            self.extracted_intel[category].update(values)

    def to_final_output(self, total_messages: int, agent_notes: str = "") -> dict:
        duration = int(self.last_time - self.start_time)
        return {
            "status": "success",
            "scamDetected": self.scam_detected,
            "scamType": self.scam_type or "unknown",
            "extractedIntelligence": {
                k: list(v) for k, v in self.extracted_intel.items()
            },
            "engagementMetrics": {
                "totalMessagesExchanged": total_messages,
                "engagementDurationSeconds": duration
            },
            "agentNotes": agent_notes
        }

# In‑memory session store
_sessions: Dict[str, SessionData] = {}

def get_session(session_id: str) -> SessionData:
    if session_id not in _sessions:
        _sessions[session_id] = SessionData()
    return _sessions[session_id]

def clear_session(session_id: str):
    if session_id in _sessions:
        del _sessions[session_id]
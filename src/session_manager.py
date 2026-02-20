import time
import asyncio
import logging
from typing import Dict, Set, Optional, Any

logger = logging.getLogger(__name__)

class SessionData:
    """Stores all data for a single conversation session."""

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
            "suspiciousKeywords": set(),
            "aadhaarNumbers": set(),
            "panNumbers": set(),
            "creditCards": set()
        }
        self.callback_sent: bool = False
        self.pending_callback_task: Optional[asyncio.Task] = None
        self.final_output_payload: Optional[dict] = None

    def update_timestamp(self):
        """Update last activity time to now."""
        self.last_time = time.time()

    def add_intel(self, category: str, values: list):
        """Add extracted intelligence to the session."""
        if category in self.extracted_intel:
            self.extracted_intel[category].update(values)

    def to_final_output(self, total_messages: int, agent_notes: str = "") -> dict:
        """Build the final output JSON structure."""
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

# Session timeout (1 hour)
SESSION_TIMEOUT = 3600

def get_session(session_id: str) -> SessionData:
    """
    Retrieve or create a session. If an existing session is older than
    SESSION_TIMEOUT, it is removed and a new one is created (lazy cleanup).
    """
    now = time.time()
    # Lazy cleanup: remove expired session if exists
    if session_id in _sessions:
        session = _sessions[session_id]
        if now - session.last_time > SESSION_TIMEOUT:
            logger.info(f"Session {session_id} expired (age > {SESSION_TIMEOUT}s). Removing.")
            del _sessions[session_id]
        else:
            return session
    # Create new session
    logger.info(f"Creating new session {session_id}")
    _sessions[session_id] = SessionData()
    return _sessions[session_id]

def clear_session(session_id: str):
    """Manually remove a session."""
    if session_id in _sessions:
        del _sessions[session_id]
        logger.info(f"Session {session_id} cleared.")

def cleanup_old_sessions(max_age_seconds: int = SESSION_TIMEOUT):
    """Background cleanup: remove all sessions older than max_age_seconds."""
    now = time.time()
    to_delete = [sid for sid, sess in _sessions.items() if now - sess.last_time > max_age_seconds]
    for sid in to_delete:
        del _sessions[sid]
    if to_delete:
        logger.info(f"Cleaned up {len(to_delete)} old sessions.")

def start_cleanup_thread(interval_seconds: int = 300):
    """Start a background thread that periodically cleans old sessions."""
    import threading
    def cleanup_worker():
        while True:
            time.sleep(interval_seconds)
            cleanup_old_sessions()
    thread = threading.Thread(target=cleanup_worker, daemon=True)
    thread.start()
    logger.info("Session cleanup thread started.")
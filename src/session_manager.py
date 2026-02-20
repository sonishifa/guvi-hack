import time
import asyncio
import logging
from typing import Dict, Set, Optional, List

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
            "creditCards": set(),
            "caseIds": set(),
            "policyNumbers": set(),
            "orderNumbers": set(),
        }
        self.red_flags: List[str] = []
        self.questions_asked: int = 0
        self.elicitation_attempts: int = 0
        self.agent_notes_history: List[str] = []
        self.final_output_payload: Optional[dict] = None

    def update_timestamp(self):
        """Update last activity time to now."""
        self.last_time = time.time()

    def add_intel(self, category: str, values):
        """Add extracted intelligence to the session."""
        if category in self.extracted_intel and values:
            if isinstance(values, (list, set)):
                self.extracted_intel[category].update(values)
            else:
                self.extracted_intel[category].add(values)

    def add_red_flags(self, flags: list):
        """Track red flags identified during conversation."""
        for flag in flags:
            if flag and flag not in self.red_flags:
                self.red_flags.append(flag)

    def to_final_output(self, session_id: str, total_messages: int, agent_notes: str = "") -> dict:
        """Build the final output JSON matching hackathon spec exactly."""
        duration = int(self.last_time - self.start_time)

        # Combine all agent notes from across turns
        all_notes = list(self.agent_notes_history)
        if agent_notes:
            all_notes.append(agent_notes)
        if self.red_flags:
            all_notes.append(f"Red flags identified: {', '.join(self.red_flags)}")
        combined_notes = " | ".join(all_notes) if all_notes else "Engaged scammer and extracted intelligence."

        # Calculate confidence based on detection signals
        confidence = 0.5
        if self.scam_detected:
            confidence = 0.75
        intel_count = sum(
            len(v) for k, v in self.extracted_intel.items()
            if k != "suspiciousKeywords"
        )
        if intel_count > 0:
            confidence = min(0.95, confidence + intel_count * 0.05)
        if len(self.red_flags) >= 3:
            confidence = min(0.98, confidence + 0.05)

        # Hackathon-spec flat structure
        return {
            "sessionId": session_id,
            "scamDetected": self.scam_detected,
            "scamType": self.scam_type or "unknown",
            "confidenceLevel": round(confidence, 2),
            "totalMessagesExchanged": total_messages,
            "engagementDurationSeconds": duration,
            "extractedIntelligence": {
                "phoneNumbers": list(self.extracted_intel.get("phoneNumbers", set())),
                "bankAccounts": list(self.extracted_intel.get("bankAccounts", set())),
                "upiIds": list(self.extracted_intel.get("upiIds", set())),
                "phishingLinks": list(self.extracted_intel.get("phishingLinks", set())),
                "emailAddresses": list(self.extracted_intel.get("emailAddresses", set())),
                "caseIds": list(self.extracted_intel.get("caseIds", set())),
                "policyNumbers": list(self.extracted_intel.get("policyNumbers", set())),
                "orderNumbers": list(self.extracted_intel.get("orderNumbers", set())),
            },
            "agentNotes": combined_notes,
        }


# In-memory session store
_sessions: Dict[str, SessionData] = {}

# Session timeout (1 hour)
SESSION_TIMEOUT = 3600


def get_session(session_id: str) -> SessionData:
    """
    Retrieve or create a session. If an existing session is older than
    SESSION_TIMEOUT, it is removed and a new one is created (lazy cleanup).
    """
    now = time.time()
    if session_id in _sessions:
        session = _sessions[session_id]
        if now - session.last_time > SESSION_TIMEOUT:
            logger.info(f"Session {session_id} expired (age > {SESSION_TIMEOUT}s). Removing.")
            del _sessions[session_id]
        else:
            return session
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
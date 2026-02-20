import asyncio
import logging
import random
from src import utils
from src import agent
from src.session_manager import get_session

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Fallback reply pools
# --------------------------------------------------------------------------- #
PASSIVE_REPLIES = [
    "I'm not sure I understand. Can you explain?",
    "Sorry, could you clarify that?",
    "I didn't quite get that. What do you mean?",
    "Hmm, can you rephrase?",
    "Not sure I follow. Can you explain differently?",
]

INJECTION_REPLIES = [
    "I'm not sure I understand. Can you explain normally?",
    "Sorry, I didn't catch that. Could you say it another way?",
    "Hmm, that doesn't make sense to me. Can you rephrase?",
]

AGENT_FALLBACK_REPLIES = [
    "Can you verify your ID first?",
    "I need to confirm this. What's your official number?",
    "This sounds suspicious. Can you give me more details?",
    "I'm not comfortable with that. Can you provide verification?",
]


# --------------------------------------------------------------------------- #
# Helper: check history for scam
# --------------------------------------------------------------------------- #
def check_history_for_scam(raw_history: list) -> tuple[bool, str]:
    for msg in raw_history:
        sender = msg.get("sender", "") if isinstance(msg, dict) else getattr(msg, "sender", "")
        text = msg.get("text", "") if isinstance(msg, dict) else getattr(msg, "text", "")
        if sender == "scammer":
            was_scam, cat = utils.detect_scam_keywords(text)
            hist_intel = any(len(v) > 0 for v in utils.extract_regex_data(text).values())
            if was_scam or hist_intel:
                return True, cat if was_scam else "Historical Pattern"
    return False, "Safe"


# --------------------------------------------------------------------------- #
# Extract intel from full conversation history
# --------------------------------------------------------------------------- #
def extract_intel_from_history(raw_history: list, session):
    """Scan ALL scammer messages in history and merge into session intel."""
    for msg in raw_history:
        sender = msg.get("sender", "") if isinstance(msg, dict) else getattr(msg, "sender", "")
        text = msg.get("text", "") if isinstance(msg, dict) else getattr(msg, "text", "")
        if sender == "scammer" and text:
            regex_data = utils.extract_regex_data(text)
            for key, values in regex_data.items():
                if key in session.extracted_intel and values:
                    session.add_intel(key, values)


# --------------------------------------------------------------------------- #
# Main processing function
# --------------------------------------------------------------------------- #
async def process_incoming_message(payload: dict) -> dict:
    """
    Core honeypot logic.
    Returns a response dict:
      - Always: {"status": "success", "reply": "..."}
      - Once scam detected: adds "finalOutput" with full analysis
    
    The evaluator logs every response as the "session log".
    After conversation ends, it reads finalOutput from the LAST response
    that contains it. So we include it on EVERY response once we have data.
    """
    msg_data = payload.get("message", {})
    current_text = msg_data.get("text", "") if isinstance(msg_data, dict) else str(msg_data)
    session_id = payload.get("sessionId", "unknown_session")
    raw_history = payload.get("conversationHistory", [])

    # Get or create session
    session = get_session(session_id)
    session.update_timestamp()
    session.turn_count += 1

    # --- STEP 0: PROMPT INJECTION DETECTION ---
    if utils.detect_injection(current_text):
        logger.warning(f"Injection attempt detected in session {session_id}")
        reply = random.choice(INJECTION_REPLIES)
        response = {"status": "success", "reply": reply}
        # Still include finalOutput if scam was detected in earlier turns
        if session.scam_detected:
            response["finalOutput"] = _build_final(session, session_id, raw_history)
        return response

    # --- 3-TIER SCAM DETECTION ---
    is_scam = False
    scam_category = "Safe"

    # Tier 1: Keywords (fast, free)
    is_scam, scam_category = utils.detect_scam_keywords(current_text)
    if is_scam:
        logger.info(f"Session {session_id}: scam via keywords ({scam_category})")

    # Tier 2: Regex patterns (fast, free)
    if not is_scam:
        regex_data = utils.extract_regex_data(current_text)
        if any(len(v) > 0 for v in regex_data.values()):
            is_scam, scam_category = True, "Financial Pattern"
            logger.info(f"Session {session_id}: scam via regex")

    # Tier 3: NLP via Gemini (slower, uses API quota)
    if not is_scam:
        try:
            is_scam, scam_category = await utils.detect_scam_intent_nlp(current_text)
            if is_scam:
                logger.info(f"Session {session_id}: scam via NLP ({scam_category})")
        except Exception as e:
            logger.error(f"NLP detection failed: {e}")

    # Tier 4: History escalation
    if not is_scam:
        hist_scam, hist_cat = check_history_for_scam(raw_history)
        if hist_scam:
            is_scam, scam_category = True, hist_cat
            logger.info(f"Session {session_id}: scam via history")

    # Update session state
    if is_scam and not session.scam_detected:
        session.scam_detected = True
        session.scam_type = scam_category

    # If not scam at all (and never was), return passive reply
    if not is_scam and not session.scam_detected:
        return {"status": "success", "reply": random.choice(PASSIVE_REPLIES)}

    # --- ACTIVATE AGENT (with key-rotation retry) ---
    ai_result = agent.get_agent_response(raw_history, current_text, session)

    # --- INTELLIGENCE EXTRACTION ---

    # 1) Regex on current message
    regex_data = utils.extract_regex_data(current_text)
    for key, values in regex_data.items():
        if key in session.extracted_intel and values:
            session.add_intel(key, values)

    # 2) Extract from ALL scammer messages in history
    extract_intel_from_history(raw_history, session)

    # 3) NLP entity extraction on current message
    try:
        nlp_entities = await utils.extract_entities_nlp(current_text)
        for key, values in nlp_entities.items():
            if isinstance(values, list) and values:
                session.add_intel(key, values)
    except Exception as e:
        logger.error(f"NLP entity extraction failed: {e}")

    # 4) Track agent intelligence outputs
    session.add_intel("suspiciousKeywords", ai_result.get("suspicious_keywords", []))
    session.add_red_flags(ai_result.get("red_flags", []))
    session.questions_asked += ai_result.get("questions_asked", 0)
    session.elicitation_attempts += 1

    # Store agent notes
    notes = ai_result.get("agent_notes", "")
    if notes:
        session.agent_notes_history.append(notes)

    # --- BUILD RESPONSE ---
    reply = ai_result.get("reply", random.choice(AGENT_FALLBACK_REPLIES))
    portal_response = {"status": "success", "reply": reply}

    # Include finalOutput on EVERY response once scam is detected.
    # The evaluator reads it from the session log (= record of all API responses).
    # The LAST response containing finalOutput is what gets scored.
    final_output = _build_final(session, session_id, raw_history, ai_result)
    session.final_output_payload = final_output
    portal_response["finalOutput"] = final_output

    return portal_response


def _build_final(session, session_id: str, raw_history: list, ai_result: dict = None) -> dict:
    """Build the final output payload matching hackathon spec."""
    # Total messages = all messages in history + current incoming message
    total_messages = len(raw_history) + 1
    agent_notes = ""
    if ai_result:
        agent_notes = ai_result.get("agent_notes", "Engaged scammer and extracted intelligence.")
    return session.to_final_output(
        session_id=session_id,
        total_messages=total_messages,
        agent_notes=agent_notes,
    )
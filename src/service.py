import asyncio
import requests
import os
import logging
import random
from src import utils
from src import agent
from src.session_manager import get_session

# Set up logging
logger = logging.getLogger(__name__)

CALLBACK_URL = os.getenv("CALLBACK_URL")  # May be None

# Varied fallback replies for non-scam and error cases
PASSIVE_REPLIES = [
    "I'm not sure I understand. Can you explain?",
    "Sorry, could you clarify that?",
    "I didn't quite get that. What do you mean?",
    "Hmm, can you rephrase?",
    "Not sure I follow. Can you explain differently?"
]

INJECTION_REPLIES = [
    "I'm not sure I understand. Can you explain normally?",
    "Sorry, I didn't catch that. Could you say it another way?",
    "Hmm, that doesn't make sense to me. Can you rephrase?"
]

AGENT_FALLBACK_REPLIES = [
    "Can you verify your ID first?",
    "I need to confirm this. What's your official number?",
    "This sounds suspicious. Can you give me more details?",
    "I'm not comfortable with that. Can you provide verification?"
]

# -----------------------------------------------------------------------------
# Helper: check history for scam (abstracted from main flow)
# -----------------------------------------------------------------------------
def check_history_for_scam(raw_history: list) -> tuple[bool, str]:
    """
    Examine conversation history to see if any previous scammer message
    was flagged as scam (by keywords or regex). Returns (is_scam, category).
    """
    for msg in raw_history:
        sender = msg.get("sender", "") if isinstance(msg, dict) else getattr(msg, "sender", "")
        text = msg.get("text", "") if isinstance(msg, dict) else getattr(msg, "text", "")
        if sender == "scammer":
            was_scam, cat = utils.detect_scam_keywords(text)
            hist_intel = any(len(v) > 0 for v in utils.extract_regex_data(text).values())
            if was_scam or hist_intel:
                return True, cat if was_scam else "Historical Pattern"
    return False, "Safe"

# -----------------------------------------------------------------------------
# Async callback functions
# -----------------------------------------------------------------------------
async def send_callback_async(payload: dict):
    """Send final output to callback URL in a thread to avoid blocking."""
    if not CALLBACK_URL:
        logger.info("No CALLBACK_URL set, skipping callback.")
        return
    try:
        await asyncio.to_thread(requests.post, CALLBACK_URL, json=payload, timeout=5)
        logger.info(f"Callback sent to {CALLBACK_URL}")
    except Exception as e:
        logger.error(f"Callback failed: {e}")

async def delayed_callback(session_id: str, payload: dict, delay: int = 10):
    """Wait for delay seconds, then send callback if not already sent."""
    try:
        await asyncio.sleep(delay)
        session = get_session(session_id)
        if session and not session.callback_sent:
            await send_callback_async(payload)
            session.callback_sent = True
    except asyncio.CancelledError:
        logger.info(f"Callback cancelled for session {session_id}")
        raise

# -----------------------------------------------------------------------------
# Main processing function
# -----------------------------------------------------------------------------
async def process_incoming_message(payload: dict) -> tuple[dict, None]:
    """Core logic. Returns portal response and always None for callback payload."""
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
        return {"status": "success", "reply": reply}, None

    # --- 3-TIER SCAM DETECTION ---
    is_scam = False
    scam_category = "Safe"

    # Tier 1: Keywords
    is_scam, scam_category = utils.detect_scam_keywords(current_text)
    if is_scam:
        logger.info(f"Session {session_id}: scam detected via keywords ({scam_category})")

    # Tier 2: Regex (only if not already scam)
    if not is_scam:
        regex_data = utils.extract_regex_data(current_text)
        if any(len(v) > 0 for v in regex_data.values()):
            is_scam, scam_category = True, "Financial Pattern"
            logger.info(f"Session {session_id}: scam detected via regex")

    # Tier 3: NLP (only if still not scam)
    if not is_scam:
        try:
            is_scam, scam_category = await utils.detect_scam_intent_nlp(current_text)
            if is_scam:
                logger.info(f"Session {session_id}: scam detected via NLP ({scam_category})")
        except Exception as e:
            logger.error(f"NLP detection failed for session {session_id}: {e}")

    # History escalation (if still not scam)
    if not is_scam:
        hist_scam, hist_cat = check_history_for_scam(raw_history)
        if hist_scam:
            is_scam, scam_category = True, hist_cat
            logger.info(f"Session {session_id}: scam detected via history escalation")

    # Update session if scam detected
    if is_scam and not session.scam_detected:
        session.scam_detected = True
        session.scam_type = scam_category

    # If not scam, return passive reply
    if not is_scam:
        reply = random.choice(PASSIVE_REPLIES)
        return {"status": "success", "reply": reply}, None

    # --- ACTIVATE AGENT (with retry logic) ---
    ai_result = None
    max_retries = 2
    for attempt in range(max_retries):
        try:
            ai_result = agent.get_agent_response(raw_history, current_text, session)
            break
        except Exception as e:
            logger.error(f"Agent call attempt {attempt+1} failed: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)  # exponential backoff
            else:
                # Final fallback
                ai_result = {
                    "reply": random.choice(AGENT_FALLBACK_REPLIES),
                    "agent_notes": f"Agent error after {max_retries} attempts: {e}",
                    "suspicious_keywords": []
                }

    # --- INTELLIGENCE EXTRACTION (regex + NLP) ---
    regex_data = utils.extract_regex_data(current_text)
    for key in ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses",
                "aadhaarNumbers", "panNumbers", "creditCards"]:
        if key in regex_data:
            session.add_intel(key, regex_data[key])

    # NLP entity extraction (with its own error handling)
    try:
        nlp_entities = await utils.extract_entities_nlp(current_text)
        for key, values in nlp_entities.items():
            if isinstance(values, list):
                session.add_intel(key, values)
    except Exception as e:
        logger.error(f"NLP entity extraction failed for session {session_id}: {e}")

    # Add suspicious keywords from agent
    session.add_intel("suspiciousKeywords", ai_result.get("suspicious_keywords", []))

    # --- PREPARE PORTAL RESPONSE ---
    portal_response = {
        "status": "success",
        "reply": ai_result.get("reply", random.choice(AGENT_FALLBACK_REPLIES))
    }

    # --- CHECK IF FINAL OUTPUT SHOULD BE GENERATED ---
    total_messages = len(raw_history) + 1
    has_intel = any(len(session.extracted_intel[k]) > 0 for k in
                    ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks",
                     "emailAddresses", "aadhaarNumbers", "panNumbers", "creditCards"])

    generate_final = False
    if session.scam_detected and not session.callback_sent:
        if has_intel:
            generate_final = True
            logger.info(f"Session {session_id}: scheduling callback (has intel)")
        elif session.turn_count >= 10:
            generate_final = True
            logger.info(f"Session {session_id}: scheduling callback (max turns reached)")

    if generate_final:
        final_output = session.to_final_output(
            total_messages=total_messages,
            agent_notes=ai_result.get("agent_notes", "Engaged scammer.")
        )
        session.final_output_payload = final_output

        # Cancel any previously scheduled callback
        if session.pending_callback_task and not session.pending_callback_task.done():
            session.pending_callback_task.cancel()

        # Schedule new callback after 10 seconds (only if CALLBACK_URL is set)
        if CALLBACK_URL:
            task = asyncio.create_task(delayed_callback(session_id, final_output, 10))
            session.pending_callback_task = task
        else:
            logger.info(f"No CALLBACK_URL set for session {session_id}. Final output stored for GET.")
    else:
        logger.debug(f"Session {session_id}: not ready for callback (scam={session.scam_detected}, intel={has_intel})")

    return portal_response, None
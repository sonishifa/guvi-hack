import asyncio
import requests
import os
from src import utils
from src import agent
from src.session_manager import get_session

CALLBACK_URL = os.getenv("CALLBACK_URL")  # May be None

async def send_callback_async(payload: dict):
    """Send final output to callback URL in a thread to avoid blocking."""
    if not CALLBACK_URL:
        print("⚠️ No CALLBACK_URL set, skipping callback.")
        return
    try:
        # Run the blocking POST in a thread
        await asyncio.to_thread(requests.post, CALLBACK_URL, json=payload, timeout=5)
        print(f"✅ Callback sent to {CALLBACK_URL}")
    except Exception as e:
        print(f"❌ Callback failed: {e}")

async def delayed_callback(session_id: str, payload: dict, delay: int = 10):
    """Wait for delay seconds, then send callback if not already sent."""
    try:
        await asyncio.sleep(delay)
        session = get_session(session_id)
        if session and not session.callback_sent:
            await send_callback_async(payload)
            session.callback_sent = True
    except asyncio.CancelledError:
        # Task was cancelled because a new message arrived – do nothing
        print(f"⏸️ Callback cancelled for session {session_id}")
        raise

async def process_incoming_message(payload: dict) -> tuple[dict, None]:
    """Core logic. Returns portal response and always None for callback payload
       (since callback is now handled via background task)."""
    msg_data = payload.get("message", {})
    current_text = msg_data.get("text", "") if isinstance(msg_data, dict) else str(msg_data)
    session_id = payload.get("sessionId", "unknown_session")
    raw_history = payload.get("conversationHistory", [])

    # Get or create session
    session = get_session(session_id)
    session.update_timestamp()
    session.turn_count += 1

    # --- 3-TIER SCAM DETECTION ---
    is_scam = False
    scam_category = "Safe"

    # Tier 1: Keywords
    is_scam, scam_category = utils.detect_scam_keywords(current_text)

    # Tier 2: Regex
    if not is_scam:
        regex_data = utils.extract_regex_data(current_text)
        if any(len(v) > 0 for v in regex_data.values()):
            is_scam, scam_category = True, "Financial Pattern"

    # Tier 3: NLP
    if not is_scam:
        is_scam, scam_category = await utils.detect_scam_intent_nlp(current_text, agent.client)

    # History escalation
    if not is_scam:
        for msg in raw_history:
            sender = msg.get("sender", "") if isinstance(msg, dict) else getattr(msg, "sender", "")
            text = msg.get("text", "") if isinstance(msg, dict) else getattr(msg, "text", "")
            if sender == "scammer":
                was_scam, _ = utils.detect_scam_keywords(text)
                hist_intel = any(len(v) > 0 for v in utils.extract_regex_data(text).values())
                if was_scam or hist_intel:
                    is_scam, scam_category = True, "Historical Pattern"
                    break

    if is_scam and not session.scam_detected:
        session.scam_detected = True
        session.scam_type = scam_category

    # If not scam, return passive reply
    if not is_scam:
        return {"status": "success", "reply": "I'm not sure I understand. Can you explain?"}, None

    # --- ACTIVATE AGENT ---
    ai_result = agent.get_agent_response(raw_history, current_text, session)

    # --- INTELLIGENCE EXTRACTION (regex + NLP) ---
    regex_data = utils.extract_regex_data(current_text)
    for key in ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses"]:
        if key in regex_data:
            session.add_intel(key, regex_data[key])

    nlp_entities = await utils.extract_entities_nlp(current_text, agent.client)
    for key, values in nlp_entities.items():
        if isinstance(values, list):
            session.add_intel(key, values)

    session.add_intel("suspiciousKeywords", ai_result.get("suspicious_keywords", []))

    # --- PREPARE PORTAL RESPONSE ---
    portal_response = {
        "status": "success",
        "reply": ai_result.get("reply", "Can you verify your bank ID first?")
    }

    # --- CHECK IF FINAL OUTPUT SHOULD BE GENERATED ---
    total_messages = len(raw_history) + 1
    has_intel = any(len(session.extracted_intel[k]) > 0 for k in
                    ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses"])
    if (session.scam_detected and not session.callback_sent and
        ((has_intel and session.turn_count >= 5) or session.turn_count >= 10)):

        # Build final output and store in session
        final_output = session.to_final_output(
            total_messages=total_messages,
            agent_notes=ai_result.get("agent_notes", "Engaged scammer.")
        )
        session.final_output_payload = final_output

        # --- IDLE TIMEOUT SCHEDULING ---
        # Cancel any previously scheduled callback for this session
        if session.pending_callback_task and not session.pending_callback_task.done():
            session.pending_callback_task.cancel()

        # Schedule new callback after 10 seconds (only if CALLBACK_URL is set)
        if CALLBACK_URL:
            task = asyncio.create_task(delayed_callback(session_id, final_output, 10))
            session.pending_callback_task = task
        else:
            print(f"ℹ️ No CALLBACK_URL set for session {session_id}. Final output stored for GET.")
    else:
        # Not yet ready – do nothing
        pass

    return portal_response, None
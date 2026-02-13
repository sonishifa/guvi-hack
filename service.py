from schemas import (
    IncomingRequest, AgentResponse, EngagementMetrics, 
    IntelligenceData, FinalCallbackPayload, Message
)
import utils
import agent
import requests 
from datetime import datetime, timezone

CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

async def process_incoming_message(payload: dict) -> tuple[dict, FinalCallbackPayload | None]:
    msg_data = payload.get("message", {})
    current_text = msg_data.get("text", "") if isinstance(msg_data, dict) else str(msg_data)
    session_id = payload.get("sessionId", "unknown_session")
    raw_history = payload.get("conversationHistory", [])
    
    # --- STEP 1: 3-TIER DEFENSE ---
    
    # Tier 1: Keywords
    is_scam, scam_category = utils.detect_scam_keywords(current_text)

    # Tier 2: Regex (Pattern Detection)
    if not is_scam:
        regex_data = utils.extract_regex_data(current_text)
        if any(len(v) > 0 for v in regex_data.values()):
            is_scam, scam_category = True, "Financial Pattern"

    # Tier 3: NLP (Intent Analysis) - The new "Brain"
    if not is_scam:
        is_scam, scam_category = await utils.detect_scam_intent_nlp(current_text, agent.client)

    # --- STEP 1.2: HISTORY ESCALATION ---
    if not is_scam:
        for msg in raw_history:
            m_sender = msg.get("sender", "") if isinstance(msg, dict) else getattr(msg, "sender", "")
            m_text = msg.get("text", "") if isinstance(msg, dict) else getattr(msg, "text", "")
            if m_sender == "scammer":
                was_scam, cat = utils.detect_scam_keywords(m_text)
                hist_intel = any(len(v) > 0 for v in utils.extract_regex_data(m_text).values())
                if was_scam or hist_intel:
                    is_scam, scam_category = True, cat if was_scam else "Historical Pattern"
                    break

    # --- STEP 2: PASSIVE MODE ---
    if not is_scam:
        return {"status": "success", "reply": "I'm not sure I understand. Can you explain?"}, None

    # --- STEP 3: ACTIVATE AGENT ---
    ai_result = agent.get_agent_response(raw_history, current_text)
    
    # --- STEP 4-7: INTELLIGENCE & CALLBACK ---
    aggregated_data = utils.aggregate_intelligence(raw_history, current_text)
    final_intel = IntelligenceData(
        bankAccounts=aggregated_data["bankAccounts"],
        upiIds=aggregated_data["upiIds"],
        phishingLinks=aggregated_data["phishingLinks"],
        phoneNumbers=aggregated_data["phoneNumbers"],
        suspiciousKeywords=ai_result.get("suspicious_keywords", [])
    )

    total_messages = len(raw_history) + 1 
    portal_response = {"status": "success", "reply": ai_result.get("reply", "Can you verify your bank ID first?")}

    callback_payload = None
    has_intel = any(len(getattr(final_intel, k)) > 0 for k in ["bankAccounts", "upiIds", "phoneNumbers", "phishingLinks"])

    if has_intel or total_messages >= 15:
        detailed_notes = ai_result.get("agent_notes", f"Scam detected: {scam_category}. Turns: {total_messages}")
        callback_payload = FinalCallbackPayload(
            sessionId=session_id, scamDetected=True, totalMessagesExchanged=total_messages,
            extractedIntelligence=final_intel, agentNotes=detailed_notes
        )

    return portal_response, callback_payload

def send_callback_background(payload: FinalCallbackPayload):
    try:
        requests.post(CALLBACK_URL, json=payload.dict(), timeout=5)
        print(f"✅ Callback Sent")
    except Exception as e:
        print(f"❌ Callback Failed: {e}")
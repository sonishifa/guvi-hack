from schemas import (
    IncomingRequest, AgentResponse, EngagementMetrics, 
    IntelligenceData, FinalCallbackPayload, Message
)
import utils
import agent
import requests 
from datetime import datetime, timezone

# Official Evaluation Endpoint from Rule 12
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def parse_timestamp(ts_input) -> datetime:
    """Standardizes various timestamp formats into ISO-8601 for the judges."""
    try:
        if isinstance(ts_input, (int, float)):
            seconds = ts_input / 1000.0 if ts_input > 1e10 else ts_input
            return datetime.fromtimestamp(seconds, timezone.utc)
        
        ts_string = str(ts_input)
        if ts_string.endswith('Z'):
            ts_string = ts_string[:-1] + '+00:00'
        
        dt = datetime.fromisoformat(ts_string)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)

async def process_incoming_message(payload: dict) -> tuple[dict, FinalCallbackPayload | None]:
    """
    Core logic: Returns Rule 8 response for the portal 
    and prepares the Rule 12 callback for the judges.
    """
    
    # 1. EXTRACT DATA
    msg_data = payload.get("message", {})
    current_text = msg_data.get("text", "") if isinstance(msg_data, dict) else str(msg_data)
    current_timestamp = msg_data.get("timestamp", datetime.now(timezone.utc).isoformat())

    session_id = payload.get("sessionId", "unknown_session")
    raw_history = payload.get("conversationHistory", [])
    
    # --- STEP 1: SCAM DETECTION ---
    is_scam, scam_category = utils.detect_scam_keywords(current_text)
    if not is_scam and len(raw_history) > 0:
        is_scam = True # Continue engagement if already started

    # --- STEP 2: PASSIVE MODE (Safe Messages) ---
    if not is_scam:
        return {"status": "success", "reply": "I'm not sure I understand. Can you explain?"}, None

    # --- STEP 3: ACTIVATE AGENT ---
    ai_result = agent.get_agent_response(raw_history, current_text)
    
    # --- STEP 4: INTELLIGENCE EXTRACTION (FULL HISTORY) ---
    # We do NOT trim history to ensure Rule 12 quality
    aggregated_data = utils.aggregate_intelligence(raw_history, current_text)
    
    final_intel = IntelligenceData(
        bankAccounts=aggregated_data["bankAccounts"],
        upiIds=aggregated_data["upiIds"],
        phishingLinks=aggregated_data["phishingLinks"],
        phoneNumbers=aggregated_data["phoneNumbers"],
        suspiciousKeywords=ai_result.get("suspicious_keywords", [])
    )

    # --- STEP 5: CALCULATE TOTAL MESSAGES ---
    total_messages = len(raw_history) + 1 

    # --- STEP 6: AGENT OUTPUT (RULE 8 COMPLIANT) ---
    # Return ONLY status and reply to turn the portal GREEN
    portal_response = {
        "status": "success",
        "reply": ai_result.get("reply", "Can you verify your bank ID first?")
    }

    # --- STEP 7: THE RULE 12 TRIGGER ---
    callback_payload = None

    # Logic: Only send the final result if we've actually caught data 
    # OR we've reached a deep engagement (e.g., 15+ turns)
    has_intel = (
        len(final_intel.bankAccounts) > 0 or 
        len(final_intel.upiIds) > 0 or 
        len(final_intel.phoneNumbers) > 0
    )

    if has_intel or total_messages >= 15:
        callback_payload = FinalCallbackPayload(
            sessionId=session_id,
            scamDetected=True,
            totalMessagesExchanged=total_messages,
            extractedIntelligence=final_intel,
            agentNotes=ai_result.get("agent_notes", "Suspected banking scam.")
        )

    return portal_response, callback_payload

def send_callback_background(payload: FinalCallbackPayload):
    """Executes the mandatory Section 12 callback."""
    try:
        data = payload.dict()
        response = requests.post(CALLBACK_URL, json=data, timeout=5)
        print(f"✅ Section 12 Result Sent: {response.status_code}")
    except Exception as e:
        print(f"❌ Callback Failed: {e}")
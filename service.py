from schemas import IncomingRequest, AgentResponse, EngagementMetrics, IntelligenceData, FinalCallbackPayload, Message
import utils
import agent
import requests 
from datetime import datetime, timezone

CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def parse_timestamp(ts_input) -> datetime:
    """
    Robust Timestamp Parser (Handles Int, Float, String)
    """
    try:
        # 1. Handle Unix Timestamp (Int/Float)
        if isinstance(ts_input, (int, float)):
            # Check if milliseconds (13 digits) or seconds (10 digits)
            seconds = ts_input / 1000.0 if ts_input > 1e10 else ts_input
            return datetime.fromtimestamp(seconds, timezone.utc)

        # 2. Handle ISO String
        ts_string = str(ts_input)
        if ts_string.endswith('Z'):
            ts_string = ts_string[:-1] + '+00:00'
        
        dt = datetime.fromisoformat(ts_string)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        # Absolute Fallback
        return datetime.now(timezone.utc)

async def process_incoming_message(payload: dict) -> tuple[AgentResponse, FinalCallbackPayload | None]:
    
    # --- 1. SAFE DATA EXTRACTION ---
    # Handle 'message' being a string or a dict
    msg_data = payload.get("message", {})
    if isinstance(msg_data, str): 
        current_text = msg_data
        current_timestamp = datetime.now(timezone.utc).isoformat()
    else:
        current_text = msg_data.get("text", "")
        current_timestamp = msg_data.get("timestamp", datetime.now(timezone.utc).isoformat())

    session_id = payload.get("sessionId", "unknown_session")
    
    # Keep history as List of Dicts (safest for agent.py)
    raw_history = payload.get("conversationHistory", [])
    
    # --- STEP 1: SCAM DETECTION ---
    is_scam = False
    scam_category = "None"
    
    # If we have history, we assume the conversation is ongoing and suspicious
    if len(raw_history) > 0:
        is_scam = True
        scam_category = "Ongoing Interaction"
    else:
        # First message: Check keywords
        is_scam, scam_category = utils.detect_scam_keywords(current_text)

    # --- STEP 2: PASSIVE MODE (Safe User) ---
    if not is_scam:
        return AgentResponse(
            status="success",  
            scamDetected=False,
            engagementMetrics=EngagementMetrics(engagementDurationSeconds=0, totalMessagesExchanged=0),
            extractedIntelligence=IntelligenceData(),
            agentNotes="Status: Monitoring. No scam detected.", 
            reply=None
        ), None

    # --- STEP 3: ACTIVATE AGENT ---
    # Pass the raw history (list of dicts) to the agent
    ai_result = agent.get_agent_response(raw_history, current_text)
    
    # --- STEP 4: INTELLIGENCE ---
    regex_data = utils.extract_regex_data(current_text)
    
    final_intel = IntelligenceData(
        bankAccounts=regex_data["bankAccounts"],
        upiIds=regex_data["upiIds"],
        phishingLinks=regex_data["phishingLinks"],
        phoneNumbers=regex_data["phoneNumbers"],
        suspiciousKeywords=ai_result.get("suspicious_keywords", [])
    )

    # --- STEP 5: METRICS ---
    total_messages = len(raw_history) + 1
    duration = 0
    
    if len(raw_history) > 0:
        first_msg = raw_history[0]
        # Robust Access to timestamp in history
        if isinstance(first_msg, dict):
            first_ts_val = first_msg.get("timestamp")
        else:
            first_ts_val = getattr(first_msg, "timestamp", datetime.now())
            
        first_msg_ts = parse_timestamp(first_ts_val)
        current_msg_ts = parse_timestamp(current_timestamp)
        
        delta = current_msg_ts - first_msg_ts
        duration = int(delta.total_seconds())

    # --- STEP 6: CONSTRUCT RESPONSE ---
    response_obj = AgentResponse(
        status="success", 
        scamDetected=True,
        engagementMetrics=EngagementMetrics(
            engagementDurationSeconds=duration, 
            totalMessagesExchanged=total_messages
        ),
        extractedIntelligence=final_intel,
        agentNotes=f"Status: Active. Category: {scam_category}. Agent Thought: {ai_result.get('agent_notes', 'N/A')}",
        reply=ai_result.get("reply")
    )

    # --- STEP 7: CALLBACK LOGIC ---
    callback_payload = None
    
    # Trigger callback if we found specific intel OR if the conversation is long enough
    has_intel = (len(final_intel.bankAccounts) > 0 or 
                 len(final_intel.upiIds) > 0 or
                 len(final_intel.phoneNumbers) > 0)
                 
    if has_intel or total_messages > 10:
        callback_payload = FinalCallbackPayload(
            sessionId=session_id,
            scamDetected=True,
            totalMessagesExchanged=total_messages,
            extractedIntelligence=final_intel,
            agentNotes=response_obj.agentNotes
        )

    return response_obj, callback_payload

def send_callback_background(payload: FinalCallbackPayload):
    try:
        data = payload.dict()
        requests.post(CALLBACK_URL, json=data, timeout=5)
    except Exception as e:
        print(f"Callback Error: {e}")
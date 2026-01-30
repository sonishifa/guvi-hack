from schemas import IncomingRequest, AgentResponse, EngagementMetrics, IntelligenceData, FinalCallbackPayload
import utils
import agent
import requests 
from datetime import datetime, timezone

CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def parse_timestamp(ts_string: str) -> datetime:
    try:
        if ts_string.endswith('Z'):
            ts_string = ts_string[:-1] + '+00:00'
        dt = datetime.fromisoformat(ts_string)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)

async def process_incoming_message(payload: dict) -> tuple[AgentResponse, FinalCallbackPayload | None]:
    # 1. EXTRACT DATA SAFELY (From Dictionary)
    msg_data = payload.get("message", {})
    if isinstance(msg_data, str): 
        current_text = msg_data
        current_timestamp = datetime.now(timezone.utc).isoformat()
    else:
        current_text = msg_data.get("text", "")
        current_timestamp = msg_data.get("timestamp", datetime.now(timezone.utc).isoformat())

    history = payload.get("conversationHistory", [])
    session_id = payload.get("sessionId", "unknown_session")
    
    # --- STEP 1: SCAM DETECTION ---
    is_scam = False
    scam_category = "None"
    
    if len(history) > 0:
        is_scam = True
        scam_category = "Ongoing Interaction"
    else:
        is_scam, scam_category = utils.detect_scam_keywords(current_text)

    # --- STEP 2: PASSIVE MODE ---
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
    # History is a list of Dicts, Agent expects Dicts -> MATCH!
    ai_result = agent.get_agent_response(history, current_text)
    
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
    total_messages = len(history) + 1
    duration = 0
    
    if len(history) > 0:
        first_msg = history[0]
        # Robust check for first timestamp
        first_ts_str = first_msg.get("timestamp") if isinstance(first_msg, dict) else str(datetime.now())
        
        first_msg_ts = parse_timestamp(str(first_ts_str))
        current_msg_ts = parse_timestamp(current_timestamp)
        delta = current_msg_ts - first_msg_ts
        duration = int(delta.total_seconds())

    # --- STEP 6: RESPONSE ---
    response_obj = AgentResponse(
        status="success", 
        scamDetected=True,
        engagementMetrics=EngagementMetrics(
            engagementDurationSeconds=duration, 
            totalMessagesExchanged=total_messages
        ),
        extractedIntelligence=final_intel,
        agentNotes=f"Status: Active. Category: {scam_category}. {ai_result.get('agent_notes', '')}",
        reply=ai_result.get("reply")
    )

    # --- STEP 7: CALLBACK ---
    callback_payload = None
    found_info = (len(final_intel.bankAccounts) > 0 or len(final_intel.upiIds) > 0 or len(final_intel.phoneNumbers) > 0)
    
    if found_info or total_messages > 10:
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
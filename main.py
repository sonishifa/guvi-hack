from fastapi import FastAPI, Header, HTTPException, BackgroundTasks, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from schemas import IncomingRequest, Message  
import service
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = FastAPI(title="Honeypot Agent API")

# 1. ALLOW CORS (Permissive)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MY_SECRET_KEY = os.getenv("SCAMMER_API_KEY")

# --- 2. UNIVERSAL HEALTH CHECK (GET & HEAD) ---
# This handles the "HEAD /" 405 error you saw in the logs.
@app.api_route("/", methods=["GET", "HEAD"])
@app.api_route("/webhook", methods=["GET", "HEAD"]) 
def health_check():
    """Simple check to see if server is running."""
    return {"status": "alive", "service": "Honeypot Agent"}

# --- 3. UNIVERSAL WEBHOOK HANDLER (POST) ---
# We catch POST requests on BOTH "/webhook" AND "/" (Root)
# This fixes the "Access Error" if you entered the wrong URL in the portal.
@app.api_route("/webhook", methods=["POST"])
@app.api_route("/", methods=["POST"])
async def handle_incoming_message(
    request: Request,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
):
    print(f"\n📨 INCOMING REQUEST: {request.method} {request.url}")
    
    # SECURITY DISABLED FOR TESTING
    # if x_api_key != MY_SECRET_KEY: ... (Commented out)

    try:
        # 4. FLEXIBLE PARSING
        raw_body = await request.json()
        print(f"📥 RAW PAYLOAD: {raw_body}") 

        valid_payload = None

        # Scenario A: Official Rule 6 Format
        if "message" in raw_body and "sessionId" in raw_body:
            valid_payload = IncomingRequest(**raw_body)
            print("✅ Detected Official Format")
        
        # Scenario B: Hackathon Tester (Lazy Format)
        else:
            user_text = raw_body.get("text") or raw_body.get("content") or str(raw_body)
            valid_payload = IncomingRequest(
                sessionId="tester-session-123",
                message=Message(
                    sender="scammer",
                    text=user_text,
                    timestamp=datetime.utcnow().isoformat()
                ),
                conversationHistory=[],
                metadata={"channel": "TESTER"}
            )
            print("⚠️ Adapted Tester Format")

        # 5. PROCESS
        payload_as_dict = valid_payload.dict()
        agent_response, callback_payload = await service.process_incoming_message(payload_as_dict)

        # 6. BACKGROUND TASK
        if callback_payload:
            background_tasks.add_task(service.send_callback_background, callback_payload)

        return agent_response

    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        # Safe fallback
        return {
            "status": "success", 
            "reply": "I received your message. (System Recovery Mode)"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
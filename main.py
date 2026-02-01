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

@app.api_route("/webhook", methods=["POST"])
@app.api_route("/", methods=["POST"])
async def handle_incoming_message(
    request: Request,
    background_tasks: BackgroundTasks
):
    try:
        raw_body = await request.json()
        
        # 1. Flexible parsing logic stays the same
        if "message" in raw_body and "sessionId" in raw_body:
            valid_payload = IncomingRequest(**raw_body)
        else:
            # Fallback for simple testers
            user_text = raw_body.get("text") or "Hello"
            valid_payload = IncomingRequest(
                sessionId="tester-123",
                message=Message(sender="scammer", text=user_text, timestamp=datetime.utcnow().isoformat()),
                conversationHistory=[]
            )

        # 2. Process through service
        payload_as_dict = valid_payload.dict()
        agent_response, callback_payload = await service.process_incoming_message(payload_as_dict)

        # 3. RULE 12: Mandatory Background Callback
        if callback_payload:
            background_tasks.add_task(service.send_callback_background, callback_payload)

        # 4. RULE 8: Return ONLY what the portal expects
        return {
            "status": "success",
            "reply": agent_response.reply
        }

    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        return {"status": "success", "reply": "I'm checking on that for you."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
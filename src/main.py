import logging
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from src import service
from src.session_manager import get_session, start_cleanup_thread
import os
from dotenv import load_dotenv
import json
from datetime import datetime, timezone

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

app = FastAPI(title="Honeyshield Agent API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MY_SECRET_KEY = os.getenv("SCAMMER_API_KEY")

# Start background session cleanup
start_cleanup_thread()

@app.api_route("/", methods=["GET", "POST", "HEAD"])
@app.api_route("/webhook", methods=["GET", "POST", "HEAD"])
async def handle_universal_request(request: Request, background_tasks: BackgroundTasks):
    # Authentication
    headers = {k.lower(): v for k, v in request.headers.items()}
    incoming_key = headers.get("x-api-key")
    if request.method == "POST" and incoming_key != MY_SECRET_KEY:
        logger.warning(f"Unauthorized access attempt with key {incoming_key}")
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid API Key")

    # Health checks
    if request.method in ["GET", "HEAD"]:
        return {"status": "alive", "service": "Honeyshield Agent"}

    # Process POST
    try:
        body_bytes = await request.body()
        raw_body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}

        sanitized_payload = {
            "sessionId": raw_body.get("sessionId", "portal-session"),
            "message": raw_body.get("message", {
                "sender": "scammer",
                "text": raw_body.get("text", "Hello"),
                "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000)
            }),
            "conversationHistory": raw_body.get("conversationHistory", []),
            "metadata": raw_body.get("metadata", {})
        }

        portal_response, _ = await service.process_incoming_message(sanitized_payload)
        return portal_response

    except Exception as e:
        logger.error(f"Unhandled error: {e}")
        return {"status": "success", "reply": "Connection is a bit slow, hold on..."}

@app.get("/final/{session_id}")
async def get_final_output(session_id: str, request: Request):
    headers = {k.lower(): v for k, v in request.headers.items()}
    incoming_key = headers.get("x-api-key")
    if incoming_key != MY_SECRET_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid API Key")

    session = get_session(session_id)
    if session and session.final_output_payload:
        return session.final_output_payload
    raise HTTPException(status_code=404, detail="Final output not available")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
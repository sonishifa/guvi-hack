from google import genai
from google.genai import types
import os
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

GOOGLE_API_KEY = os.getenv("GEMINI_API_KEY")

if not GOOGLE_API_KEY:
    raise ValueError(" CRITICAL: GEMINI_API_KEY is missing from .env")

# Initialize Client
client = genai.Client(api_key=GOOGLE_API_KEY)

def get_agent_response(history: list, current_text: str) -> dict:
    """
    Production Logic:
    - Connects to Gemini 2.5 using the V1 SDK.
    - If Gemini fails, this function CRASHES (Raises Exception).
    - This allows the main server to catch the error and return a 503 status.
    """
    
    # 1. Format History for the Prompt
    history_text = ""
    for msg in history:
        sender = msg.get("sender", "unknown")
        text = msg.get("text", "")
        role = "Scammer" if sender == "scammer" else "User (You)"
        history_text += f"{role}: {text}\n"

    # 2. The Master Prompt (Skeptical Persona)
    prompt = f"""
    You are a sharp, skeptical user who has been scammed before. 
    You are interested in the offer, but you don't trust the sender yet.

    STYLE GUIDE:
    - Be blunt. Ask: "How do I know this is real?"
    - Demand proof. "Send me a photo of your ID card first."
    - If they ask for money, say: "I can pay, but I need to verify your account first. Send the UPI again."
    - Your goal is to make them send as much 'proof' as possible.
    
    CONVERSATION HISTORY:
    {history_text}
    
    LATEST MESSAGE FROM SCAMMER:
    "{current_text}"
    
    TASK:
    Analyze the message and generate a reply in JSON format.
    
    JSON SCHEMA:
    {{
        "reply": "text response to scammer",
        "agent_notes": "internal thought",
        "suspicious_keywords": ["list", "of", "words"]
    }}
    """

    # 3. Call Gemini (Using your confirmed model)
    response = client.models.generate_content(
        model='gemini-2.5-flash-lite', 
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type='application/json'
        )
    )
    
    # 4. Parse Result
    if not response.text:
        raise ValueError("Gemini returned an empty response.")
        
    return json.loads(response.text)
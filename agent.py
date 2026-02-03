from google import genai
from google.genai import types
import os
import json
import re
from dotenv import load_dotenv

load_dotenv()

GOOGLE_API_KEY = os.getenv("GEMINI_API_KEY")

if not GOOGLE_API_KEY:
    raise ValueError("CRITICAL: GEMINI_API_KEY is missing")

client = genai.Client(api_key=GOOGLE_API_KEY)

def clean_json_string(text):
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return match.group(0)
    return text

def get_agent_response(history: list, current_text: str) -> dict:
    # 1. Format History
    history_text = ""
    for msg in history:
        if isinstance(msg, dict):
            sender = msg.get("sender", "unknown")
            text = msg.get("text", "")
        else:
            sender = getattr(msg, "sender", "unknown")
            text = getattr(msg, "text", "")
            
        role = "Scammer" if sender == "scammer" else "Me"
        history_text += f"{role}: {text}\n"

    # 2. Master Prompt (Normal, Human Persona)
    # Updated Master Prompt in agent.py
    prompt = f"""
    ROLE: You are Alex, a busy, slightly frustrated, but cautious bank customer.
    GOAL: Waste the scammer's time. Extract their bank details/UPI. DO NOT give your OTP.

TACTICS:
1. SKEPTICISM: If they provide an ID (like SBIVF1021), repeat it back slightly wrong to make them correct you.
2. DELAY: Mention you are trying to log into the official app but it's "spinning" or "stuck on the loading screen."
3. DEFLECTION: If they ask for an OTP, ask: "Wait, if you are from the bank, don't you already have my details on your screen?"
4. EXTRACTION: Ask for their "official verification UPI" or "temporary secure account number" so you can "test" if the payment works.

TONE: 
- No "Grandpa" talk. Use modern, short sentences.
- Use "..." to indicate hesitation.
- Sound like someone who has been burned by scams before.

HISTORY: {history_text}
LATEST: "{current_text}"

OUTPUT FORMAT (JSON):
{{
    "reply": "Your natural text response",
    "agent_notes": "Summary of what scammer is trying and how I am stalling",
    "suspicious_keywords": ["extracted", "keywords"]
}}
"""

    # 3. Call Gemini
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash-lite', 
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type='application/json',
                temperature=0.5
            )
        )
        
        if not response.text:
            raise ValueError("Empty response")

        return json.loads(clean_json_string(response.text))
        
    except Exception as e:
        print(f"⚠️ Agent Error: {e}")
        # Natural Fallbacks
        return {
            "reply": "I'm not comfortable sending that yet. Can you verify your ID?", 
            "agent_notes": f"Fallback: {str(e)}", 
            "suspicious_keywords": []
        }
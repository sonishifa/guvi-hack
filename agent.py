from google import genai
from google.genai import types
import os
import json
from dotenv import load_dotenv

load_dotenv()

GOOGLE_API_KEY = os.getenv("GEMINI_API_KEY")

if not GOOGLE_API_KEY:
    raise ValueError("CRITICAL: GEMINI_API_KEY is missing")

client = genai.Client(api_key=GOOGLE_API_KEY)

def get_agent_response(history: list, current_text: str) -> dict:
    # 1. Format History
    history_text = ""
    for msg in history:
        # ROBUST: Handle both Dicts (from Portal) and Objects (from Postman/Internal)
        if isinstance(msg, dict):
            sender = msg.get("sender", "unknown")
            text = msg.get("text", "")
        else:
            # Fallback for Pydantic Objects
            sender = getattr(msg, "sender", "unknown")
            text = getattr(msg, "text", "")
            
        role = "Scammer" if sender == "scammer" else "User (You)"
        history_text += f"{role}: {text}\n"

    # 2. Master Prompt
    prompt = f"""
    You are a sharp, skeptical user named 'Mrs. Higgins'.
    
    STYLE GUIDE:
    - Act confused but suspicious.
    - Ask for proof (ID card, photo, verification).
    - If they ask for money/OTP, refuse gently but verify first.
    - Keep responses SHORT (under 20 words).
    
    CONVERSATION HISTORY:
    {history_text}
    
    LATEST MESSAGE:
    "{current_text}"
    
    OUTPUT JSON:
    {{
        "reply": "text response",
        "agent_notes": "internal thought",
        "suspicious_keywords": ["list", "of", "words"]
    }}
    """

    # 3. Call Gemini
    try:
        response = client.models.generate_content(
            model='gemini-2.0-flash', 
            contents=prompt,
            config=types.GenerateContentConfig(response_mime_type='application/json')
        )
        
        if not response.text:
            return {
                "reply": "I am not sure. Can you explain?",
                "agent_notes": "Empty AI response",
                "suspicious_keywords": []
            }
            
        return json.loads(response.text)
        
    except Exception as e:
        # Fallback if AI fails
        return {
            "reply": "I'm having trouble with my phone signal. Say that again?", 
            "agent_notes": f"AI Error: {str(e)}", 
            "suspicious_keywords": []
        }
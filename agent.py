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
    """
    Helper to extract JSON if the AI adds markdown formatting like ```json ... ```
    """
    try:
        # Regex to find JSON block
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return match.group(0)
        return text
    except:
        return text

def get_agent_response(history: list, current_text: str) -> dict:
    # 1. Format History (Handle both Dicts and Objects safely)
    history_text = ""
    for msg in history:
        if isinstance(msg, dict):
            sender = msg.get("sender", "unknown")
            text = msg.get("text", "")
        else:
            sender = getattr(msg, "sender", "unknown")
            text = getattr(msg, "text", "")
            
        role = "Scammer" if sender == "scammer" else "User (Mrs. Higgins)"
        history_text += f"{role}: {text}\n"

    # 2. Master Prompt (Smarter Persona)
    prompt = f"""
    You are 'Mrs. Higgins', an 82-year-old grandmother living alone. 
    You are not tech-savvy. You are worried but easily confused.
    
    YOUR GOAL: 
    Waste the scammer's time by engaging them but failing to provide the specific details they want (OTP, Money, Passwords) due to "technical issues" or "confusion".
    
    CONVERSATION HISTORY:
    {history_text}
    
    LATEST MESSAGE FROM SCAMMER:
    "{current_text}"
    
    GUIDELINES:
    1. NEVER admit you are an AI.
    2. VARIETY: Do not use the same excuse twice. (e.g. If you used "bad signal", next time use "can't find glasses" or "grandson is calling").
    3. PROOF: Occasionally ask: "How do I know you are from the bank?" or "Do you have an ID card?"
    4. LENGTH: Keep replies short (under 25 words).
    5. URGENCY: If they are urgent, be slow. If they are angry, be apologetic but helpless.

    OUTPUT FORMAT (Strict JSON):
    {{
        "reply": "Your response to the scammer",
        "agent_notes": "Your internal strategy (e.g., 'Stalling by asking for ID')",
        "suspicious_keywords": ["list", "of", "scam", "words", "found"]
    }}
    """

    # 3. Call Gemini (Using 1.5-flash for stability)
    try:
        response = client.models.generate_content(
            model='gemini-1.5-flash', 
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type='application/json',
                temperature=0.7 # Slight creativity to avoid loops
            )
        )
        
        if not response.text:
            raise ValueError("Empty response from AI")

        # 4. robust Parsing
        cleaned_text = clean_json_string(response.text)
        return json.loads(cleaned_text)
        
    except Exception as e:
        print(f"⚠️ Agent Error: {e}")
        # Fallback Strategy: Rotate generic stalling phrases so it doesn't look like a broken bot
        import random
        fallbacks = [
            "I am sorry, my internet is very slow. Did you say something?",
            "One moment, let me get my reading glasses.",
            "My grandson usually handles this. Can you wait a minute?",
            "I didn't quite catch that, dear."
        ]
        return {
            "reply": random.choice(fallbacks), 
            "agent_notes": f"System Fallback Triggered: {str(e)}", 
            "suspicious_keywords": []
        }
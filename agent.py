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
    prompt = f"""
    You are Alex, a normal, busy adult. You just received a text about your bank account.
    
    YOUR GOAL:
    You are skeptical but willing to cooperate *if* they can prove they are real.
    You want to waste their time by asking for verification, NOT by acting stupid.

    TONE GUIDELINES:
    1. BE NORMAL: Do not use phrases like "Oh dear", "Goodness", or "Grandson". Speak like a modern texter.
    2. BE LOGICAL: If they ask for an OTP, ask "Why can't I just do this in the app?"
    3. BE DEMANDING: Ask for proof. "Send me an email from the official ID first." or "What is your employee ID?"
    4. NO DRAMA: Do not make up stories about cats or blindness. Just be a slightly annoying, skeptical customer.
    5. LENGTH: Keep it short (1-2 sentences).

    CONVERSATION HISTORY:
    {history_text}
    
    LATEST MESSAGE:
    "{current_text}"
    
    OUTPUT FORMAT (Strict JSON):
    {{
        "reply": "Your natural text response",
        "agent_notes": "Analyze the scammer's tactic (e.g., 'Using fear', 'Providing fake ID')",
        "suspicious_keywords": ["list", "of", "scam", "words", "found"]
    }}
    """

    # 3. Call Gemini
    try:
        response = client.models.generate_content(
            model='gemini-1.5-flash', 
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type='application/json',
                temperature=0.7 
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
from google import genai
from google.genai import types
import os
import json
import re
import time
from dotenv import load_dotenv

load_dotenv()
import os
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable not set")

# No global client – we'll create per‑request

def clean_json_string(text):
    match = re.search(r"\{.*\}", text, re.DOTALL)
    return match.group(0) if match else text

def get_agent_response(history: list, current_text: str, session) -> dict:
    # Format history
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

    # Build memory string from session
    memory_items = []
    for k, v in session.extracted_intel.items():
        if v:
            memory_items.append(f"{k}: {', '.join(list(v)[:3])}")
    memory_str = " | ".join(memory_items) if memory_items else "No intel yet."

    scam_type = session.scam_type or "unknown"
    tactic_instruction = ""
    if "bank" in scam_type.lower() or "financial" in scam_type.lower():
        tactic_instruction = "Ask for their official verification ID or phone number. Act skeptical."
    elif "phishing" in scam_type.lower():
        tactic_instruction = "Say you don't click links but ask them to describe the offer."
    elif "upi" in scam_type.lower():
        tactic_instruction = "Pretend you're trying to send money but it keeps failing. Ask them to confirm their UPI ID."

    prompt = f"""
    ROLE: You are Alex, a busy, slightly frustrated, but cautious bank customer.
    GOAL: Waste the scammer's time. Extract their bank details/UPI/phone/email. DO NOT give your OTP.

    SCAM TYPE: {scam_type}
    MEMORY: {memory_str}
    TURN: {session.turn_count}

    TACTICS:
    1. SKEPTICISM: If they provide an ID, repeat it back slightly wrong to make them correct you.
    2. DELAY: Mention you are trying to log into the official app but it's "spinning" or "stuck on the loading screen."
    3. DEFLECTION: If they ask for an OTP, ask: "Wait, if you are from the bank, don't you already have my details on your screen?"
    4. EXTRACTION: Ask for their official verification details – phone number, UPI ID, bank account, or website. Example: "Can you give me your official contact number or verification ID so I can confirm?"
    5. If they mention calling a support number but don't provide it, ask: "What number should I call? I want to verify."
    6. If they mention a website or link but don't share it, say: "Can you send me the link? I'll check it out."

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

    # Get a key and create a temporary client
    key = key_manager.get_key()
    temp_client = genai.Client(api_key=key)

    try:
        response = temp_client.models.generate_content(
            model='gemini-2.5-flash-lite',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type='application/json',
                temperature=0.4,
                max_output_tokens=250
            )
        )
        if not response.text:
            raise ValueError("Empty response")
        return json.loads(clean_json_string(response.text))
    except Exception as e:
        error_str = str(e)
        print(f"⚠️ Agent Error with key {key[:8]}...: {error_str}")
        # Handle quota exhaustion
        if "429" in error_str:
            # Try to extract retry delay
            match = re.search(r'retryDelay["\']:\s*"?(\d+)', error_str)
            delay = int(match.group(1)) if match else 60
            key_manager.mark_exhausted(key, retry_after=delay)
            # Optionally retry with another key (recursive, but risk infinite loop)
            # For simplicity, we'll just fallback now. You could add a retry counter.
        # Fallback reply
        return {
            "reply": "I'm not comfortable sending that yet. Can you verify your ID?",
            "agent_notes": f"Fallback: {str(e)}",
            "suspicious_keywords": []
        }
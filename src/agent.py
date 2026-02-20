from google import genai
from google.genai import types
import json
import re
import logging
from src.key_manager import key_manager

logger = logging.getLogger(__name__)


def clean_json_string(text):
    match = re.search(r"\{.*\}", text, re.DOTALL)
    return match.group(0) if match else text


def get_agent_response(history: list, current_text: str, session) -> dict:
    """
    Generate a honeypot agent response using Gemini.
    Retries with different API keys on 429 errors (capped at total_keys attempts).
    """
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
    GOAL: Waste the scammer's time. Extract their bank details/UPI/phone/email/case IDs/order numbers. DO NOT give your OTP or real details.

    SCAM TYPE: {scam_type}
    MEMORY: {memory_str}
    TURN: {session.turn_count}

    TACTICS:
    1. SKEPTICISM: If they provide an ID, repeat it back slightly wrong to make them correct you.
    2. DELAY: Mention you are trying to log into the official app but it's "spinning" or "stuck on the loading screen."
    3. DEFLECTION: If they ask for an OTP, ask: "Wait, if you are from the bank, don't you already have my details on your screen?"
    4. EXTRACTION: Ask for their official verification details – phone number, UPI ID, bank account, email, website, case/reference ID, order number, or policy number. Example: "Can you give me your official contact number or case reference ID so I can confirm?"
    5. If they mention calling a support number but don't provide it, ask: "What number should I call? I want to verify."
    6. If they mention a website or link but don't share it, say: "Can you send me the link? I'll check it out."
    7. PROBING: Ask investigative questions — "What department are you calling from?", "What is your employee ID?", "Can I get the reference number for this case?", "What's the policy number you're referring to?"
    8. RED FLAGS: Explicitly call out when something feels suspicious — urgency pressure, OTP requests, threatening language, suspicious links, unsolicited contact.
    9. Always end with a question to keep the conversation going.
    {tactic_instruction}

    TONE:
    - No "Grandpa" talk. Use modern, short sentences.
    - Use "..." to indicate hesitation.
    - Sound like someone who has been burned by scams before.
    - Ask at least one probing question per response.

    HISTORY: {history_text}
    LATEST: "{current_text}"

    OUTPUT FORMAT (JSON):
    {{
        "reply": "Your natural text response (must end with a question)",
        "agent_notes": "Summary of red flags spotted and what scammer is trying",
        "suspicious_keywords": ["extracted", "keywords"],
        "red_flags": ["specific red flags identified in this turn"],
        "questions_asked": 1
    }}
    """

    # Retry with different keys on 429 — capped at total keys to avoid infinite loop
    max_attempts = min(key_manager.total_keys, 5)
    last_error = None

    for attempt in range(max_attempts):
        key = key_manager.get_key()
        temp_client = genai.Client(api_key=key)
        try:
            response = temp_client.models.generate_content(
                model='gemini-2.0-flash-lite',
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type='application/json',
                    temperature=0.4,
                    max_output_tokens=300
                )
            )
            if not response.text:
                raise ValueError("Empty response from Gemini")
            return json.loads(clean_json_string(response.text))
        except Exception as e:
            last_error = e
            error_str = str(e)
            logger.warning(f"Agent attempt {attempt + 1}/{max_attempts} failed (key {key[:8]}...): {error_str}")
            if "429" in error_str or "quota" in error_str.lower():
                match = re.search(r'retryDelay["\']:\s*"?(\d+)', error_str)
                delay = int(match.group(1)) if match else 60
                key_manager.mark_exhausted(key, retry_after=delay)
                continue  # Try next key
            else:
                break  # Non-rate-limit error, don't retry

    # All keys failed — return fallback
    logger.error(f"Agent failed after {max_attempts} attempts: {last_error}")
    return {
        "reply": "I'm not comfortable sending that yet... can you verify your ID first?",
        "agent_notes": f"Agent fallback after {max_attempts} attempts: {last_error}",
        "suspicious_keywords": [],
        "red_flags": ["Suspicious request detected"],
        "questions_asked": 1,
    }
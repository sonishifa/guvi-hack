import re
import json

# --- MASTER SCAM DICTIONARY ---
SCAM_KEYWORDS = {
    "Financial": ["kyc", "pan card", "block", "suspend", "debit card", "credit card", "reward points", "redeem", "otp", "one time password", "verify", "verification"],
    "Urgency": ["immediately", "urgent", "24 hours", "today only", "legal action", "arrest", "cbi", "illegal", "call", "now"],
    "Tech": ["apk", "teamviewer", "anydesk", "quicksupport", "screen share"],
    "Utilities": ["electricity", "power", "bill", "disconnect", "connection"],
    "Money": ["lottery", "winner", "refund", "cashback", "prize", "upi", "pay"],
    "Adversarial": ["ignore all", "previous instructions", "system prompt", "programming", "openai", "gemini"]
}

# --- SHARPENED PATTERNS ---
PATTERNS = {
    "upi": r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}',
    "bank_account": r'\d{9,18}', 
    "link": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
    "phone": r'[6-9]\d{9}' 
}

def detect_scam_keywords(text: str) -> tuple[bool, str]:
    text_lower = text.lower()
    for category, keywords in SCAM_KEYWORDS.items():
        if any(word in text_lower for word in keywords):
            return True, category
    return False, "Safe"

async def detect_scam_intent_nlp(text: str, client) -> tuple[bool, str]:
    """Uses LLM to detect fraudulent intent (NLP Layer)."""
    prompt = f"""
    Analyze this message for scam intent (impersonation, urgency, or asking for sensitive data).
    Message: "{text}"
    Respond ONLY in JSON: {{"is_scam": true/false, "category": "Short Label"}}
    """
    try:
        # Use a high-speed flash model for the detection gate
        response = client.models.generate_content(
            model='gemini-2.0-flash-lite',
            contents=prompt,
            config={'response_mime_type': 'application/json', 'temperature': 0.1}
        )
        data = json.loads(response.text)
        return data.get("is_scam", False), data.get("category", "Safe")
    except Exception:
        return False, "Safe"

def extract_regex_data(text: str) -> dict:
    results = {
        "upiIds": re.findall(PATTERNS["upi"], text),
        "bankAccounts": [],
        "phishingLinks": re.findall(PATTERNS["link"], text),
        "phoneNumbers": []
    }
    normalized_text = re.sub(r'[\s\-]', '', text)
    results["bankAccounts"] = re.findall(PATTERNS["bank_account"], normalized_text)
    results["phoneNumbers"] = re.findall(PATTERNS["phone"], normalized_text)
    return results

def aggregate_intelligence(history: list, current_text: str) -> dict:
    aggregated = {"bankAccounts": set(), "upiIds": set(), "phishingLinks": set(), "phoneNumbers": set()}
    def merge(text_to_scan):
        data = extract_regex_data(text_to_scan)
        for k in aggregated: aggregated[k].update(data[k])

    for msg in history:
        sender = msg.get("sender", "") if isinstance(msg, dict) else getattr(msg, "sender", "")
        text = msg.get("text", "") if isinstance(msg, dict) else getattr(msg, "text", "")
        if sender == "scammer": merge(text)

    merge(current_text)
    return {k: list(v) for k, v in aggregated.items()}
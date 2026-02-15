import re
import json
from typing import Tuple, List, Dict, Any

SCAM_KEYWORDS = {
    "Financial": ["kyc", "pan card", "block", "suspend", "debit card", "credit card", "reward points", "redeem", "otp", "one time password", "verify", "verification"],
    "Urgency": ["immediately", "urgent", "24 hours", "today only", "legal action", "arrest", "cbi", "illegal", "call", "now"],
    "Tech": ["apk", "teamviewer", "anydesk", "quicksupport", "screen share"],
    "Utilities": ["electricity", "power", "bill", "disconnect", "connection"],
    "Money": ["lottery", "winner", "refund", "cashback", "prize", "upi", "pay"],
    "Adversarial": ["ignore all", "previous instructions", "system prompt", "programming", "openai", "gemini"]
}

PATTERNS = {
    "upi": r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}',
    "bank_account": r'\b\d{9,18}\b',
    "link": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
    "phone": r'\b[6-9]\d{9}\b',
    "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "phone_loose": r'[\+\d\s\-]{10,15}'
}

def detect_scam_keywords(text: str) -> Tuple[bool, str]:
    text_lower = text.lower()
    for category, keywords in SCAM_KEYWORDS.items():
        if any(word in text_lower for word in keywords):
            return True, category
    return False, "Safe"

async def detect_scam_intent_nlp(text: str, client) -> Tuple[bool, str]:
    prompt = f"""
    Analyze this message for scam intent (impersonation, urgency, or asking for sensitive data).
    Message: "{text}"
    Respond ONLY in JSON: {{"is_scam": true/false, "category": "Short Label"}}
    """
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash-lite',
            contents=prompt,
            config={'response_mime_type': 'application/json', 'temperature': 0.1}
        )
        data = json.loads(response.text)
        return data.get("is_scam", False), data.get("category", "Safe")
    except Exception:
        return False, "Safe"

async def extract_entities_nlp(text: str, client) -> Dict[str, List[str]]:
    prompt = f"""
    Extract any financial information from this message:
    "{text}"

    Return a JSON with these keys only if found:
    - phoneNumbers (list of strings)
    - bankAccounts (list of strings)
    - upiIds (list of strings)
    - phishingLinks (list of strings)
    - emailAddresses (list of strings)

    If nothing found, return empty lists.
    """
    try:
        response = client.models.generate_content(
            model='gemini-2.0-flash-lite',
            contents=prompt,
            config={'response_mime_type': 'application/json', 'temperature': 0.1}
        )
        return json.loads(response.text)
    except Exception:
        return {}

def extract_regex_data(text: str) -> Dict[str, List[str]]:
    results = {
        "upiIds": re.findall(PATTERNS["upi"], text),
        "bankAccounts": [],
        "phishingLinks": re.findall(PATTERNS["link"], text),
        "phoneNumbers": [],
        "emailAddresses": re.findall(PATTERNS["email"], text)
    }

    normalized_text = re.sub(r'[\s\-]', '', text)
    results["bankAccounts"] = re.findall(PATTERNS["bank_account"], normalized_text)

    loose_phones = re.findall(PATTERNS["phone_loose"], text)
    for p in loose_phones:
        clean = re.sub(r'[\s\-]', '', p)
        if re.fullmatch(r'[6-9]\d{9}', clean) or re.fullmatch(r'\+91[6-9]\d{9}', clean):
            results["phoneNumbers"].append(clean)

    results["phoneNumbers"].extend(re.findall(PATTERNS["phone"], normalized_text))
    for k in results:
        results[k] = list(set(results[k]))
    return results

def aggregate_intelligence(history: list, current_text: str) -> Dict[str, List[str]]:
    aggregated = {
        "bankAccounts": set(),
        "upiIds": set(),
        "phishingLinks": set(),
        "phoneNumbers": set(),
        "emailAddresses": set()
    }

    def merge(text_to_scan):
        data = extract_regex_data(text_to_scan)
        for k in aggregated:
            aggregated[k].update(data.get(k, []))

    for msg in history:
        sender = msg.get("sender", "") if isinstance(msg, dict) else getattr(msg, "sender", "")
        text = msg.get("text", "") if isinstance(msg, dict) else getattr(msg, "text", "")
        if sender == "scammer":
            merge(text)

    merge(current_text)
    return {k: list(v) for k, v in aggregated.items()}
import re

# --- MASTER SCAM DICTIONARY ---
SCAM_KEYWORDS = {
    "Financial": ["kyc", "pan card", "block", "suspend", "debit card", "credit card", "reward points", "redeem"],
    "Urgency": ["immediately", "urgent", "24 hours", "today only", "legal action", "police", "arrest", "cbi", "illegal"],
    "Tech": ["apk", "teamviewer", "anydesk", "quicksupport", "screen share"],
    "Utilities": ["electricity", "power", "bill", "disconnect", "connection"],
    "Money": ["lottery", "winner", "refund", "cashback", "prize", "upi", "pay"],
    "Adversarial": ["ignore all", "previous instructions", "system prompt", "programming", "openai", "gemini"]
}

# --- SHARPENED PATTERNS ---
PATTERNS = {
    # UPI: Handles both text and number-based handles
    "upi": r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}',
    
    # Bank Account: 11-18 digits (to distinguish from 10-digit phones)
    "bank_account": r'\b\d{11,18}\b',
    
    # Links: Standard http/https
    "link": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
    
    # Phone: Indian format (+91, 0, or 10 digits starting with 6-9)
    "phone": r'(?:\+91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}'
}

def detect_scam_keywords(text: str) -> tuple[bool, str]:
    text_lower = text.lower()
    for category, keywords in SCAM_KEYWORDS.items():
        if any(word in text_lower for word in keywords):
            return True, category
    return False, "Safe"

def extract_regex_data(text: str) -> dict:
    """Extracts data from a single string using sharpened patterns."""
    return {
        "upiIds": re.findall(PATTERNS["upi"], text),
        "bankAccounts": re.findall(PATTERNS["bank_account"], text),
        "phishingLinks": re.findall(PATTERNS["link"], text),
        "phoneNumbers": re.findall(PATTERNS["phone"], text)
    }

def aggregate_intelligence(history: list, current_text: str) -> dict:
    """
    Scans ENTIRE history + current message.
    Strictly maps to Rule 12 keys for the final callback.
    """
    aggregated = {
        "bankAccounts": set(),
        "upiIds": set(),
        "phishingLinks": set(),
        "phoneNumbers": set()
    }
    
    def merge(text):
        data = extract_regex_data(text)
        # Note: We match the keys here to the Rule 12 format
        aggregated["bankAccounts"].update(data["bankAccounts"])
        aggregated["upiIds"].update(data["upiIds"])
        aggregated["phishingLinks"].update(data["phishingLinks"])
        aggregated["phoneNumbers"].update(data["phoneNumbers"])

    # 1. Scan History (Scammer messages only)
    for msg in history:
        sender = msg.get("sender", "") if isinstance(msg, dict) else getattr(msg, "sender", "")
        text = msg.get("text", "") if isinstance(msg, dict) else getattr(msg, "text", "")
        if sender == "scammer":
            merge(text)

    # 2. Scan Current Message
    merge(current_text)

    # 3. Final lists for Section 12 Payload
    return {k: list(v) for k, v in aggregated.items()}
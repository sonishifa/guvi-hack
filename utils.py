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
    "upi": r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}',
    # Bank Account: 11-18 digits (standard for most Indian banks)
    "bank_account": r'\b\d{11,18}\b',
    "link": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
    # Phone: 10 digits starting with 6-9
    "phone": r'\b[6-9]\d{9}\b'
}

def detect_scam_keywords(text: str) -> tuple[bool, str]:
    text_lower = text.lower()
    for category, keywords in SCAM_KEYWORDS.items():
        if any(word in text_lower for word in keywords):
            return True, category
    return False, "Safe"

def extract_regex_data(text: str) -> dict:
    """Extracts data using both raw and normalized text to catch obscured numbers."""
    
    # 1. Standard extraction (for links and UPIs which usually don't have internal spaces)
    results = {
        "upiIds": re.findall(PATTERNS["upi"], text),
        "bankAccounts": [],
        "phishingLinks": re.findall(PATTERNS["link"], text),
        "phoneNumbers": []
    }

    # 2. Advanced extraction for spaced-out numbers (e.g., "9 8 7 6 5 4 3 2 1 0")
    # We remove ALL whitespace and hyphens to find hidden sequences
    normalized_text = re.sub(r'[\s\-]', '', text)
    
    # Extract from normalized text
    results["bankAccounts"] = re.findall(PATTERNS["bank_account"], normalized_text)
    results["phoneNumbers"] = re.findall(PATTERNS["phone"], normalized_text)

    return results

def aggregate_intelligence(history: list, current_text: str) -> dict:
    """Scans ENTIRE history + current message for mandatory Section 12 callback."""
    aggregated = {
        "bankAccounts": set(),
        "upiIds": set(),
        "phishingLinks": set(),
        "phoneNumbers": set()
    }
    
    def merge(text_to_scan):
        data = extract_regex_data(text_to_scan)
        aggregated["bankAccounts"].update(data["bankAccounts"])
        aggregated["upiIds"].update(data["upiIds"])
        aggregated["phishingLinks"].update(data["phishingLinks"])
        aggregated["phoneNumbers"].update(data["phoneNumbers"])

    # Scan History (Scammer messages only)
    for msg in history:
        sender = msg.get("sender", "") if isinstance(msg, dict) else getattr(msg, "sender", "")
        text = msg.get("text", "") if isinstance(msg, dict) else getattr(msg, "text", "")
        if sender == "scammer":
            merge(text)

    # Scan Current Message
    merge(current_text)

    return {k: list(v) for k, v in aggregated.items()}
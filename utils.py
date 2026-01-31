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

# --- IMPROVED REGEX PATTERNS ---
PATTERNS = {
    # UPI: text@text (captures standard UPI IDs)
    "upi": r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}',
    
    # Bank Account: 9-18 digits (robust against spaces)
    "bank_account": r'\b\d{9,18}\b',
    
    # Links: http/https
    "link": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
    
    # Phone: Matches +91, 0, or plain 10 digits. Handles dashes/spaces.
    "phone": r'(?:\+91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}'
}

def detect_scam_keywords(text: str) -> tuple[bool, str]:
    text_lower = text.lower()
    for category, keywords in SCAM_KEYWORDS.items():
        if any(word in text_lower for word in keywords):
            return True, category
    return False, "Safe"

def extract_regex_data(text: str) -> dict:
    """Extracts data from a single string."""
    return {
        "upiIds": re.findall(PATTERNS["upi"], text),
        "bankAccounts": re.findall(PATTERNS["bank_account"], text),
        "phishingLinks": re.findall(PATTERNS["link"], text),
        "phoneNumbers": re.findall(PATTERNS["phone"], text)
    }

def aggregate_intelligence(history: list, current_text: str) -> dict:
    """
    Scans the ENTIRE history + current message to ensure we don't miss 
    details sent earlier in the chat.
    """
    aggregated = {
        "bankAccounts": set(),
        "upiIds": set(),
        "phishingLinks": set(),
        "phoneNumbers": set(),
        "suspiciousKeywords": set() # We don't really regex for keywords here, handled by AI
    }
    
    # 1. Helper to merge data
    def merge(text):
        data = extract_regex_data(text)
        aggregated["bankAccounts"].update(data["bankAccounts"])
        aggregated["upiIds"].update(data["upiIds"])
        aggregated["phishingLinks"].update(data["phishingLinks"])
        aggregated["phoneNumbers"].update(data["phoneNumbers"])

    # 2. Scan History
    for msg in history:
        # Check if msg is dict or object (Handle both safely)
        if isinstance(msg, dict):
            sender = msg.get("sender", "")
            text = msg.get("text", "")
        else:
            sender = getattr(msg, "sender", "")
            text = getattr(msg, "text", "")
            
        # Only scan SCAMMER messages for intel
        if sender == "scammer":
            merge(text)

    # 3. Scan Current Message
    merge(current_text)

    # 4. Convert sets back to lists
    return {k: list(v) for k, v in aggregated.items()}
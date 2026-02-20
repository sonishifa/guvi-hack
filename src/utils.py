import re
import json
import logging
import asyncio
import random
from typing import Tuple, List, Dict, Any
from google import genai
from src.key_manager import key_manager

# Set up logging
logger = logging.getLogger(__name__)

# =============================================================================
# SCAM KEYWORD LISTS (EXPANDED)
# =============================================================================
SCAM_KEYWORDS = {
    "Financial": [
        "kyc", "pan card", "aadhaar", "block", "suspend", "debit card", "credit card",
        "reward points", "redeem", "otp", "one time password", "verify", "verification",
        "account blocked", "account suspended", "bank account", "update kyc", "wallet",
        "banking", "transaction", "fraud alert", "unauthorized"
    ],
    "Urgency": [
        "immediately", "urgent", "24 hours", "today only", "legal action", "arrest",
        "cbi", "ed", "income tax", "raid", "illegal", "call now", "act fast",
        "last warning", "final notice", "terminated", "penalty", "fine", "deadline",
        "action required", "time sensitive"
    ],
    "Tech": [
        "apk", "teamviewer", "anydesk", "quicksupport", "screen share", "remote access",
        "install app", "download app", "click here", "update software", "tech support",
        "virus alert", "security issue"
    ],
    "Utilities": [
        "electricity", "power", "bill", "disconnect", "connection", "gas bill",
        "water bill", "broadband", "due amount", "outstanding", "utility", "meter"
    ],
    "Money": [
        "lottery", "winner", "refund", "cashback", "prize", "reward", "gift voucher",
        "money back", "bonus", "discount", "offer", "free", "claim now", "cash",
        "payout", "withdrawal"
    ],
    "Investment": [
        "investment", "returns", "profit", "crypto", "bitcoin", "ethereum", "trading",
        "forex", "stocks", "mutual funds", "guaranteed returns", "double your money",
        "pump and dump", "signals", "tips", "wealth", "portfolio"
    ],
    "Job": [
        "job", "work from home", "wfh", "part time", "full time", "data entry",
        "online job", "earn money", "registration fee", "processing fee", "interview",
        "joining bonus", "easy money", "passive income", "freelance", "remote work"
    ],
    "Lottery": [
        "lottery", "kbc", "kaun banega crorepati", "lucky draw", "prize money",
        "won", "selected", "processing fee", "tax payment", "release fee", "winner"
    ],
    "CustomerSupport": [
        "customer support", "customer care", "helpdesk", "technical support",
        "order stuck", "delivery failed", "refund", "cancellation", "amazon",
        "flipkart", "paytm", "phonepe", "google pay", "amazon pay", "ebay",
        "customer service", "helpline"
    ],
    "Loan": [
        "loan", "pre approved", "instant loan", "personal loan", "home loan",
        "car loan", "credit card", "processing fee", "disbursement", "cibil",
        "credit score", "low interest", "no collateral", "quick loan"
    ],
    "Government": [
        "pm kisan", "pm awas yojana", "subsidy", "government scheme", "beneficiary",
        "direct benefit transfer", "dbt", "scholarship", "pension", "aadhaar link",
        "govt", "sarkari", "yojana"
    ],
    "Romance": [
        "matrimonial", "marriage", "bride", "groom", "meet", "ticket money",
        "medical emergency", "travel expenses", "visa fee", "customs", "love",
        "dating", "relationship"
    ],
    "Courier": [
        "courier", "parcel", "shipment", "customs", "clearance fee", "international",
        "dhl", "fedex", "ups", "blue dart", "delivery failed", "held at customs",
        "shipping", "tracking"
    ],
    "SIM": [
        "sim", "mobile number", "deactivated", "network issue", "re verification",
        "sim swap", "port", "otp", "network provider", "airtel", "jio", "vi",
        "mobile network"
    ]
}

# =============================================================================
# REGEX PATTERNS (ENHANCED)
# =============================================================================
PATTERNS = {
    "upi": r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}',
    "bank_account": r'\b\d{9,18}\b',
    "link": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
    "phone": r'\b[6-9]\d{9}\b',                     # Strict 10-digit Indian mobile
    "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "phone_loose": r'[\+\d\s\-\(\)]{10,15}',       # Improved: includes parentheses
    "aadhaar": r'\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b',  # Aadhaar with optional spaces
    "pan": r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',        # PAN format
    "credit_card": r'\b(?:\d[ -]*?){13,16}\b'       # Generic credit card (13-16 digits)
}

# Prompt injection phrases
INJECTION_PHRASES = [
    "ignore all", "previous instructions", "system prompt", "programming",
    "openai", "gemini", "you are an ai", "bypass", "jailbreak", "role play",
    "act as", "simulate", "pretend", "now you are", "disregard", "override",
    "you're an ai", "you are a bot"
]

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
def detect_injection(text: str) -> bool:
    """Return True if the message contains prompt injection attempts."""
    text_lower = text.lower()
    return any(phrase in text_lower for phrase in INJECTION_PHRASES)


def detect_scam_keywords(text: str) -> Tuple[bool, str]:
    """
    Scan text for scam-related keywords.
    Returns (is_scam, category) where category is the first matched keyword group.
    """
    text_lower = text.lower()
    for category, keywords in SCAM_KEYWORDS.items():
        if any(word in text_lower for word in keywords):
            logger.debug(f"Keyword match: {category} in '{text[:50]}...'")
            return True, category
    return False, "Safe"


async def detect_scam_intent_nlp(text: str) -> Tuple[bool, str]:
    """
    Use Gemini to detect scam intent with a detailed prompt.
    Returns (is_scam, category).
    """
    prompt = f"""
    Analyze this message for scam intent. Scams often include:
    - Impersonation of a bank, government, or trusted company
    - Creating urgency/panic (account blocked, legal action, arrest)
    - Requesting sensitive information (OTP, password, money)
    - Links to fake websites or phishing pages
    - Promises of lottery, prize, cashback, or easy money

    Message: "{text}"

    Return ONLY a JSON object with these fields:
    {{"is_scam": true/false, "category": "ShortLabel"}}
    """
    key = key_manager.get_key()
    temp_client = genai.Client(api_key=key)
    try:
        response = await asyncio.to_thread(
            temp_client.models.generate_content,
            model='gemini-2.5-flash',
            contents=prompt,
            config={'response_mime_type': 'application/json', 'temperature': 0.2}  # Increased temp
        )
        data = json.loads(response.text)
        logger.info(f"NLP detection: {data}")
        return data.get("is_scam", False), data.get("category", "Safe")
    except Exception as e:
        logger.error(f"NLP detection error: {e}")
        if "429" in str(e):
            match = re.search(r'retryDelay["\']:\s*"?(\d+)', str(e))
            delay = int(match.group(1)) if match else 60
            key_manager.mark_exhausted(key, retry_after=delay)
        return False, "Safe"


async def extract_entities_nlp(text: str) -> Dict[str, List[str]]:
    """
    Extract financial/personal entities using Gemini.
    Returns dict with keys: phoneNumbers, bankAccounts, upiIds, phishingLinks,
    emailAddresses, aadhaarNumbers, panNumbers.
    """
    prompt = f"""
    Extract any financial or personal identifying information from this message:
    "{text}"

    Return a JSON object with the following keys. Use empty lists if nothing found.
    - phoneNumbers: Indian phone numbers (10 digits, may start with +91 or 0)
    - bankAccounts: Indian bank account numbers (9-18 digits)
    - upiIds: UPI IDs (e.g., name@bank)
    - phishingLinks: Suspicious URLs (http, https)
    - emailAddresses: Email addresses
    - aadhaarNumbers: 12-digit Aadhaar numbers (may have spaces)
    - panNumbers: PAN card numbers (format: ABCDE1234F)

    Be thorough: capture numbers even if they are written with spaces, hyphens, or country codes.
    Do not include numbers that are clearly not relevant (e.g., amounts, dates).
    """
    key = key_manager.get_key()
    temp_client = genai.Client(api_key=key)
    try:
        response = await asyncio.to_thread(
            temp_client.models.generate_content,
            model='gemini-2.0-flash-lite',
            contents=prompt,
            config={'response_mime_type': 'application/json', 'temperature': 0.2}
        )
        return json.loads(response.text)
    except Exception as e:
        logger.error(f"NLP entity extraction error: {e}")
        if "429" in str(e):
            match = re.search(r'retryDelay["\']:\s*"?(\d+)', str(e))
            delay = int(match.group(1)) if match else 60
            key_manager.mark_exhausted(key, retry_after=delay)
        return {}


def extract_regex_data(text: str) -> Dict[str, List[str]]:
    """
    Extract structured data using regex patterns.
    Returns dict with keys: upiIds, bankAccounts, phishingLinks, phoneNumbers,
    emailAddresses, aadhaarNumbers, panNumbers, creditCards.
    """
    results = {
        "upiIds": re.findall(PATTERNS["upi"], text),
        "bankAccounts": [],
        "phishingLinks": re.findall(PATTERNS["link"], text),
        "phoneNumbers": [],
        "emailAddresses": re.findall(PATTERNS["email"], text),
        "aadhaarNumbers": re.findall(PATTERNS["aadhaar"], text),
        "panNumbers": re.findall(PATTERNS["pan"], text),
        "creditCards": []
    }

    # Normalize text: remove spaces and hyphens for bank/phone detection
    normalized_text = re.sub(r'[\s\-\(\)]', '', text)

    # Bank accounts from normalized text
    results["bankAccounts"] = re.findall(PATTERNS["bank_account"], normalized_text)

    # Phone numbers: loose capture + normalization
    loose_phones = re.findall(PATTERNS["phone_loose"], text)
    for p in loose_phones:
        clean = re.sub(r'[\s\-\(\)]', '', p)
        # Match strict Indian mobile (with or without +91)
        if re.fullmatch(r'(?:\+91)?[6-9]\d{9}', clean):
            # Normalize to 10 digits (remove +91 if present)
            if clean.startswith('+91'):
                clean = clean[3:]
            results["phoneNumbers"].append(clean)

    # Also scan normalized text for strict phone pattern
    results["phoneNumbers"].extend(re.findall(PATTERNS["phone"], normalized_text))

    # Credit cards: generic pattern (13-16 digits)
    # We could add Luhn validation later if needed
    results["creditCards"] = re.findall(PATTERNS["credit_card"], normalized_text)

    # Deduplicate all lists
    for k in results:
        results[k] = list(set(results[k]))

    # Remove phone numbers from bankAccounts (if any)
    results["bankAccounts"] = [acc for acc in results["bankAccounts"] if acc not in results["phoneNumbers"]]

    return results


def aggregate_intelligence(history: list, current_text: str) -> Dict[str, List[str]]:
    """
    Aggregate intelligence from all scammer messages in history and current message.
    """
    aggregated = {
        "bankAccounts": set(),
        "upiIds": set(),
        "phishingLinks": set(),
        "phoneNumbers": set(),
        "emailAddresses": set(),
        "aadhaarNumbers": set(),
        "panNumbers": set(),
        "creditCards": set()
    }

    def merge(text_to_scan):
        data = extract_regex_data(text_to_scan)
        for k in aggregated:
            aggregated[k].update(data.get(k, []))

    # Scan scammer messages from history
    for msg in history:
        sender = msg.get("sender", "") if isinstance(msg, dict) else getattr(msg, "sender", "")
        text = msg.get("text", "") if isinstance(msg, dict) else getattr(msg, "text", "")
        if sender == "scammer":
            merge(text)

    # Scan current message
    merge(current_text)

    return {k: list(v) for k, v in aggregated.items()}
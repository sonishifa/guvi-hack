import re
import json
from typing import Tuple, List, Dict, Any
from src.key_manager import key_manager
from google import genai
import asyncio

SCAM_KEYWORDS = {
    # Bank & Financial Fraud
    "Financial": [
        "kyc", "pan card", "aadhaar", "block", "suspend", "debit card", "credit card",
        "reward points", "redeem", "otp", "one time password", "verify", "verification",
        "account blocked", "account suspended", "bank account", "update kyc"
    ],

    # Urgency & Fear Tactics
    "Urgency": [
        "immediately", "urgent", "24 hours", "today only", "legal action", "arrest",
        "cbi", "ed", "income tax", "raid", "illegal", "call now", "act fast",
        "last warning", "final notice", "terminated", "penalty", "fine"
    ],

    # Tech Support & Remote Access
    "Tech": [
        "apk", "teamviewer", "anydesk", "quicksupport", "screen share", "remote access",
        "install app", "download app", "click here", "update software"
    ],

    # Utilities & Bills
    "Utilities": [
        "electricity", "power", "bill", "disconnect", "connection", "gas bill",
        "water bill", "broadband", "due amount", "outstanding"
    ],

    # Money, Prizes & Cashbacks
    "Money": [
        "lottery", "winner", "refund", "cashback", "prize", "reward", "gift voucher",
        "money back", "bonus", "discount", "offer", "free", "claim now"
    ],

    # Investment & Trading
    "Investment": [
        "investment", "returns", "profit", "crypto", "bitcoin", "ethereum", "trading",
        "forex", "stocks", "mutual funds", "guaranteed returns", "double your money",
        "pump and dump", "signals", "tips"
    ],

    # Job & Work from Home
    "Job": [
        "job", "work from home", "wfh", "part time", "full time", "data entry",
        "online job", "earn money", "registration fee", "processing fee", "interview",
        "joining bonus", "easy money", "passive income"
    ],

    # Lottery & Prize Scams
    "Lottery": [
        "lottery", "kbc", "kaun banega crorepati", "lucky draw", "prize money",
        "won", "selected", "processing fee", "tax payment", "release fee"
    ],

    # Customer Support Impersonation
    "CustomerSupport": [
        "customer support", "customer care", "helpdesk", "technical support",
        "order stuck", "delivery failed", "refund", "cancellation", "amazon",
        "flipkart", "paytm", "phonepe", "google pay", "amazon pay"
    ],

    # Loan & Credit Card
    "Loan": [
        "loan", "pre approved", "instant loan", "personal loan", "home loan",
        "car loan", "credit card", "processing fee", "disbursement", "cibil",
        "credit score", "low interest", "no collateral"
    ],

    # Government Schemes
    "Government": [
        "pm kisan", "pm awas yojana", "subsidy", "government scheme", "beneficiary",
        "direct benefit transfer", "dbt", "scholarship", "pension", "aadhaar link"
    ],

    # Romance & Matrimonial
    "Romance": [
        "matrimonial", "marriage", "bride", "groom", "meet", "ticket money",
        "medical emergency", "travel expenses", "visa fee", "customs"
    ],

    # Courier & Parcel
    "Courier": [
        "courier", "parcel", "shipment", "customs", "clearance fee", "international",
        "dhl", "fedex", "ups", "blue dart", "delivery failed", "held at customs"
    ],

    # SIM & Mobile
    "SIM": [
        "sim", "mobile number", "deactivated", "network issue", "re verification",
        "sim swap", "port", "otp", "network provider", "airtel", "jio", "vi"
    ]
}

PATTERNS = {
    "upi": r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}',
    "bank_account": r'\b\d{9,18}\b',
    "link": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
    "phone": r'\b[6-9]\d{9}\b',
    "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "phone_loose": r'[\+\d\s\-]{10,15}'
}

# List of phrases used to hijack or manipulate the AI
INJECTION_PHRASES = [
    "ignore all", "previous instructions", "system prompt", "programming",
    "openai", "gemini", "you are an ai", "bypass", "jailbreak", "role play",
    "act as", "simulate", "pretend", "now you are", "disregard", "override"
]

def detect_injection(text: str) -> bool:
    """Return True if the message contains prompt injection attempts."""
    text_lower = text.lower()
    return any(phrase in text_lower for phrase in INJECTION_PHRASES)

def detect_scam_keywords(text: str) -> Tuple[bool, str]:
    text_lower = text.lower()
    for category, keywords in SCAM_KEYWORDS.items():
        if any(word in text_lower for word in keywords):
            return True, category
    return False, "Safe"

async def detect_scam_intent_nlp(text: str, client=None) -> tuple[bool, str]:
    # client parameter is ignored; we use key manager
    prompt = f"""
    Analyze this message for scam intent (impersonation, urgency, or asking for sensitive data).
    Message: "{text}"
    Respond ONLY in JSON: {{"is_scam": true/false, "category": "Short Label"}}
    """
    key = key_manager.get_key()
    temp_client = genai.Client(api_key=key)
    try:
        # Run the synchronous generate_content in a thread
        response = await asyncio.to_thread(
            temp_client.models.generate_content,
            model='gemini-2.0-flash-lite',  # keep your model
            contents=prompt,
            config={'response_mime_type': 'application/json', 'temperature': 0.1}
        )
        data = json.loads(response.text)
        return data.get("is_scam", False), data.get("category", "Safe")
    except Exception as e:
        if "429" in str(e):
            match = re.search(r'retryDelay["\']:\s*"?(\d+)', str(e))
            delay = int(match.group(1)) if match else 60
            key_manager.mark_exhausted(key, retry_after=delay)
        return False, "Safe"

async def extract_entities_nlp(text: str, client=None) -> Dict[str, List[str]]:
    prompt = f"""
    Extract any financial or personal identifying information from this message:
    "{text}"

    Return a JSON object with the following keys. Use empty lists if nothing found.
    - phoneNumbers: Indian phone numbers (10 digits, may start with +91 or 0)
    - bankAccounts: Indian bank account numbers (9-18 digits)
    - upiIds: UPI IDs (e.g., name@bank)
    - phishingLinks: Suspicious URLs (http, https)
    - emailAddresses: Email addresses
    - aadhaarNumbers: 12-digit Aadhaar numbers (optional)
    - panNumbers: PAN card numbers (format: ABCDE1234F) (optional)

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
            config={'response_mime_type': 'application/json', 'temperature': 0.1}
        )
        return json.loads(response.text)
    except Exception as e:
        if "429" in str(e):
            match = re.search(r'retryDelay["\']:\s*"?(\d+)', str(e))
            delay = int(match.group(1)) if match else 60
            key_manager.mark_exhausted(key, retry_after=delay)
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

    # Bank accounts from normalized text
    results["bankAccounts"] = re.findall(PATTERNS["bank_account"], normalized_text)

    # Phone numbers: loose capture + normalization
    loose_phones = re.findall(PATTERNS["phone_loose"], text)
    for p in loose_phones:
        clean = re.sub(r'[\s\-]', '', p)
        if re.fullmatch(r'[6-9]\d{9}', clean) or re.fullmatch(r'\+91[6-9]\d{9}', clean):
            results["phoneNumbers"].append(clean)

    # Also scan normalized text for strict phone pattern
    results["phoneNumbers"].extend(re.findall(PATTERNS["phone"], normalized_text))

    # Deduplicate all lists
    for k in results:
        results[k] = list(set(results[k]))

    # Remove phone numbers from bankAccounts (if any)
    results["bankAccounts"] = [acc for acc in results["bankAccounts"] if acc not in results["phoneNumbers"]]

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
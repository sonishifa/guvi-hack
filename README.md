<h1>
  <img src="src/logo.png" alt="HoneyShield Logo" width="40" style="vertical-align: middle; margin-right: 10px;">
  HoneyShield
</h1>

An AI-powered **agentic honeypot** that detects scam messages, engages fraudsters with a realistic human persona (“Alex”), and extracts actionable intelligence such as:

- Bank Accounts  
- UPI IDs  
- Phone Numbers  
- Phishing Links  
- Email Addresses  

The system uses a **three-layer detection pipeline** (Keywords → Regex → NLP) and a **dual-mode output system**:
- Background callback after idle timeout  
- GET endpoint for manual retrieval  

---

# 📌 Tech Stack

**Language & Framework**
- Python 3.10+
- FastAPI

**Key Libraries**
- `google-genai`
- `requests`
- `python-dotenv`
- `pydantic`
- `asyncio`

**LLM / AI Model**
- Google Gemini-2.5-Flash-Lite  
  (Scam intent detection, entity extraction, and agent persona)

**Deployment**
- Render
- Heroku
- Any Python-compatible cloud platform

---

# ⚙️ Setup Instructions

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/sonishifa/Honeypot-AI.git
cd Honeypot-AI
```

## 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

## 3️⃣ Set Environment Variables

Copy `.env.example` to `.env` and configure:

```
GEMINI_API_KEY=your_google_gemini_api_key
SCAMMER_API_KEY=your_secret_api_key_for_authentication
CALLBACK_URL=   # optional – final output POSTed here after 10s inactivity
```

## 4️⃣ Run the Application

```bash
uvicorn src.main:app --host 0.0.0.0 --port 8000
```

---

# 🌐 API Endpoint

**Webhook URL**
```
https://honeypot-ai-guard.onrender.com/webhook
```

**Method:** `POST`  
**Authentication Header:**  
```
x-api-key: SCAMMER_API_KEY
```

---

## 📥 Request Format (JSON)

```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your account will be blocked today...",
    "timestamp": "2025-02-11T10:30:00Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

---

## 📤 Response Format (JSON)

```json
{
  "status": "success",
  "reply": "Why would my account be blocked? I just used the app this morning."
}
```

---

# 📊 Retrieving Final Output (Mode B)

After 10 seconds of inactivity:

```bash
GET https://your-deployed-url.com/final/{sessionId}
```

Requires the same `x-api-key` header.

---

# 🧠 Approach

---

## 1️⃣ Scam Detection – Three-Tier Shield

### 🔎 Keyword Spotter
Curated scam-related words grouped by category (financial, urgency, tech, etc.).  
Fast, low-cost first pass.

### 🧩 Pattern Hunter (Regex)
Detects:
- UPI IDs
- Bank accounts
- Phone numbers
- Emails
- Phishing links

Also normalises text to catch obfuscated numbers.

### 🤖 AI Brain (NLP)
Uses Google Gemini to understand intent and catch novel scam phrasing.

If **any layer triggers**, the message is flagged as scam.

---

## 2️⃣ Engagement – Human-Like Agent “Alex”

Once a scam is detected, control passes to a Gemini-powered agent.

Alex is:
- A busy, slightly frustrated bank customer
- Uses modern language
- Adds hesitation (“...”)
- Asks sceptical questions to stall the scammer

Prompt adapts by scam type:
- Bank fraud → asks for official ID
- Phishing → refuses to click links

---

## 3️⃣ Intelligence Extraction – Layered Entity Gathering

- Regex immediately captures structured data  
- NLP extraction acts as fallback  
- Data aggregated per session  
- Returned in final output  

---

## 4️⃣ Conversation Lifecycle & Final Output

Each message updates:
- Turn count
- Timestamps
- Extracted intelligence

If intelligence is captured:
- Background task scheduled
- Sends final output after 10 seconds inactivity
- Cancelled if new message arrives
- Rescheduled to ensure accuracy

If no intelligence:
- Forced callback at 10th turn

---

### 🔄 Dual-Mode Delivery

**Mode A – Push**
- If `CALLBACK_URL` is set
- Final output POSTed automatically

**Mode B – Pull**
- Stored in memory
- Retrieved via:
```
GET /final/{sessionId}
```

---

## 5️⃣ Security & Robustness

### 🛑 Prompt Injection Protection
Messages like:
```
ignore all previous instructions
```
Are intercepted and replied with:
> “I don’t understand”

Agent is never activated.

### 🧯 Fallback Replies
If any component fails:
- Safe generic reply returned
- Conversation never breaks

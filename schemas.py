from pydantic import BaseModel, Field
from typing import List, Optional

# 1. INPUT MODELS (What the Scammer Sends)

class Message(BaseModel):
    sender: str  # "scammer" or "user"
    text: str
    timestamp: str

class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None

class IncomingRequest(BaseModel):
    sessionId: str
    message: Message
    # Defaults to empty list for the first message
    conversationHistory: List[dict] = []
    metadata: Optional[Metadata] = None

# 2. OUTPUT MODELS (What You Send Back)

class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int
    totalMessagesExchanged: int

class IntelligenceData(BaseModel):
    # Optional because we might not find them in every message
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    suspiciousKeywords: List[str] = []

class AgentResponse(BaseModel):
    status: str  # MUST be "success" to match spec
    scamDetected: bool
    engagementMetrics: EngagementMetrics
    extractedIntelligence: IntelligenceData
    agentNotes: str
    
    # We keep 'reply' because it's functionally required, 
    # but we treat it as an extra field.
    reply: Optional[str] = None

# 3. CALLBACK MODEL (What the Platform Receives After Processing)

class FinalCallbackPayload(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: IntelligenceData
    agentNotes: str
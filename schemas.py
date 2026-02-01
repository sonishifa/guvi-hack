from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Union
from datetime import datetime, timezone

# 1. INPUT MODELS 

class Message(BaseModel):
    sender: str
    text: str
    # FIX: Accept string, int, or float
    timestamp: Union[str, int, float]

    @field_validator('timestamp')
    @classmethod
    def convert_timestamp_to_iso(cls, v):
        if isinstance(v, (int, float)):
            try:
                # Heuristic: If > 10 billion, it's milliseconds
                seconds = v / 1000.0 if v > 1e10 else v
                return datetime.fromtimestamp(seconds, timezone.utc).isoformat()
            except ValueError:
                return str(v)
        return str(v)

class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None

class IncomingRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[dict] = []
    metadata: Optional[Metadata] = None

# 2. OUTPUT MODELS 

class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int
    totalMessagesExchanged: int

class IntelligenceData(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    suspiciousKeywords: List[str] = []

class AgentResponse(BaseModel):
    status: str = "success"
    reply: str

# 3. CALLBACK MODEL

class FinalCallbackPayload(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: IntelligenceData
    agentNotes: str
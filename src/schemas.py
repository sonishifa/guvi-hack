from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Union
from datetime import datetime, timezone

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Union[str, int, float]

    @field_validator('timestamp')
    @classmethod
    def convert_timestamp_to_iso(cls, v):
        if isinstance(v, (int, float)):
            try:
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

class IntelligenceData(BaseModel):
    phoneNumbers: List[str] = []
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    emailAddresses: List[str] = []
    suspiciousKeywords: List[str] = []
    aadhaarNumbers: List[str] = []
    panNumbers: List[str] = []
    creditCards: List[str] = []

class EngagementMetrics(BaseModel):
    totalMessagesExchanged: int
    engagementDurationSeconds: int

class FinalOutput(BaseModel):
    status: str = "success"
    scamDetected: bool
    scamType: str
    extractedIntelligence: IntelligenceData
    engagementMetrics: EngagementMetrics
    agentNotes: str = ""

class AgentResponse(BaseModel):
    status: str = "success"
    reply: str
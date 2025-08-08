from sqlmodel import SQLModel, Field
from datetime import datetime, timezone

class AuditLog(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    ip: str
    method: str
    path: str
    timestamp: datetime = Field(default_factory=datetime.now(timezone.utc))
    user_agent: str | None = None

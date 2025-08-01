from sqlmodel import SQLModel, Field
from datetime import datetime

class Password(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    encrypted_password: str | None = Field(default=None)
    created_at: datetime | None = Field(default=None)
    expire_at: datetime | None = Field(default=None)
    views_left: int | None = Field(default=None)
    is_expired: bool | None = Field(default=False)
    

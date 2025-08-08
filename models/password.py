from sqlmodel import SQLModel, Field
from pydantic import field_validator
from datetime import datetime, timedelta, timezone
from functools import partial
import secrets

class PasswordBase(SQLModel):
    password: str = Field(min_length=8, max_length=128)
    expire_at: datetime | None = Field(default=None)
    views_left: int = Field(default=1, ge=1, le=5)

    @field_validator("expire_at", mode="before")
    @classmethod
    def validate_expire_at(cls, value) -> datetime:
        # If value is None, use default (24 hours from now)
        if value is None:
            return datetime.now(timezone.utc) + timedelta(hours=24)
        
        # If value is a string, parse it first
        if isinstance(value, str):
            try:
                # Parse ISO format datetime string
                value = datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError("Formato de data inválido")
        
        # If value is not a datetime object yet, raise error
        if not isinstance(value, datetime):
            raise ValueError("expire_at deve ser um datetime")
        
        now = datetime.now(timezone.utc)

        # Ensure the value has timezone info
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        # Add a small buffer (30 seconds) to account for request processing time
        if value <= now - timedelta(seconds=30):
            raise ValueError("A data de expiração deve ser no futuro")

        if value > now + timedelta(days=7):
            raise ValueError("A data de expiração não pode ultrapassar 7 dias")

        return value


class Password(PasswordBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    token_url: str = Field(default_factory=partial(secrets.token_urlsafe, 32), index=True, unique=True, min_length=32, max_length=32)
    
    
class PasswordGen(SQLModel):
    size: int = Field(default=16, ge=8, le=128)
    numbers: bool = Field(default=True)
    special_char: bool = Field(default=True)
    expire_at: datetime | None = Field(default=None)
    views_left: int = Field(default=1, ge=1, le=5)

    @field_validator("expire_at", mode="before")
    @classmethod
    def validate_expire_at(cls, value) -> datetime:
        # If value is None, use default (24 hours from now)
        if value is None:
            return datetime.now(timezone.utc) + timedelta(hours=24)
        
        # If value is a string, parse it first
        if isinstance(value, str):
            try:
                # Parse ISO format datetime string
                value = datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError("Formato de data inválido")
        
        # If value is not a datetime object yet, raise error
        if not isinstance(value, datetime):
            raise ValueError("expire_at deve ser um datetime")
        
        now = datetime.now(timezone.utc)

        # Ensure the value has timezone info
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        # Add a small buffer (30 seconds) to account for request processing time
        if value <= now - timedelta(seconds=30):
            raise ValueError("A data de expiração deve ser no futuro")

        if value > now + timedelta(days=7):
            raise ValueError("A data de expiração não pode ultrapassar 7 dias")

        return value


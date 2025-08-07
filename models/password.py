from fastapi import HTTPException, status
from sqlmodel import SQLModel, Field, DateTime, Column, select, Session
from sqlalchemy import func
from datetime import datetime
from utils.database import SessionDep, engine
from functools import partial
import secrets

class PasswordBase(SQLModel):
    password: str
    expire_at: datetime
    views_left: int = Field(default=1)


class Password(PasswordBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime | None = Field(default_factory=datetime.utcnow)
    token_url: str | None = Field(default_factory=partial(secrets.token_urlsafe, 32), index=True, unique=True)
    
    
class PasswordGen(SQLModel):
    size: int = Field(default=16)
    numbers: bool = Field(default=True)
    special_char: bool = Field(default=True)    
    expire_at: datetime = Field(default=None)
    views_left: int = Field(default=1)


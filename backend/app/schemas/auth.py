"""Authentication-related schemas."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.models import Role


def _normalize_email(value: str) -> str:
    """Permit .local / .test etc. — Pydantic's strict EmailStr rejects them."""
    return (value or "").strip().lower()


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: str = Field(min_length=3, max_length=255)
    full_name: Optional[str] = Field(default=None, max_length=128)
    # Bcrypt silently truncates at 72 bytes; cap to avoid DoS via huge
    # payloads and to keep hash behaviour predictable.
    password: str = Field(min_length=8, max_length=128)
    role: Role = Role.VIEWER

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        v = _normalize_email(v)
        if "@" not in v or " " in v:
            raise ValueError("invalid email")
        # Require at least one char on each side of the "@".
        local, _, domain = v.partition("@")
        if not local or not domain or "." not in domain:
            raise ValueError("invalid email")
        return v


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    # Pydantic v2 treats ``Optional[T]`` *without* a default as still
    # required; an explicit default is needed so ``None`` from the ORM
    # round-trips instead of raising ``ValidationError``.
    full_name: Optional[str] = Field(default=None)
    role: Role
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut
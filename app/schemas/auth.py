"""Auth request/response schemas."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

model_config = ConfigDict(strict=True, extra="forbid")


class LoginRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    username: Annotated[str, Field(min_length=1, max_length=64)]
    password: Annotated[str, Field(min_length=1)]


class LoginResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    old_password: Annotated[str, Field(min_length=1)]
    new_password: Annotated[str, Field(min_length=12)]


class SessionResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    id: int
    ip_address: str | None
    user_agent: str | None
    created_at: str
    last_activity: str | None


class ApiKeyCreateRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    name: Annotated[str, Field(min_length=1, max_length=128)]
    permissions: Annotated[list[str], Field(min_length=1, max_length=50)]


class ApiKeyResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    id: int
    name: str
    key: str | None = None  # Only present on create
    permissions: list[str]
    created_at: str


class CreateUserRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    username: Annotated[str, Field(min_length=3, max_length=64)]
    password: Annotated[str, Field(min_length=12)]
    role: Literal["admin", "senior_analyst", "analyst", "viewer"] = "analyst"
    email: str | None = None


class UpdateUserRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    role: Literal["admin", "senior_analyst", "analyst", "viewer"] | None = None
    is_active: bool | None = None

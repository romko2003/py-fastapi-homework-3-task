from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


# -------------------------
# Register
# -------------------------
class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


# -------------------------
# Activate account
# -------------------------
class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str = Field(min_length=1, max_length=512)


class MessageResponseSchema(BaseModel):
    message: str


# -------------------------
# Password reset (request)
# -------------------------
class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


# -------------------------
# Password reset (complete)
# -------------------------
class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str = Field(min_length=1, max_length=512)
    password: str = Field(min_length=8, max_length=128)


# -------------------------
# Login
# -------------------------
class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# -------------------------
# Refresh access token
# -------------------------
class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str = Field(min_length=1, max_length=2048)


class AccessTokenResponseSchema(BaseModel):
    access_token: str

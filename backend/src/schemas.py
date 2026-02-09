from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional

class UserCreate(BaseModel):
    username: str = Field(..., min_length=5, max_length=50)
    contact: str = Field(..., min_length=10, max_length=10)
    address: Optional[str] = None
    email: EmailStr
    password: str = Field(..., min_length=8)

    @validator("contact")
    def validate_contact(cls, contact):
        if not contact.isdigit():
            raise ValueError("Contact must contain digit! ")
        return contact

class UserResponse(BaseModel):
    username: str
    contact: str
    address: Optional[str] = None
    email: EmailStr

    class Config:
        orm_mode = True

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    email: Optional[EmailStr] = None

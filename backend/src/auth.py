from fastapi import Depends, HTTPException
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from dotenv import load_dotenv
import os
from src.db import(UserDB, get_async_session, RefreshTokenDB)
from src.schemas import (TokenData, Token)
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import timedelta, datetime
from typing import Optional


load_dotenv()

SECURITY_KEY = os.getenv("SECURITY_KEY")
REFRESH_KEY = os.getenv("REFRESH_KEY")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS"))
ALGORITHM = os.getenv("ALGORITHM")


pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(plain_password):
    return pwd_context.hash(plain_password)

def verify_password(plain_password, hashed_password) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

async def get_user_by_email(
    email: str,
    session: AsyncSession
):
    result = await session.execute(
        select(UserDB).where(UserDB.email == email)
    )
    return result.scalar_one_or_none()

async def is_authenticated_user(
    email: str,
    plain_password: str,
    session: AsyncSession,
) -> UserDB|None:
    
    user = await get_user_by_email(email, session)
    if not user:
        return None
    if not verify_password(plain_password, user.password):
        return None  
    return user

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/login", auto_error=False)

def create_access_token(data: dict, expire_delta: Optional[timedelta] = None):
    try:
        to_encode = data.copy()

        if expire_delta:
            expire = datetime.utcnow() + expire_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode.update({"exp": expire, "type":"access"})

        encoded_data = jwt.encode(to_encode, SECURITY_KEY, algorithm=ALGORITHM)
        return encoded_data
    except JWTError:
        raise HTTPException(status_code=400, detail="Some thing get wrong inside create_access_token()")
    

def create_refresh_token(data: dict, expire_delta: Optional[timedelta] = None):
    try:
        to_encode = data.copy()

        if expire_delta:
            expire = datetime.utcnow() + expire_delta
        else:
            expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        to_encode.update(
            {"exp": expire, "type":"refresh"}
        )

        encoded_data = jwt.encode(to_encode, REFRESH_KEY, algorithm=ALGORITHM)
        return encoded_data
    except JWTError:
        raise HTTPException(status_code=400, detail="Some thing get wrong inside create_access_token()")

def verify_access_token(
    token: str,    
):
    try:
        payload = jwt.decode(token, SECURITY_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return TokenData(email=email)

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
def verify_refresh_token(
    token: str,
):
    try:
        payload = jwt.decode(token, REFRESH_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return TokenData(email=email)

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_async_session),     
):

    token_data = verify_access_token(token)

    user = await get_user_by_email(token_data.email, session)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def get_current_super_user(
    user: UserDB = Depends(get_current_user),
):
    if not user.is_super_user:
        raise HTTPException(
            status_code=403,
            detail="User is not a super user"
        )
    return user
    

async def get_current_optional_user(
    token: Optional[str] = Depends(oauth2_scheme_optional),
    session: AsyncSession = Depends(get_async_session)      
):
    if not token:
        return None
    try:
        token_data = verify_access_token(token)
        user = await get_user_by_email(token_data.email, session)
        if not user:
            return None
        return user
    except HTTPException:
        return None

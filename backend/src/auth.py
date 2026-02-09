from fastapi import Depends, HTTPException
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from dotenv import load_dotenv
import os
from src.db import(UserDB, get_async_session, RefreshTokenDB)
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError


pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(plain_password):
    return pwd_context.hash(plain_password)

def verify_password(plain_password, hashed_password) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

async def get_user_by_email(
    email: str,
    session: AsyncSession = Depends(get_async_session)
):
    result = await session.execute(select(UserDB).where(UserDB.email == email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

async def is_authenticated_user(
    email: str,
    plain_password: str,
    session: AsyncSession = Depends(get_async_session)
) -> bool:
    
    user = await get_user_by_email(email, session)

    if verify_password(plain_password, user.password):
        return True
    
    return False


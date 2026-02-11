from fastapi import FastAPI, Depends, HTTPException, Cookie, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from src.db import(
    UserDB,
    RefreshTokenDB,
    ExpensesDB,
    engine,
    create_table,
    get_async_session
)
from src.schemas import (
    UserCreate,
    UserLogin,
    UserResponse,
    Token,
    TokenData
)
from src.auth import(
    hash_password,
    get_user_by_email,
    get_current_user,
    get_current_optional_user,
    is_authenticated_user,
    create_access_token,
    create_refresh_token,
    get_current_super_user
)
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from datetime import datetime, timedelta
import os

@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_table()
    try:
        yield
    finally:
        await engine.dispose()
        


load_dotenv()

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS"))



app = FastAPI(lifespan=lifespan)

@app.get("/")
def index():
    return {"message":"Fuck! this shit is working. Cool!"}


@app.post("/register")
async def register(
    user_data: UserCreate,
    session: AsyncSession = Depends(get_async_session),
    current_user : Optional[UserDB] = Depends(get_current_optional_user)
) -> UserResponse:
    if current_user:
        raise HTTPException(status_code=403, detail="Already logged in")
    result = await session.execute(select(UserDB).where(UserDB.email == user_data.email))
    user_in_db = result.scalar_one_or_none()

    if user_in_db:
        raise HTTPException(status_code=401, detail="User of this email already exist")
    
    user = UserDB(
        username = user_data.username,
        contact = user_data.contact,
        address = user_data.address,
        email = user_data.email,
        password = hash_password(user_data.password)
    )

    session.add(user)
    await session.commit()
    await session.refresh(user)

    res = UserResponse(
        username=user.username,
        contact=user.contact,
        address=user.address,
        email=user.email,
    )

    return res


@app.post("/login")
async def login(
    user_login_data: UserLogin,
    response: Response,
    session: AsyncSession = Depends(get_async_session),
    current_user: Optional[UserDB] = Depends(get_current_optional_user)
):
    if current_user:
        raise HTTPException(status_code=403, detail="Already logged in")
    
    user = await is_authenticated_user(user_login_data.email, user_login_data.password, session)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    
    access_token = create_access_token(
        data={"sub":user.email, "type":"access"},
        expire_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    refresh_token = create_refresh_token(
        data={"sub":user.email, "type":"refresh"},
        expire_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    ref_token_db = RefreshTokenDB(
        u_id = user.u_id,
        ref_token = refresh_token
    )

    session.add(ref_token_db)
    await session.commit()
    await session.refresh(ref_token_db)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        max_age=REFRESH_TOKEN_EXPIRE_DAYS*24*60*60,
        secure=True,
        samesite="lax"
    )

    return {"access_token": access_token, "token_type": "bearer"}



from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
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
    hash_password
)
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_table()
    try:
        yield
    finally:
        await engine.dispose()
        

app = FastAPI(lifespan=lifespan)

@app.get("/")
def index():
    return {"message":"Fuck! this shit is working. Cool!"}


@app.post("/register")
async def register(
    user_data: UserCreate,
    session: AsyncSession = Depends(get_async_session)
) -> UserResponse:
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


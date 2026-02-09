from sqlalchemy import Numeric, select, Column, ForeignKey, Integer, Boolean, String, Text, DateTime
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.dialects.postgresql import UUID
from uuid import uuid4
from dotenv import load_dotenv
import os
from datetime import datetime


load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")


class Base(DeclarativeBase):
    pass

class UserDB(Base):
    __tablename__ = "users"

    u_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    username = Column(String(200), nullable=False, unique=True)
    contact = Column(String(10), nullable=False, unique=True)
    address = Column(Text)
    email = Column(String(225), unique=True, nullable=False)
    password = Column(String(225), nullable=False)
    is_super_user = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    refresh_tokens = relationship("RefreshTokenDB", back_populates="user")
    expenses = relationship("ExpensesDB", back_populates="user")

class RefreshTokenDB(Base):
    __tablename__ = "ref_token_table"

    t_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    u_id = Column(UUID(as_uuid=True), ForeignKey("users.u_id"), nullable=False)
    ref_token = Column(String(225), nullable=False,unique=True)
    is_revoked = Column(Boolean, default=False) 
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow,onupdate=datetime.utcnow)
    
    user = relationship("UserDB", back_populates="refresh_tokens")

class ExpensesDB(Base):
    __tablename__ = "expenses_table"

    e_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    u_id = Column(UUID(as_uuid=True), ForeignKey("users.u_id"), nullable=False)
    
    amount = Column(Numeric(10, 2), nullable=False)
    category = Column(String(100), nullable=False)
    title = Column(String(225), nullable=False)
    description = Column(String(255))

    expense_date = Column(DateTime, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("UserDB", back_populates="expenses")


engine = create_async_engine(DATABASE_URL, echo=True)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)

async def create_table():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_async_session():
    async with async_session_maker() as session:
        yield session
print("HELLO")
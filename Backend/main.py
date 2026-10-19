
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import jwt
from bson import ObjectId
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel, EmailStr, Field
from pymongo import AsyncMongoClient
from pymongo.errors import DuplicateKeyError

load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME", "shortie")
JWT_SECRET = os.getenv("JWT_SECRET")

if not MONGODB_URL or not JWT_SECRET:
    raise RuntimeError("Configure MONGODB_URL and JWT_SECRET in .env")

if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET must be at least 32 characters")

client = AsyncMongoClient(MONGODB_URL)
db = client[DATABASE_NAME]
users = db["users"]

password_hash = PasswordHash.recommended()
bearer_scheme = HTTPBearer(auto_error=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await client.admin.command("ping")
    await users.create_index("email", unique=True)
    yield
    await client.close()


app = FastAPI(title="Shortie API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:5501",
        "http://localhost:5501",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


class SignupRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    terms_accepted: bool


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


def make_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": user_id,
            "iat": now,
            "exp": now + timedelta(minutes=30),
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def safe_user(user: dict) -> dict:
    return {
        "id": str(user["_id"]),
        "full_name": user["full_name"],
        "email": user["email"],
    }


@app.get("/")
async def home():
    return {"message": "Shortie API is running"}


@app.post("/api/auth/signup", status_code=201)
async def signup(data: SignupRequest):
    full_name = data.full_name.strip()
    email = str(data.email).lower()

    if len(full_name) < 2:
        raise HTTPException(400, "Enter a valid name")

    if not data.terms_accepted:
        raise HTTPException(400, "Accept the terms to continue")

    user = {
        "full_name": full_name,
        "email": email,
        "password_hash": password_hash.hash(data.password),
        "role": "user",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
    }

    try:
        result = await users.insert_one(user)
    except DuplicateKeyError:
        raise HTTPException(409, "Email is already registered")

    user["_id"] = result.inserted_id

    return {
        "message": "Account created successfully",
        "user": safe_user(user),
    }


@app.post("/api/auth/login")
async def login(data: LoginRequest):
    user = await users.find_one(
        {"email": str(data.email).lower()}
    )

    if not user or not password_hash.verify(
        data.password, user["password_hash"]
    ):
        raise HTTPException(401, "Invalid email or password")

    if not user.get("is_active", False):
        raise HTTPException(403, "Account is disabled")

    return {
        "message": "Login successful",
        "access_token": make_token(str(user["_id"])),
        "token_type": "bearer",
        "user": safe_user(user),
    }


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
):
    if credentials is None:
        raise HTTPException(401, "Authentication required")

    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=["HS256"],
        )
        user_id = payload.get("sub")

        if not isinstance(user_id, str) or not ObjectId.is_valid(user_id):
            raise InvalidTokenError("Invalid user ID")

    except InvalidTokenError:
        raise HTTPException(401, "Invalid or expired token")

    user = await users.find_one({"_id": ObjectId(user_id)})

    if not user or not user.get("is_active", False):
        raise HTTPException(401, "User not found or inactive")

    return safe_user(user)


@app.get("/api/auth/me")
async def current_user(user: dict = Depends(get_current_user)):
    return {"user": user}

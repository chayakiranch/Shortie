
import os
import re
import secrets
import string
from contextlib import asynccontextmanager
from datetime import date, datetime, time, timedelta, timezone
from typing import Literal
from urllib.parse import urlparse

import jwt
from bson import ObjectId
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel, EmailStr, Field, HttpUrl
from pymongo import AsyncMongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError

load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME", "shortie")
JWT_SECRET = os.getenv("JWT_SECRET")
SHORTIE_BASE_URL = os.getenv(
    "SHORTIE_BASE_URL", "http://127.0.0.1:8000"
).rstrip("/")

if not MONGODB_URL or not JWT_SECRET:
    raise RuntimeError(
        "Configure MONGODB_URL and JWT_SECRET in Backend/.env"
    )

if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET must be at least 32 characters")

client = AsyncMongoClient(MONGODB_URL)
db = client[DATABASE_NAME]

users = db["users"]
links = db["links"]
qr_codes = db["qr_codes"]

password_hash = PasswordHash.recommended()
bearer_scheme = HTTPBearer(auto_error=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await client.admin.command("ping")

    await users.create_index("email", unique=True)
    await links.create_index("code", unique=True)
    await links.create_index([("owner_id", 1), ("created_at", -1)])

    await qr_codes.create_index([("owner_id", 1), ("created_at", -1)])
    await qr_codes.create_index([("owner_id", 1), ("link_id", 1)])

    yield
    await client.close()


app = FastAPI(title="Shortie API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:5501",
        "http://localhost:5501",
        "http://127.0.0.1:5502",
        "http://localhost:5502",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
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


class CreateLinkRequest(BaseModel):
    original_url: HttpUrl
    alias: str | None = Field(default=None, min_length=3, max_length=40)
    expiry_date: date | None = None


class UpdateLinkRequest(BaseModel):
    original_url: HttpUrl | None = None
    active: bool | None = None


class DeleteLinkResponse(BaseModel):
    message: str


class SaveQRCodeRequest(BaseModel):
    link_id: str = Field(min_length=1, max_length=100)
    size: int = Field(ge=128, le=2048)
    correction: Literal["L", "M", "Q", "H"]
    foreground: str = Field(pattern=r"^#[0-9A-Fa-f]{6}$")
    background: str = Field(pattern=r"^#[0-9A-Fa-f]{6}$")
    logo: str | None = Field(default=None, max_length=3_000_000)


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


def link_response(link: dict) -> dict:
    return {
        "id": str(link["_id"]),
        "code": link["code"],
        "short_url": f"{SHORTIE_BASE_URL}/s/{link['code']}",
        "original_url": link["original_url"],
        "created_at": link["created_at"],
        "expiry_date": link.get("expiry_date"),
        "active": link.get("active", True),
        "clicks": link.get("clicks", 0),
    }


def qr_response(document: dict) -> dict:
    created_at = document["created_at"]

    return {
        "id": str(document["_id"]),
        "linkId": document["link_id"],
        "shortUrl": document["short_url"],
        "size": document["size"],
        "correction": document["correction"],
        "foreground": document["foreground"],
        "background": document["background"],
        "logo": document.get("logo"),
        "createdAt": created_at.isoformat(),
    }


def generate_code(length: int = 7) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


@app.get("/")
async def home():
    return {"message": "Shortie API is running", "docs": "/docs"}


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
    user = await users.find_one({"email": str(data.email).lower()})

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


@app.post("/api/links", status_code=201)
async def create_link(
    data: CreateLinkRequest,
    user: dict = Depends(get_current_user),
):
    destination = str(data.original_url)

    if urlparse(destination).scheme not in ("http", "https"):
        raise HTTPException(400, "Only HTTP and HTTPS URLs are allowed")

    if data.expiry_date and data.expiry_date < datetime.now(
        timezone.utc
    ).date():
        raise HTTPException(400, "Expiry date cannot be in the past")

    if data.alias:
        if not re.fullmatch(r"[A-Za-z0-9_-]{3,40}", data.alias):
            raise HTTPException(
                400,
                "Alias must be 3–40 letters, numbers, hyphens or underscores",
            )
        code = data.alias
    else:
        code = generate_code()

    expiry = (
        datetime.combine(
            data.expiry_date, time.max, tzinfo=timezone.utc
        )
        if data.expiry_date
        else None
    )

    for attempt in range(5):
        document = {
            "code": code,
            "original_url": destination,
            "owner_id": user["id"],
            "created_at": datetime.now(timezone.utc),
            "expiry_date": expiry,
            "active": True,
            "clicks": 0,
        }

        try:
            result = await links.insert_one(document)
            document["_id"] = result.inserted_id
            return link_response(document)

        except DuplicateKeyError:
            if data.alias:
                raise HTTPException(409, "Alias already exists")

            if attempt == 4:
                raise HTTPException(
                    503,
                    "Could not generate a unique code. Please retry.",
                )

            code = generate_code()


@app.get("/api/links")
async def list_links(user: dict = Depends(get_current_user)):
    cursor = links.find(
        {"owner_id": user["id"]}
    ).sort("created_at", -1).limit(500)

    return {"links": [link_response(link) async for link in cursor]}


@app.patch("/api/links/{link_id}")
async def update_link(
    link_id: str,
    data: UpdateLinkRequest,
    user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(link_id):
        raise HTTPException(400, "Invalid link ID")

    changes = {}

    if data.original_url is not None:
        destination = str(data.original_url)

        if urlparse(destination).scheme not in ("http", "https"):
            raise HTTPException(
                400, "Only HTTP and HTTPS URLs are allowed"
            )

        changes["original_url"] = destination

    if data.active is not None:
        changes["active"] = data.active

    if not changes:
        raise HTTPException(400, "No changes supplied")

    link = await links.find_one_and_update(
        {"_id": ObjectId(link_id), "owner_id": user["id"]},
        {"$set": changes},
        return_document=ReturnDocument.AFTER,
    )

    if not link:
        raise HTTPException(404, "Link not found")

    return link_response(link)


@app.delete("/api/links/{link_id}", response_model=DeleteLinkResponse)
async def delete_link(
    link_id: str,
    user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(link_id):
        raise HTTPException(400, "Invalid link ID")

    result = await links.delete_one({
        "_id": ObjectId(link_id),
        "owner_id": user["id"],
    })

    if result.deleted_count == 0:
        raise HTTPException(404, "Link not found")

    return {"message": "Link deleted"}


# QR code endpoints

@app.post("/api/qr-codes", status_code=201)
async def save_qr_code(
    data: SaveQRCodeRequest,
    user: dict = Depends(get_current_user),
):
    if ObjectId.is_valid(data.link_id):
        link = await links.find_one({
            "_id": ObjectId(data.link_id),
            "owner_id": user["id"],
        })
    else:
        link = await links.find_one({
            "code": data.link_id,
            "owner_id": user["id"],
        })

    if not link:
        raise HTTPException(
            404, "Short link not found in your account"
        )

    if not link.get("active", True):
        raise HTTPException(
            400, "Cannot save a QR code for a disabled link"
        )

    expiry = link.get("expiry_date")
    if expiry:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            raise HTTPException(
                400, "Cannot save a QR code for an expired link"
            )

    document = {
        "owner_id": user["id"],
        "link_id": str(link["_id"]),
        "link_code": link["code"],
        "short_url": f"{SHORTIE_BASE_URL}/s/{link['code']}",
        "size": data.size,
        "correction": data.correction,
        "foreground": data.foreground,
        "background": data.background,
        "logo": data.logo,
        "created_at": datetime.now(timezone.utc),
    }

    result = await qr_codes.insert_one(document)
    document["_id"] = result.inserted_id

    return {
        "message": "QR configuration saved to MongoDB",
        "qr_code": qr_response(document),
    }


@app.get("/api/qr-codes")
async def list_qr_codes(
    user: dict = Depends(get_current_user),
):
    cursor = qr_codes.find(
        {"owner_id": user["id"]}
    ).sort("created_at", -1).limit(500)

    return {
        "qr_codes": [
            qr_response(document)
            async for document in cursor
        ]
    }


@app.delete("/api/qr-codes/{qr_id}")
async def delete_qr_code(
    qr_id: str,
    user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(qr_id):
        raise HTTPException(400, "Invalid QR code ID")

    result = await qr_codes.delete_one({
        "_id": ObjectId(qr_id),
        "owner_id": user["id"],
    })

    if result.deleted_count == 0:
        raise HTTPException(404, "QR configuration not found")

    return {"message": "QR configuration deleted"}


@app.get("/s/{code}")
async def redirect_short_link(code: str):
    link = await links.find_one({"code": code})

    if not link or not link.get("active", True):
        raise HTTPException(
            404, "Short link not found or disabled"
        )

    expiry = link.get("expiry_date")

    if expiry:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)

        if expiry <= datetime.now(timezone.utc):
            raise HTTPException(410, "This short link has expired")

    await links.update_one(
        {"_id": link["_id"]},
        {"$inc": {"clicks": 1}},
    )

    return RedirectResponse(
        url=link["original_url"],
        status_code=307,
    )

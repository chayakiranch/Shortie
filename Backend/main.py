
import os
import re
import secrets
import string
import logging
import hashlib
import hmac
from collections import Counter
from contextlib import asynccontextmanager
from datetime import date, datetime, time, timedelta, timezone
from typing import Literal
from urllib.parse import urlparse

import jwt
from bson import ObjectId
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from pydantic import BaseModel, EmailStr, Field, HttpUrl
from pymongo import AsyncMongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError
import csv
import io

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shortie")

MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME", "shortie")
JWT_SECRET = os.getenv("JWT_SECRET")
SHORTIE_BASE_URL = os.getenv(
    "SHORTIE_BASE_URL", "http://127.0.0.1:8000"
).rstrip("/")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()

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
click_events = db["click_events"]
domains = db["domains"]

password_hash = PasswordHash.recommended()
bearer_scheme = HTTPBearer(auto_error=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await client.admin.command("ping")

    await users.create_index("email", unique=True)
    await users.create_index("google_sub", unique=True, sparse=True)
    await domains.create_index([("owner_id", 1), ("domain", 1)], unique=True)
    await links.create_index("code", unique=True)
    await links.create_index([("owner_id", 1), ("created_at", -1)])

    await qr_codes.create_index(
        [("owner_id", 1), ("created_at", -1)]
    )
    await qr_codes.create_index(
        [("owner_id", 1), ("link_id", 1)]
    )

    await click_events.create_index(
        [("link_id", 1), ("clicked_at", -1)]
    )
    await click_events.create_index(
        [("owner_id", 1), ("clicked_at", -1)]
    )
    await click_events.create_index(
        [("code", 1), ("clicked_at", -1)]
    )

    logger.info("Shortie database connected successfully")
    yield
    await client.close()


app = FastAPI(
    title="Shortie API",
    version="1.3.0",
)

# Permit localhost development servers on any port.
# For production, restrict this to your deployed frontend domain.
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
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# Request models

class SignupRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    terms_accepted: bool


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class GoogleAuthRequest(BaseModel):
    credential: str = Field(min_length=20, max_length=10000)


class UpdateProfileRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=100)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class CreateLinkRequest(BaseModel):
    original_url: HttpUrl
    alias: str | None = Field(default=None, min_length=3, max_length=40)
    expiry_date: date | None = None
    activation_date: date | None = None
    password: str | None = Field(default=None, min_length=4, max_length=128)


class VerifyLinkPasswordRequest(BaseModel):
    password: str = Field(min_length=1, max_length=128)


class UpdateLinkRequest(BaseModel):
    original_url: HttpUrl | None = None
    active: bool | None = None
    expiry_date: date | None = None

class DeleteLinkResponse(BaseModel):
    message: str


class SaveQRCodeRequest(BaseModel):
    link_id: str = Field(min_length=1, max_length=100)
    size: int = Field(ge=128, le=2048)
    correction: Literal["L", "M", "Q", "H"]
    foreground: str = Field(pattern=r"^#[0-9A-Fa-f]{6}$")
    background: str = Field(pattern=r"^#[0-9A-Fa-f]{6}$")
    logo: str | None = Field(default=None, max_length=3_000_000)


# Privacy-conscious visitor tracking. A random first-party cookie is stored
# in the visitor browser; only an HMAC of its value is saved in click_events.
VISITOR_COOKIE_NAME = "shortie_visitor"
VISITOR_COOKIE_MAX_AGE = 60 * 60 * 24 * 365

def visitor_fingerprint(request: Request) -> tuple[str, str, bool]:
    cookie_value = request.cookies.get(VISITOR_COOKIE_NAME)
    is_new = not cookie_value
    if not cookie_value:
        cookie_value = secrets.token_urlsafe(32)
    fingerprint = hmac.new(
        JWT_SECRET.encode("utf-8"),
        cookie_value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return cookie_value, fingerprint, is_new

def set_visitor_cookie(response, cookie_value: str, is_new: bool):
    if is_new:
        response.set_cookie(
            key=VISITOR_COOKIE_NAME,
            value=cookie_value,
            max_age=VISITOR_COOKIE_MAX_AGE,
            httponly=True,
            secure=False,  # Set True when deployed exclusively over HTTPS.
            samesite="lax",
            path="/",
        )
    return response


# Authentication helpers

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


# Response helpers

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
        "activation_date": link.get("activation_date"),
        "password_protected": bool(link.get("password_hash")),
    }


def qr_response(document: dict) -> dict:
    return {
        "id": str(document["_id"]),
        "linkId": document["link_id"],
        "shortUrl": document["short_url"],
        "size": document["size"],
        "correction": document["correction"],
        "foreground": document["foreground"],
        "background": document["background"],
        "logo": document.get("logo"),
        "createdAt": document["created_at"].isoformat(),
    }


def generate_code(length: int = 7) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


# Home and authentication

@app.get("/")
async def home():
     return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/auth/google/config")
async def google_auth_config():
    """Expose only the public Google OAuth client ID to the frontend."""
    return {"enabled": bool(GOOGLE_CLIENT_ID), "client_id": GOOGLE_CLIENT_ID or None}


@app.post("/api/auth/google")
async def google_auth(data: GoogleAuthRequest):
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(503, "Google sign-in is not configured")

    try:
        claims = google_id_token.verify_oauth2_token(
            data.credential,
            google_requests.Request(),
            GOOGLE_CLIENT_ID,
        )
    except Exception:
        logger.warning("Google sign-in rejected an invalid ID token")
        raise HTTPException(401, "Google authentication failed. Please try again.")

    email = str(claims.get("email", "")).strip().lower()
    google_sub = claims.get("sub")
    full_name = str(claims.get("name") or claims.get("given_name") or "Shortie user").strip()

    if not email or not google_sub or claims.get("email_verified") is not True:
        raise HTTPException(401, "Google must provide a verified email address")

    user = await users.find_one({"google_sub": google_sub})
    is_new_user = user is None

    if user is None:
        user = await users.find_one({"email": email})

        if user is not None:
            # A verified Google email can be linked to an existing password account.
            if user.get("google_sub") and user["google_sub"] != google_sub:
                raise HTTPException(409, "This email is already linked to another Google account")
            if not user.get("is_active", False):
                raise HTTPException(403, "Account is disabled")
            await users.update_one(
                {"_id": user["_id"]},
                {"$set": {"google_sub": google_sub}, "$addToSet": {"auth_providers": "google"}},
            )
            user["google_sub"] = google_sub
        else:
            # A verified Google identity can create a Shortie account automatically.
            user = {
                "full_name": full_name[:100] or "Shortie user",
                "email": email,
                "password_hash": None,
                "google_sub": google_sub,
                "auth_providers": ["google"],
                "role": "user",
                "is_active": True,
                "created_at": datetime.now(timezone.utc),
            }
            try:
                result = await users.insert_one(user)
                user["_id"] = result.inserted_id
            except DuplicateKeyError:
                # Handle simultaneous first sign-ins without creating duplicates.
                user = await users.find_one({"$or": [{"email": email}, {"google_sub": google_sub}]})
                if not user:
                    raise HTTPException(409, "Could not create your account. Please try again.")

    if not user.get("is_active", False):
        raise HTTPException(403, "Account is disabled")

    return {
        "message": "Google sign-in successful",
        "access_token": make_token(str(user["_id"])),
        "token_type": "bearer",
        "user": safe_user(user),
        "is_new_user": is_new_user,
    }


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

    if not user or not user.get("password_hash") or not password_hash.verify(
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


@app.get("/api/auth/me")
async def current_user(user: dict = Depends(get_current_user)):
    return {"user": user}


@app.patch("/api/settings/profile")
async def update_profile(data: UpdateProfileRequest, user: dict = Depends(get_current_user)):
    full_name = data.full_name.strip()
    if len(full_name) < 2:
        raise HTTPException(400, "Enter a valid name")
    result = await users.update_one({"_id": ObjectId(user["id"])}, {"$set": {"full_name": full_name}})
    if result.matched_count != 1:
        raise HTTPException(404, "Account not found")
    updated = await users.find_one({"_id": ObjectId(user["id"])})
    return {"message": "Profile updated successfully", "user": safe_user(updated)}


@app.patch("/api/settings/password")
async def change_password(data: ChangePasswordRequest, user: dict = Depends(get_current_user)):
    account = await users.find_one({"_id": ObjectId(user["id"])})
    if not account:
        raise HTTPException(404, "Account not found")
    if not account.get("password_hash"):
        raise HTTPException(400, "This account uses Google sign-in and does not have a password yet")
    if not password_hash.verify(data.current_password, account["password_hash"]):
        raise HTTPException(400, "Current password is incorrect")
    if password_hash.verify(data.new_password, account["password_hash"]):
        raise HTTPException(400, "New password must be different from the current password")
    await users.update_one({"_id": ObjectId(user["id"])}, {"$set": {"password_hash": password_hash.hash(data.new_password)}})
    return {"message": "Password changed successfully"}


# URL shortening and link management

@app.post("/api/links", status_code=201)
async def create_link(
    data: CreateLinkRequest,
    user: dict = Depends(get_current_user),
):
    destination = str(data.original_url)

    if urlparse(destination).scheme not in ("http", "https"):
        raise HTTPException(400, "Only HTTP and HTTPS URLs are allowed")

    today = datetime.now(timezone.utc).date()
    if data.expiry_date and data.expiry_date < today:
        raise HTTPException(400, "Expiry date cannot be in the past")
    if data.activation_date and data.expiry_date and data.activation_date > data.expiry_date:
        raise HTTPException(400, "Activation date cannot be after expiry date")

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
        datetime.combine(data.expiry_date, time.max, tzinfo=timezone.utc)
        if data.expiry_date else None
    )
    activation = (
        datetime.combine(data.activation_date, time.min, tzinfo=timezone.utc)
        if data.activation_date else None
    )

    for attempt in range(5):
        document = {
            "code": code,
            "original_url": destination,
            "owner_id": user["id"],
            "created_at": datetime.now(timezone.utc),
            "expiry_date": expiry,
            "activation_date": activation,
            "password_hash": password_hash.hash(data.password) if data.password else None,
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
                    503, "Could not generate a unique code. Please retry."
                )
            code = generate_code()


@app.post("/api/links/bulk-import")
async def bulk_import_links(
    file: UploadFile = File(...),
    user: dict = Depends(get_current_user),
):
    """Create up to 200 links from a CSV file."""
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Upload a .csv file")

    content = await file.read(1_000_001)
    await file.close()
    if len(content) > 1_000_000:
        raise HTTPException(413, "CSV file must be 1 MB or smaller")
    if not content.strip():
        raise HTTPException(400, "The CSV file is empty")

    try:
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
    except UnicodeDecodeError:
        raise HTTPException(400, "CSV must be a valid UTF-8 file")
    if not reader.fieldnames:
        raise HTTPException(400, "CSV must have a header row")
    reader.fieldnames = [name.strip().lower() if name else "" for name in reader.fieldnames]
    if "original_url" not in reader.fieldnames:
        raise HTTPException(400, "CSV must include an original_url column")

    rows = list(reader)
    if not rows:
        raise HTTPException(400, "CSV contains no data rows")
    if len(rows) > 200:
        raise HTTPException(400, "CSV can contain at most 200 data rows")

    results = []
    created_count = 0
    for row_number, raw in enumerate(rows, start=2):
        row = {str(k).strip().lower(): (v or "").strip() for k, v in raw.items() if k}
        try:
            destination = row.get("original_url", "")
            if not destination:
                raise ValueError("original_url is required")
            parsed = urlparse(destination)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ValueError("URL must begin with http:// or https://")
            alias = row.get("alias", "")
            if alias and not re.fullmatch(r"[A-Za-z0-9_-]{3,40}", alias):
                raise ValueError("Alias must be 3–40 letters, numbers, hyphens or underscores")
            expiry = None
            if row.get("expiry_date"):
                try:
                    expiry_day = date.fromisoformat(row["expiry_date"])
                except ValueError:
                    raise ValueError("expiry_date must use YYYY-MM-DD format")
                if expiry_day < datetime.now(timezone.utc).date():
                    raise ValueError("expiry_date cannot be in the past")
                expiry = datetime.combine(expiry_day, time.max, tzinfo=timezone.utc)
            code = alias or generate_code()
            document = {
                "code": code, "original_url": destination, "owner_id": user["id"],
                "created_at": datetime.now(timezone.utc), "expiry_date": expiry,
                "activation_date": None, "password_hash": None, "active": True, "clicks": 0,
            }
            for attempt in range(5):
                try:
                    inserted = await links.insert_one(document)
                    document["_id"] = inserted.inserted_id
                    results.append({"row": row_number, "status": "created", "link": link_response(document)})
                    created_count += 1
                    break
                except DuplicateKeyError:
                    if alias:
                        raise ValueError("Alias already exists")
                    if attempt == 4:
                        raise ValueError("Could not generate a unique short code; retry this row")
                    code = generate_code()
                    document["code"] = code
        except ValueError as exc:
            results.append({"row": row_number, "status": "error", "message": str(exc)})
    return {"created": created_count, "failed": len(results) - created_count, "results": results}


@app.get("/api/links")
async def list_links(user: dict = Depends(get_current_user)):
    cursor = (
        links.find({"owner_id": user["id"]})
        .sort("created_at", -1)
        .limit(500)
    )
    return {
        "links": [link_response(link) async for link in cursor]
    }


@app.patch("/api/links/{link_id}")
async def update_link(
    link_id: str,
    data: UpdateLinkRequest,
    user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(link_id):
        raise HTTPException(400, "Invalid link ID")

    changes = {}

    # Update destination URL
    if data.original_url is not None:
        destination = str(data.original_url)

        if urlparse(destination).scheme not in ("http", "https"):
            raise HTTPException(
                400, "Only HTTP and HTTPS URLs are allowed"
            )

        changes["original_url"] = destination

    # Activate or deactivate the link
    if data.active is not None:
        changes["active"] = data.active

    # Update or remove the expiry date
    if "expiry_date" in data.model_fields_set:
        if data.expiry_date is None:
            # Remove expiry: link will have no expiry date
            changes["expiry_date"] = None
        else:
            today = datetime.now(timezone.utc).date()

            if data.expiry_date < today:
                raise HTTPException(
                    400, "Expiry date cannot be in the past"
                )

            # Keep the link active until the end of the chosen day
            changes["expiry_date"] = datetime.combine(
                data.expiry_date,
                time.max,
                tzinfo=timezone.utc,
            )

    if not changes:
        raise HTTPException(400, "No changes supplied")

    link = await links.find_one_and_update(
        {
            "_id": ObjectId(link_id),
            "owner_id": user["id"],
        },
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
        raise HTTPException(404, "Short link not found in your account")

    if not link.get("active", True):
        raise HTTPException(400, "Cannot save a QR code for a disabled link")

    expiry = link.get("expiry_date")
    if expiry:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            raise HTTPException(400, "Cannot save a QR code for an expired link")

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
async def list_qr_codes(user: dict = Depends(get_current_user)):
    cursor = (
        qr_codes.find({"owner_id": user["id"]})
        .sort("created_at", -1)
        .limit(500)
    )
    return {
        "qr_codes": [qr_response(item) async for item in cursor]
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


# Phase 2: analytics helpers

def analytics_date_range(
    period: str,
    start_date: str | None = None,
    end_date: str | None = None,
):
    today = datetime.now(timezone.utc).date()

    if period == "daily":
        first_day = today
        last_day = today
    elif period == "weekly":
        first_day = today - timedelta(days=today.weekday())
        last_day = first_day + timedelta(days=6)
    elif period == "monthly":
        first_day = today.replace(day=1)
        if first_day.month == 12:
            next_month = date(first_day.year + 1, 1, 1)
        else:
            next_month = date(first_day.year, first_day.month + 1, 1)
        last_day = next_month - timedelta(days=1)
    elif period == "custom":
        if not start_date or not end_date:
            raise HTTPException(
                400, "Custom range requires start_date and end_date"
            )
        try:
            first_day = date.fromisoformat(start_date)
            last_day = date.fromisoformat(end_date)
        except ValueError:
            raise HTTPException(400, "Dates must use YYYY-MM-DD format")

        if first_day > last_day:
            raise HTTPException(400, "start_date must not be after end_date")
        if (last_day - first_day).days > 365:
            raise HTTPException(400, "Custom range cannot exceed 366 days")
    else:
        raise HTTPException(
            400, "period must be daily, weekly, monthly, or custom"
        )

    start = datetime.combine(first_day, time.min, tzinfo=timezone.utc)
    end = datetime.combine(
        last_day + timedelta(days=1),
        time.min,
        tzinfo=timezone.utc,
    )
    return start, end


def classify_user_agent(user_agent: str | None) -> dict:
    ua = (user_agent or "").lower()

    if not ua:
        return {"device": "Unknown", "browser": "Unknown"}

    if any(term in ua for term in (
        "bot", "crawler", "spider", "slurp", "headless"
    )):
        device = "Bot"
    elif any(term in ua for term in ("ipad", "tablet")):
        device = "Tablet"
    elif any(term in ua for term in (
        "mobile", "android", "iphone", "ipod"
    )):
        device = "Mobile"
    else:
        device = "Desktop"

    if "edg/" in ua:
        browser = "Edge"
    elif "opr/" in ua or "opera" in ua:
        browser = "Opera"
    elif "firefox/" in ua:
        browser = "Firefox"
    elif "chrome/" in ua:
        browser = "Chrome"
    elif "safari/" in ua:
        browser = "Safari"
    else:
        browser = "Other"

    return {"device": device, "browser": browser}


async def get_analytics_events(
    owner_id: str,
    start: datetime,
    end: datetime,
):
    return [
        event async for event in click_events.find({
            "owner_id": owner_id,
            "clicked_at": {"$gte": start, "$lt": end},
        }).sort("clicked_at", 1)
    ]


# Analytics overview

@app.get("/api/analytics/overview")
async def analytics_overview(
    period: str = "daily",
    start_date: str | None = None,
    end_date: str | None = None,
    user: dict = Depends(get_current_user),
):
    start, end = analytics_date_range(period, start_date, end_date)
    events = await get_analytics_events(user["id"], start, end)

    devices = Counter()
    browsers = Counter()
    bots = 0

    for event in events:
        result = classify_user_agent(event.get("user_agent"))
        devices[result["device"]] += 1
        browsers[result["browser"]] += 1
        if result["device"] == "Bot":
            bots += 1

    return {
        "period": period,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "total_clicks": len(events),
        "bots_filtered": bots,
        "human_clicks": len(events) - bots,
        "devices": dict(devices),
        "browsers": dict(browsers),
        "unique_visitors": None,
        "qr_scans": None,
    }


# Daily traffic chart

@app.get("/api/analytics/clicks")
async def analytics_clicks(
    period: str = "daily",
    start_date: str | None = None,
    end_date: str | None = None,
    user: dict = Depends(get_current_user),
):
    start, end = analytics_date_range(period, start_date, end_date)
    events = await get_analytics_events(user["id"], start, end)

    counts = Counter()
    for event in events:
        clicked_at = event["clicked_at"]
        if clicked_at.tzinfo is None:
            clicked_at = clicked_at.replace(tzinfo=timezone.utc)
        counts[clicked_at.date().isoformat()] += 1

    output = []
    current_day = start.date()
    while current_day < end.date():
        key = current_day.isoformat()
        output.append({"date": key, "clicks": counts.get(key, 0)})
        current_day += timedelta(days=1)

    return {"period": period, "data": output}


# Top links


@app.get("/api/analytics/top-links")
async def analytics_top_links(
    period: str = "daily",
    start_date: str | None = None,
    end_date: str | None = None,
    user: dict = Depends(get_current_user),
):
    start, end = analytics_date_range(period, start_date, end_date)

    pipeline = [
        {
            "$match": {
                "owner_id": user["id"],
                "clicked_at": {"$gte": start, "$lt": end},
            }
        },
        {
            "$group": {
                "_id": "$link_id",
                "code": {"$first": "$code"},
                "clicks": {"$sum": 1},
            }
        },
        {"$sort": {"clicks": -1}},
        {"$limit": 10},
    ]

    # FIX: Await aggregate() before reading the async cursor.
    cursor = await click_events.aggregate(pipeline)
    results = await cursor.to_list(length=10)

    output = []

    for item in results:
        link_id = item.get("_id")

        if not link_id or not ObjectId.is_valid(link_id):
            continue

        link = await links.find_one({
            "_id": ObjectId(link_id),
            "owner_id": user["id"],
        })

        if link:
            output.append({
                "code": link["code"],
                "short_url": f"{SHORTIE_BASE_URL}/s/{link['code']}",
                "original_url": link["original_url"],
                "clicks": item["clicks"],
            })

    return {"links": output}

# CSV export


@app.get("/api/analytics/export")
async def analytics_export(
    period: str = "daily",
    start_date: str | None = None,
    end_date: str | None = None,
    user: dict = Depends(get_current_user),
):
    start, end = analytics_date_range(
        period, start_date, end_date
    )

    # Load only links owned by the authenticated user.
    owned_links = [
        link async for link in links.find({
            "owner_id": user["id"]
        })
    ]

    links_by_id = {
        str(link["_id"]): link
        for link in owned_links
    }

    # Retrieve individual click events in the selected period.
    events = [
        event async for event in click_events.find({
            "owner_id": user["id"],
            "clicked_at": {"$gte": start, "$lt": end},
        }).sort("clicked_at", 1)
    ]

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Clicked At (UTC)",
        "Short Code",
        "Short URL",
        "Destination URL",
        "Referrer",
        "User Agent",
    ])

    for event in events:
        link = links_by_id.get(event.get("link_id"))

        if not link:
            continue

        clicked_at = event.get("clicked_at")
        if isinstance(clicked_at, datetime):
            clicked_at = clicked_at.isoformat()

        writer.writerow([
            clicked_at or "",
            link["code"],
            f"{SHORTIE_BASE_URL}/s/{link['code']}",
            link.get("original_url", ""),
            event.get("referrer") or "",
            event.get("user_agent") or "",
        ])

    filename = f"shortie-click-events-{period}.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            )
        },
    )

@app.post("/api/links/{code}/verify-password")
async def verify_link_password(
    code: str, data: VerifyLinkPasswordRequest, request: Request
):
    link = await links.find_one({"code": code})
    if not link or not link.get("active", True):
        raise HTTPException(404, "Short link not found or disabled")

    now = datetime.now(timezone.utc)
    activation = link.get("activation_date")
    if activation:
        if activation.tzinfo is None:
            activation = activation.replace(tzinfo=timezone.utc)
        if activation > now:
            raise HTTPException(403, "This link is not active yet")
    expiry = link.get("expiry_date")
    if expiry:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= now:
            raise HTTPException(410, "This short link has expired")

    stored_hash = link.get("password_hash")
    if not stored_hash:
        raise HTTPException(400, "This link does not require a password")
    if not password_hash.verify(data.password, stored_hash):
        raise HTTPException(401, "Incorrect password. Try again.")

    cookie_value, visitor_id, is_new_visitor = visitor_fingerprint(request)
    click_event = {
        "link_id": str(link["_id"]), "code": link["code"],
        "owner_id": link["owner_id"], "clicked_at": now,
        "visitor_id": visitor_id,
        "referrer": request.headers.get("referer"),
        "user_agent": request.headers.get("user-agent"),
    }
    try:
        await click_events.insert_one(click_event)
        await links.update_one({"_id": link["_id"]}, {"$inc": {"clicks": 1}})
    except Exception:
        logger.exception("Failed to record protected link click for %s", code)
    response = JSONResponse({"destination_url": link["original_url"]})
    return set_visitor_cookie(response, cookie_value, is_new_visitor)


# Dashboard metric: distinct tracked visitors for the signed-in owner's links.
@app.get("/api/analytics/unique-visitors")
async def unique_visitors(user: dict = Depends(get_current_user)):
    pipeline = [
        {"$match": {"owner_id": user["id"], "visitor_id": {"$exists": True, "$ne": None}}},
        {"$group": {"_id": "$visitor_id"}},
        {"$count": "total"},
    ]
    cursor = await click_events.aggregate(pipeline)
    result = await cursor.to_list(length=1)
    return {"unique_visitors": result[0]["total"] if result else 0}


# Redirect and click tracking

@app.get("/s/{code}")
async def redirect_short_link(code: str, request: Request):
    link = await links.find_one({"code": code})

    if not link or not link.get("active", True):
        raise HTTPException(404, "Short link not found or disabled")

    expiry = link.get("expiry_date")
    if expiry:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            raise HTTPException(410, "This short link has expired")

    activation = link.get("activation_date")
    if activation:
        if activation.tzinfo is None:
            activation = activation.replace(tzinfo=timezone.utc)
        if activation > datetime.now(timezone.utc):
            raise HTTPException(403, "This link is not active yet")

    if link.get("password_hash"):
        # Serve the visitor page from this FastAPI app, so the route works
        # even when the frontend is not running in a separate Live Server.
        return RedirectResponse(
            url=f"/ProtectedLink.html?code={code}",
            status_code=307,
        )

    cookie_value, visitor_id, is_new_visitor = visitor_fingerprint(request)
    click_event = {
        "link_id": str(link["_id"]),
        "code": link["code"],
        "owner_id": link["owner_id"],
        "clicked_at": datetime.now(timezone.utc),
        "visitor_id": visitor_id,
        "referrer": request.headers.get("referer"),
        "user_agent": request.headers.get("user-agent"),
    }

    try:
        await click_events.insert_one(click_event)
    except Exception:
        logger.exception("Failed to save click event for %s", code)

    try:
        await links.update_one(
            {"_id": link["_id"]},
            {"$inc": {"clicks": 1}},
        )
    except Exception:
        logger.exception("Failed to increment click counter for %s", code)

    response = RedirectResponse(
        url=link["original_url"],
        status_code=307,
    )
    return set_visitor_cookie(response, cookie_value, is_new_visitor)
  


# Custom domain management. DNS ownership verification is real; routing a domain
# to this server still requires DNS and deployment/proxy configuration.
class DomainCreateRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise HTTPException(400, "Enter a domain only, without a path")
        value = parsed.hostname or ""
    if not value or len(value) > 253 or "." not in value:
        raise HTTPException(400, "Enter a valid domain name, such as links.example.com")
    if value == "localhost" or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
        raise HTTPException(400, "Use a public domain name, not localhost or an IP address")
    labels = value.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise HTTPException(400, "Domain name contains invalid characters")
    return value


def serialize_domain(doc: dict) -> dict:
    return {
        "id": str(doc["_id"]), "domain": doc["domain"],
        "status": doc.get("status", "pending"),
        "verification_token": doc["verification_token"],
        "is_default": bool(doc.get("is_default", False)),
        "created_at": doc["created_at"].isoformat(),
        "verified_at": doc.get("verified_at").isoformat() if doc.get("verified_at") else None,
        "dns_target": SHORTIE_BASE_URL.replace("https://", "").replace("http://", "").split("/")[0],
    }


@app.get("/api/domains")
async def list_domains(user: dict = Depends(get_current_user)):
    cursor = domains.find({"owner_id": user["id"]}).sort("created_at", -1)
    return {"domains": [serialize_domain(d) async for d in cursor]}


async def _create_domain_record(data: DomainCreateRequest, user: dict):
    domain = normalize_domain(data.domain)
    existing = await domains.find_one({"owner_id": user["id"], "domain": domain})
    if existing:
        raise HTTPException(409, "This domain has already been added to your account")
    doc = {
        "owner_id": user["id"],
        "domain": domain,
        "status": "pending",
        "verification_token": "shortie-verify=" + secrets.token_urlsafe(24),
        "is_default": False,
        "created_at": datetime.now(timezone.utc),
        "verified_at": None,
    }
    result = await domains.insert_one(doc)
    doc["_id"] = result.inserted_id
    return {
        "domain": serialize_domain(doc),
        "message": "Domain added. Add the requested DNS record, then verify ownership.",
    }


@app.post("/api/domains/create", status_code=201)
async def create_domain(data: DomainCreateRequest, user: dict = Depends(get_current_user)):
    return await _create_domain_record(data, user)


@app.post("/api/domains", status_code=201, include_in_schema=False)
async def create_domain_compat(data: DomainCreateRequest, user: dict = Depends(get_current_user)):
    return await _create_domain_record(data, user)


@app.post("/api/domains/{domain_id}/verify")
async def verify_domain(domain_id: str, user: dict = Depends(get_current_user)):
    if not ObjectId.is_valid(domain_id):
        raise HTTPException(404, "Domain not found")
    doc = await domains.find_one({"_id": ObjectId(domain_id), "owner_id": user["id"]})
    if not doc:
        raise HTTPException(404, "Domain not found")
    try:
        import dns.resolver
        answers = dns.resolver.resolve("_shortie." + doc["domain"], "TXT", lifetime=5)
        records = [part.decode() if isinstance(part, bytes) else str(part) for answer in answers for part in answer.strings]
    except ImportError:
        raise HTTPException(503, "DNS verification needs dnspython. Install it with: pip install dnspython")
    except Exception:
        records = []
    if doc["verification_token"] not in records:
        raise HTTPException(400, "Verification TXT record not found yet. Check your DNS settings and try again.")
    now = datetime.now(timezone.utc)
    await domains.update_one({"_id": doc["_id"]}, {"$set": {"status": "verified", "verified_at": now}})
    doc["status"] = "verified"; doc["verified_at"] = now
    return {"domain": serialize_domain(doc), "message": "Domain ownership verified."}


@app.post("/api/domains/{domain_id}/default")
async def set_default_domain(domain_id: str, user: dict = Depends(get_current_user)):
    if not ObjectId.is_valid(domain_id):
        raise HTTPException(404, "Domain not found")
    doc = await domains.find_one({"_id": ObjectId(domain_id), "owner_id": user["id"]})
    if not doc:
        raise HTTPException(404, "Domain not found")
    if doc.get("status") != "verified":
        raise HTTPException(400, "Verify this domain before setting it as default")
    await domains.update_many({"owner_id": user["id"]}, {"$set": {"is_default": False}})
    await domains.update_one({"_id": doc["_id"]}, {"$set": {"is_default": True}})
    return {"message": "Default domain updated."}


@app.delete("/api/domains/{domain_id}")
async def delete_domain(domain_id: str, user: dict = Depends(get_current_user)):
    if not ObjectId.is_valid(domain_id):
        raise HTTPException(404, "Domain not found")
    result = await domains.delete_one({"_id": ObjectId(domain_id), "owner_id": user["id"]})
    if not result.deleted_count:
        raise HTTPException(404, "Domain not found")
    return {"message": "Domain removed."}


# IMPORTANT: mount the frontend only AFTER registering all API routes.
# A root StaticFiles mount placed earlier intercepts API POST requests and returns 405.
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "Frontend"
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
else:
    logger.warning("Frontend directory not found at %s; static frontend serving is disabled", FRONTEND_DIR)

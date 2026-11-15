
import os
import json
import base64
import http.client
import ipaddress
import socket
import ssl
import time as time_module
import urllib.parse
import urllib.request
import asyncio
import smtplib
from email.message import EmailMessage
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
from urllib.parse import urlparse, quote

import jwt
from bson import ObjectId
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from pydantic import BaseModel, ConfigDict, EmailStr, Field, HttpUrl
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
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()

# Password-reset email configuration. Keep these values in Render Environment,
# never commit real SMTP credentials to GitHub.
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", SMTP_USERNAME).strip()
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"}
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() in {"1", "true", "yes"}
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", SHORTIE_BASE_URL).rstrip("/")
PASSWORD_RESET_TTL_MINUTES = 15
API_KEY_PEPPER = os.getenv("API_KEY_PEPPER", "").strip()
WEBHOOK_SECRET_PEPPER = os.getenv("WEBHOOK_SECRET_PEPPER", "").strip()
WEBHOOK_WORKER_POLL_SECONDS = max(
    1.0, min(float(os.getenv("WEBHOOK_WORKER_POLL_SECONDS", "2")), 60.0)
)
WEBHOOK_MAX_ATTEMPTS = max(
    1, min(int(os.getenv("WEBHOOK_MAX_ATTEMPTS", "6")), 10)
)
WEBHOOK_REQUEST_TIMEOUT_SECONDS = max(
    1.0, min(float(os.getenv("WEBHOOK_REQUEST_TIMEOUT_SECONDS", "8")), 20.0)
)
WEBHOOK_WORKER_CONCURRENCY = max(
    1, min(int(os.getenv("WEBHOOK_WORKER_CONCURRENCY", "4")), 10)
)

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
password_reset_tokens = db["password_reset_tokens"]
campaigns = db["campaigns"]
api_keys = db["api_keys"]
webhooks = db["webhooks"]
webhook_deliveries = db["webhook_deliveries"]

password_hash = PasswordHash.recommended()
bearer_scheme = HTTPBearer(auto_error=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await client.admin.command("ping")

    await users.create_index("email", unique=True)
    await users.create_index("google_sub", unique=True, sparse=True)
    await password_reset_tokens.create_index("token_hash", unique=True)
    await password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)
    await password_reset_tokens.create_index("user_id")
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
    await campaigns.create_index([("owner_id", 1), ("created_at", -1)])
    await api_keys.create_index(
        "key_hash",
        unique=True,
        partialFilterExpression={"key_hash": {"$type": "string"}},
    )
    await api_keys.create_index([("owner_id", 1), ("created_at", -1)])
    await api_keys.create_index("key_prefix")
    await webhooks.create_index([("owner_id", 1), ("created_at", -1)])
    await webhooks.create_index([("owner_id", 1), ("active", 1)])
    await webhook_deliveries.create_index(
        [("event_id", 1), ("webhook_id", 1)],
        unique=True,
        partialFilterExpression={
            "event_id": {"$type": "string"},
            "webhook_id": {"$type": "string"},
        },
    )
    await webhook_deliveries.create_index(
        [("webhook_id", 1), ("created_at", -1)]
    )
    await webhook_deliveries.create_index(
        [("status", 1), ("next_attempt_at", 1)]
    )
    await webhook_deliveries.create_index(
        [("status", 1), ("lease_until", 1)]
    )
    await webhook_deliveries.create_index(
        [("owner_id", 1), ("created_at", -1)]
    )

    logger.info("Shortie database connected successfully")
    stop_worker = asyncio.Event()
    worker_task = asyncio.create_task(
        webhook_delivery_worker(stop_worker),
        name="shortie-webhook-delivery-worker",
    )
    try:
        yield
    finally:
        stop_worker.set()
        try:
            await asyncio.wait_for(
                worker_task,
                timeout=(WEBHOOK_REQUEST_TIMEOUT_SECONDS * 3) + 12,
            )
        except asyncio.TimeoutError:
            worker_task.cancel()
            await asyncio.gather(worker_task, return_exceptions=True)
        finally:
            await client.close()


app = FastAPI(
    title="Shortie API",
    version="1.3.0",
    lifespan=lifespan,
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
        FRONTEND_BASE_URL,
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
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


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=8, max_length=128)


class GoogleAuthRequest(BaseModel):
    credential: str = Field(min_length=20, max_length=10000)
    terms_accepted: bool = False


class GoogleCodeAuthRequest(BaseModel):
    code: str = Field(min_length=10, max_length=10000)
    terms_accepted: bool = False


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


class StrictRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CampaignCreateRequest(StrictRequestModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    channel: Literal[
        "Other", "Social", "Email", "Newsletter", "QR scan",
        "Website", "Paid ads", "Print",
    ] = "Other"
    status: Literal["active", "paused", "archived"] = "active"
    link_ids: list[str] = Field(default_factory=list, max_length=500)


class CampaignUpdateRequest(StrictRequestModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    channel: Literal[
        "Other", "Social", "Email", "Newsletter", "QR scan",
        "Website", "Paid ads", "Print",
    ] | None = None
    status: Literal["active", "paused", "archived"] | None = None
    link_ids: list[str] | None = Field(default=None, max_length=500)


class APIKeyCreateRequest(StrictRequestModel):
    name: str = Field(min_length=2, max_length=60)
    scopes: list[str] = Field(min_length=1, max_length=8)


class WebhookCreateRequest(StrictRequestModel):
    url: str = Field(min_length=1, max_length=2048)
    events: list[str] = Field(min_length=1, max_length=3)


class LinkDefaultsUpdateRequest(StrictRequestModel):
    filter_known_bots: bool | None = None
    check_malicious_urls: bool | None = None
    default_expiry: Literal["never", "7", "30", "90"] | None = None


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

def make_token(user_id: str, token_version: int = 0) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": user_id,
            "ver": token_version,
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
        token_version = payload.get("ver", 0)

        if not isinstance(user_id, str) or not ObjectId.is_valid(user_id):
            raise InvalidTokenError("Invalid user ID")

        if (
            not isinstance(token_version, int)
            or isinstance(token_version, bool)
            or token_version < 0
        ):
            raise InvalidTokenError("Invalid token version")

    except InvalidTokenError:
        raise HTTPException(401, "Invalid or expired token")

    user = await users.find_one({"_id": ObjectId(user_id)})

    if not user or not user.get("is_active", False):
        raise HTTPException(401, "User not found or inactive")

    current_version = user.get("token_version", 0)

    if token_version != current_version:
        raise HTTPException(401, "Session expired. Please log in again.")

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


DEFAULT_LINK_PREFERENCES = {
    "filter_known_bots": True,
    "check_malicious_urls": False,
    "default_expiry": "never",
}

API_KEY_SCOPES = frozenset({
    "links:read",
    "links:write",
    "campaigns:read",
    "campaigns:write",
    "analytics:read",
    "qr_codes:read",
    "qr_codes:write",
    "domains:read",
})
WEBHOOK_EVENTS = frozenset({
    "link.created",
    "link.clicked",
    "link.deleted",
})
WEBHOOK_TEST_EVENT = "webhook.test"
API_KEY_RATE_LIMIT = 60
API_KEY_RATE_WINDOW_SECONDS = 60


def _require_secret(value: str, setting_name: str) -> bytes:
    if len(value) < 32:
        raise HTTPException(
            status_code=503,
            detail=f"{setting_name} must be configured with at least 32 characters.",
        )
    if hmac.compare_digest(value.encode("utf-8"), JWT_SECRET.encode("utf-8")):
        raise HTTPException(
            status_code=503,
            detail=f"{setting_name} must not reuse JWT_SECRET.",
        )
    if setting_name == "WEBHOOK_SECRET_PEPPER" and hmac.compare_digest(
        value.encode("utf-8"),
        API_KEY_PEPPER.encode("utf-8"),
    ):
        raise HTTPException(
            status_code=503,
            detail="WEBHOOK_SECRET_PEPPER must be independent from API_KEY_PEPPER.",
        )
    return value.encode("utf-8")


def hash_api_key(raw_key: str) -> str:
    return hmac.new(
        _require_secret(API_KEY_PEPPER, "API_KEY_PEPPER"),
        raw_key.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def derive_webhook_secret(secret_nonce: str) -> str:
    digest = hmac.new(
        _require_secret(WEBHOOK_SECRET_PEPPER, "WEBHOOK_SECRET_PEPPER"),
        b"shortie-webhook:" + secret_nonce.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return "whsec_" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def validate_api_key_scopes(scopes: list[str]) -> list[str]:
    if not scopes:
        raise HTTPException(422, "Select at least one API key scope.")
    if len(scopes) != len(set(scopes)):
        raise HTTPException(422, "API key scopes must not contain duplicates.")
    invalid = sorted(set(scopes) - API_KEY_SCOPES)
    if invalid:
        raise HTTPException(
            422,
            f"Unsupported API key scope: {', '.join(invalid)}",
        )
    return sorted(scopes)


async def authenticate_api_key(raw_key: str, required_scope: str) -> dict:
    if len(raw_key) > 256 or not re.fullmatch(r"sk_live_[A-Za-z0-9_-]{32,100}", raw_key):
        raise HTTPException(401, "Invalid API key")

    digest = hash_api_key(raw_key)
    prefix = raw_key[:16]
    matches = [
        item async for item in api_keys.find(
            {"key_prefix": prefix},
            {"key_hash": 1, "owner_id": 1, "scopes": 1, "active": 1},
        )
    ]
    key_record = next(
        (
            item for item in matches
            if isinstance(item.get("key_hash"), str)
            and hmac.compare_digest(item["key_hash"], digest)
        ),
        None,
    )
    if not key_record or not key_record.get("active", False):
        raise HTTPException(401, "Invalid or revoked API key")

    if required_scope not in key_record.get("scopes", []):
        raise HTTPException(403, f"API key is missing the {required_scope} scope.")

    owner_id = key_record.get("owner_id")
    if not isinstance(owner_id, str) or not ObjectId.is_valid(owner_id):
        raise HTTPException(401, "Invalid API key owner")
    owner_object_id = ObjectId(owner_id)
    owner = await users.find_one({"_id": owner_object_id})
    if not owner or not owner.get("is_active", False):
        raise HTTPException(401, "API key owner is inactive")

    now = datetime.now(timezone.utc)
    month = now.strftime("%Y-%m")
    rate_cutoff = now - timedelta(seconds=API_KEY_RATE_WINDOW_SECONDS)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    result = await api_keys.update_one(
        {"_id": key_record["_id"], "active": True},
        [
            {
                "$set": {
                    "rate_window_start": {
                        "$cond": [
                            {
                                "$lt": [
                                    {"$ifNull": ["$rate_window_start", epoch]},
                                    rate_cutoff,
                                ]
                            },
                            now,
                            "$rate_window_start",
                        ]
                    },
                    "rate_window_count": {
                        "$cond": [
                            {
                                "$lt": [
                                    {"$ifNull": ["$rate_window_start", epoch]},
                                    rate_cutoff,
                                ]
                            },
                            1,
                            {"$add": [{"$ifNull": ["$rate_window_count", 0]}, 1]},
                        ]
                    },
                    "usage_month": month,
                    "monthly_usage": {
                        "$cond": [
                            {"$eq": ["$usage_month", month]},
                            {"$add": [{"$ifNull": ["$monthly_usage", 0]}, 1]},
                            1,
                        ]
                    },
                    "last_used_at": {
                        "$cond": [
                            {
                                "$lt": [
                                    {"$ifNull": ["$last_used_at", epoch]},
                                    rate_cutoff,
                                ]
                            },
                            now,
                            "$last_used_at",
                        ]
                    },
                }
            }
        ],
    )
    if result.matched_count != 1:
        raise HTTPException(401, "Invalid or revoked API key")
    usage = await api_keys.find_one(
        {"_id": key_record["_id"]},
        {"rate_window_count": 1, "rate_window_start": 1},
    )
    if usage and usage.get("rate_window_count", 0) > API_KEY_RATE_LIMIT:
        retry_after = max(
            1,
            API_KEY_RATE_WINDOW_SECONDS
            - int((now - usage["rate_window_start"]).total_seconds()),
        )
        raise HTTPException(
            429,
            "API key rate limit exceeded.",
            headers={"Retry-After": str(retry_after)},
        )
    return safe_user(owner)


def require_api_scope(required_scope: str):
    async def authenticated_user(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
        api_key: str | None = Header(default=None, alias="X-API-Key"),
    ):
        if api_key is not None:
            if credentials is not None:
                raise HTTPException(
                    400,
                    "Send either a Bearer token or X-API-Key, not both.",
                )
            return await authenticate_api_key(api_key, required_scope)
        return await get_current_user(credentials)

    return authenticated_user


async def get_link_preferences(user_id: str) -> dict:
    user = await users.find_one(
        {"_id": ObjectId(user_id)},
        {"preferences": 1},
    )
    stored = user.get("preferences", {}) if user else {}
    preferences = {**DEFAULT_LINK_PREFERENCES, **(stored if isinstance(stored, dict) else {})}
    if preferences.get("default_expiry") not in {"never", "7", "30", "90"}:
        preferences["default_expiry"] = "never"
    preferences["filter_known_bots"] = bool(preferences["filter_known_bots"])
    preferences["check_malicious_urls"] = bool(preferences["check_malicious_urls"])
    return preferences


async def campaign_response(campaign: dict, owner_id: str) -> dict:
    raw_ids = campaign.get("link_ids", [])
    object_ids = [ObjectId(value) for value in raw_ids if ObjectId.is_valid(value)]
    owned_links = [
        item async for item in links.find(
            {"_id": {"$in": object_ids}, "owner_id": owner_id},
            {"_id": 1},
        )
    ] if object_ids else []
    link_ids = [str(item["_id"]) for item in owned_links]
    clicks = await click_events.count_documents({
        "owner_id": owner_id,
        "link_id": {"$in": link_ids},
    }) if link_ids else 0
    return {
        "id": str(campaign["_id"]),
        "name": campaign["name"],
        "description": campaign.get("description", ""),
        "channel": campaign.get("channel", "Other"),
        "status": campaign.get("status", "active"),
        "link_ids": link_ids,
        "link_count": len(link_ids),
        "clicks": clicks,
        "created_at": campaign["created_at"].isoformat(),
        "updated_at": campaign["updated_at"].isoformat(),
    }


async def validate_campaign_links(link_ids: list[str], owner_id: str) -> list[str]:
    canonical_ids = []
    for link_id in link_ids:
        if not ObjectId.is_valid(link_id):
            raise HTTPException(400, "One or more selected links are invalid.")
        canonical_ids.append(str(ObjectId(link_id)))
    if len(canonical_ids) != len(set(canonical_ids)):
        raise HTTPException(400, "A link can only be associated once.")
    if not canonical_ids:
        return []
    owned_count = await links.count_documents({
        "_id": {"$in": [ObjectId(value) for value in canonical_ids]},
        "owner_id": owner_id,
    })
    if owned_count != len(canonical_ids):
        raise HTTPException(
            400,
            "One or more selected links are unavailable in your account.",
        )
    return canonical_ids


def serialize_api_key(record: dict) -> dict:
    current_month = datetime.now(timezone.utc).strftime("%Y-%m")
    return {
        "id": str(record["_id"]),
        "name": record["name"],
        "prefix": record.get("key_prefix", ""),
        "last_four": record.get("last_four", ""),
        "scopes": record.get("scopes", []),
        "revoked": not record.get("active", False),
        "created_at": record["created_at"].isoformat(),
        "last_used_at": (
            record["last_used_at"].isoformat()
            if record.get("last_used_at") else None
        ),
        "monthly_usage": (
            record.get("monthly_usage", 0)
            if record.get("usage_month") == current_month else 0
        ),
    }


def serialize_webhook(record: dict) -> dict:
    return {
        "id": str(record["_id"]),
        "url": record["url"],
        "events": record.get("events", []),
        "active": bool(record.get("active", False)),
        "created_at": record["created_at"].isoformat(),
        "last_test_at": (
            record["last_test_at"].isoformat()
            if record.get("last_test_at") else None
        ),
    }


async def resolve_public_webhook_target(url: str) -> tuple[str, str, int, str]:
    try:
        parsed = urllib.parse.urlsplit(url)
        host = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port or 443
    except ValueError:
        raise ValueError("Webhook URL is invalid.")

    if (
        parsed.scheme.lower() != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port != 443
        or host in {"localhost"}
        or host.endswith((".localhost", ".local", ".internal", ".test"))
    ):
        raise ValueError("Webhook URLs must use HTTPS on a public host and port 443.")

    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host:
            raise ValueError("Webhook host must be a public DNS name.")
        loop = asyncio.get_running_loop()
        try:
            resolved = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
                timeout=WEBHOOK_REQUEST_TIMEOUT_SECONDS,
            )
        except (OSError, asyncio.TimeoutError):
            raise ValueError("Webhook host could not be resolved.")
        addresses = list(dict.fromkeys(item[4][0] for item in resolved))
    else:
        addresses = [str(literal_ip)]

    if not addresses:
        raise ValueError("Webhook host has no usable address.")
    for address in addresses:
        try:
            parsed_ip = ipaddress.ip_address(address)
        except ValueError:
            raise ValueError("Webhook host resolved to an invalid address.")
        if not parsed_ip.is_global:
            raise ValueError("Webhook host must resolve only to public IP addresses.")

    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    return host, addresses[0], port, target


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float):
        super().__init__(
            host,
            port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._pinned_address = address

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_address, self.port),
            self.timeout,
        )
        self.sock = self._context.wrap_socket(
            self.sock,
            server_hostname=self.host,
        )


def _send_webhook_request(
    host: str,
    address: str,
    port: int,
    target: str,
    body: bytes,
    headers: dict[str, str],
) -> int:
    connection = _PinnedHTTPSConnection(
        host,
        address,
        port,
        WEBHOOK_REQUEST_TIMEOUT_SECONDS,
    )
    try:
        connection.request("POST", target, body=body, headers=headers)
        response = connection.getresponse()
        return response.status
    finally:
        connection.close()


def _build_webhook_signature(secret: str, timestamp: str, body: bytes) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        timestamp.encode("ascii") + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    return "sha256=" + digest


async def enqueue_webhook_deliveries(
    owner_id: str,
    event_type: str,
    data: dict,
    webhook_records: list[dict] | None = None,
) -> str:
    event_id = "evt_" + secrets.token_urlsafe(18)
    now = datetime.now(timezone.utc)
    payload = {
        "id": event_id,
        "type": event_type,
        "created_at": now.isoformat(),
        "data": data,
    }
    if webhook_records is None:
        webhook_records = [
            item async for item in webhooks.find({
                "owner_id": owner_id,
                "active": True,
                "events": event_type,
            })
        ]
    if webhook_records:
        await webhook_deliveries.insert_many(
            [
                {
                    "event_id": event_id,
                    "webhook_id": str(item["_id"]),
                    "owner_id": owner_id,
                    "event_type": event_type,
                    "payload": payload,
                    "status": "pending",
                    "attempts": 0,
                    "max_attempts": WEBHOOK_MAX_ATTEMPTS,
                    "next_attempt_at": now,
                    "last_attempt_at": None,
                    "last_status_code": None,
                    "last_error": None,
                    "lease_until": None,
                    "lease_token": None,
                    "created_at": now,
                    "delivered_at": None,
                }
                for item in webhook_records
            ],
            ordered=False,
        )
    return event_id


async def safely_enqueue_link_event(
    owner_id: str,
    event_type: str,
    data: dict,
):
    try:
        await enqueue_webhook_deliveries(owner_id, event_type, data)
    except Exception:
        logger.exception("Could not persist webhook event %s", event_type)


async def record_click_event(
    link: dict,
    request: Request,
    visitor_id: str,
    clicked_at: datetime,
    increment_if_unrecorded: bool = False,
):
    event = {
        "link_id": str(link["_id"]),
        "code": link["code"],
        "owner_id": link["owner_id"],
        "clicked_at": clicked_at,
        "visitor_id": visitor_id,
        "referrer": request.headers.get("referer"),
        "user_agent": request.headers.get("user-agent"),
    }
    try:
        await click_events.insert_one(event)
    except Exception:
        logger.exception("Failed to record click event for %s", link["code"])
    else:
        try:
            await links.update_one(
                {"_id": link["_id"]},
                {"$inc": {"clicks": 1}},
            )
        except Exception:
            logger.exception(
                "Failed to increment click counter for %s",
                link["code"],
            )
        await safely_enqueue_link_event(
            link["owner_id"],
            "link.clicked",
            {
                "link_id": str(link["_id"]),
                "code": link["code"],
                "clicked_at": clicked_at.isoformat(),
            },
        )
        return True

    if increment_if_unrecorded:
        try:
            await links.update_one(
                {"_id": link["_id"]},
                {"$inc": {"clicks": 1}},
            )
        except Exception:
            logger.exception(
                "Failed to increment click counter for %s",
                link["code"],
            )
    return False


async def _claim_webhook_delivery() -> dict | None:
    now = datetime.now(timezone.utc)
    lease_token = secrets.token_urlsafe(18)

    # A worker may crash after claiming the final allowed attempt. Once that
    # lease expires, mark the delivery failed instead of claiming it again.
    await webhook_deliveries.update_many(
        {
            "status": "processing",
            "lease_until": {"$lte": now},
            "$expr": {
                "$gte": [
                    {"$ifNull": ["$attempts", 0]},
                    {"$ifNull": ["$max_attempts", WEBHOOK_MAX_ATTEMPTS]},
                ]
            },
        },
        {
            "$set": {
                "status": "failed",
                "last_error": (
                    "Maximum delivery attempts reached after worker lease expired."
                ),
                "lease_until": None,
                "lease_token": None,
            }
        },
    )

    # Claim pending or expired deliveries only while attempts remain.
    return await webhook_deliveries.find_one_and_update(
        {
            "$or": [
                {
                    "status": "pending",
                    "next_attempt_at": {"$lte": now},
                    "$expr": {
                        "$lt": [
                            {"$ifNull": ["$attempts", 0]},
                            {"$ifNull": ["$max_attempts", WEBHOOK_MAX_ATTEMPTS]},
                        ]
                    },
                },
                {
                    "status": "processing",
                    "lease_until": {"$lte": now},
                    "$expr": {
                        "$lt": [
                            {"$ifNull": ["$attempts", 0]},
                            {"$ifNull": ["$max_attempts", WEBHOOK_MAX_ATTEMPTS]},
                        ]
                    },
                },
            ]
        },
        {
            "$set": {
                "status": "processing",
                "lease_until": now + timedelta(
                    seconds=(WEBHOOK_REQUEST_TIMEOUT_SECONDS * 3) + 10
                ),
                "lease_token": lease_token,
                "last_attempt_at": now,
            },
            "$inc": {"attempts": 1},
        },
        sort=[("next_attempt_at", 1), ("created_at", 1)],
        return_document=ReturnDocument.AFTER,
    )


async def _finish_webhook_delivery(
    delivery: dict,
    *,
    delivered: bool,
    status_code: int | None = None,
    error: str | None = None,
):
    now = datetime.now(timezone.utc)
    attempts = delivery.get("attempts", 1)
    max_attempts = delivery.get("max_attempts", WEBHOOK_MAX_ATTEMPTS)
    if delivered:
        changes = {
            "status": "delivered",
            "delivered_at": now,
            "last_status_code": status_code,
            "last_error": None,
            "lease_until": None,
            "lease_token": None,
        }
    elif attempts >= max_attempts:
        changes = {
            "status": "failed",
            "last_status_code": status_code,
            "last_error": (error or "Delivery failed")[:500],
            "lease_until": None,
            "lease_token": None,
        }
    else:
        base_delay = min(3600, 5 * (2 ** min(attempts - 1, 10)))
        jitter = 0.5 + secrets.randbelow(1001) / 1000
        changes = {
            "status": "pending",
            "next_attempt_at": now + timedelta(seconds=base_delay * jitter),
            "last_status_code": status_code,
            "last_error": (error or "Delivery failed")[:500],
            "lease_until": None,
            "lease_token": None,
        }
    await webhook_deliveries.update_one(
        {
            "_id": delivery["_id"],
            "status": "processing",
            "lease_token": delivery.get("lease_token"),
        },
        {"$set": changes},
    )


async def _deliver_webhook_delivery(delivery: dict):
    webhook = None
    if ObjectId.is_valid(delivery.get("webhook_id", "")):
        webhook = await webhooks.find_one({
            "_id": ObjectId(delivery["webhook_id"]),
            "owner_id": delivery["owner_id"],
            "active": True,
        })
    if not webhook:
        await webhook_deliveries.update_one(
            {
                "_id": delivery["_id"],
                "status": "processing",
                "lease_token": delivery.get("lease_token"),
            },
            {
                "$set": {
                    "status": "failed",
                    "last_error": "Webhook is no longer active.",
                    "lease_until": None,
                    "lease_token": None,
                }
            },
        )
        return

    try:
        host, address, port, target = await resolve_public_webhook_target(
            webhook["url"]
        )
        secret = derive_webhook_secret(webhook["secret_nonce"])
        body = json.dumps(
            delivery["payload"],
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        timestamp = str(int(time_module.time()))
        status_code = await asyncio.to_thread(
            _send_webhook_request,
            host,
            address,
            port,
            target,
            body,
            {
                "Content-Type": "application/json",
                "X-Shortie-Event-Id": delivery["event_id"],
                "X-Shortie-Event": delivery["event_type"],
                "X-Shortie-Timestamp": timestamp,
                "Host": f"[{host}]" if ":" in host else host,
                "X-Shortie-Signature": _build_webhook_signature(
                    secret,
                    timestamp,
                    body,
                ),
            },
        )
        await _finish_webhook_delivery(
            delivery,
            delivered=200 <= status_code < 300,
            status_code=status_code,
            error=None if 200 <= status_code < 300 else "Endpoint returned a non-2xx response.",
        )
    except Exception as exc:
        await _finish_webhook_delivery(
            delivery,
            delivered=False,
            error=f"Delivery failed ({type(exc).__name__}).",
        )
        logger.warning(
            "Webhook delivery %s failed with %s",
            delivery.get("event_id", "unknown"),
            type(exc).__name__,
        )


async def webhook_delivery_worker(stop_event: asyncio.Event):
    logger.info("Webhook delivery worker started")
    while not stop_event.is_set():
        try:
            batch = []
            for _ in range(WEBHOOK_WORKER_CONCURRENCY):
                delivery = await _claim_webhook_delivery()
                if not delivery:
                    break
                logger.info(
                    "Claimed webhook delivery event_id=%s event_type=%s",
                    delivery.get("event_id", "unknown"),
                    delivery.get("event_type", "unknown"),
                )
                batch.append(delivery)
            if batch:
                await asyncio.gather(
                    *(_deliver_webhook_delivery(item) for item in batch)
                )
                continue
        except Exception:
            logger.exception("Webhook delivery worker encountered an error")

        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=WEBHOOK_WORKER_POLL_SECONDS,
            )
        except asyncio.TimeoutError:
            pass


# Password reset helpers


def _password_reset_email_configured() -> bool:
    required_settings = [
        SMTP_HOST,
        SMTP_PORT,
        SMTP_USERNAME,
        SMTP_PASSWORD,
        SMTP_FROM_EMAIL,
    ]

    if not all(required_settings):
        return False

    placeholder_markers = (
        "your-",
        "replace",
        "placeholder",
        "example",
        "changeme",
        "dummy",
        "xxxx",
    )

    configured_values = [
        SMTP_HOST,
        SMTP_USERNAME,
        SMTP_PASSWORD,
        SMTP_FROM_EMAIL,
    ]

    return not any(
        marker in value.lower()
        for value in configured_values
        for marker in placeholder_markers
    )



def _send_password_reset_email(recipient: str, reset_url: str, expires_minutes: int) -> None:
    message = EmailMessage()
    message["Subject"] = "Reset your Shortie password"
    message["From"] = SMTP_FROM_EMAIL
    message["To"] = recipient
    message.set_content(
        "We received a request to reset your Shortie password.\n\n"
        f"Use this one-time link within {expires_minutes} minutes:\n{reset_url}\n\n"
        "If you did not request this, you can safely ignore this email. "
        "Your password will not change unless you open the link and choose a new password.\n\n"
        "Shortie Support"
    )
    message.add_alternative(
        f"""<!doctype html><html><body style='font-family:Arial,sans-serif;color:#14231e'>
        <h2>Reset your Shortie password</h2>
        <p>We received a request to reset your Shortie password.</p>
        <p><a href=\"{reset_url}\" style='display:inline-block;background:#0c8062;color:#fff;padding:13px 22px;border-radius:8px;text-decoration:none;font-weight:bold'>Reset password</a></p>
        <p>This link expires in <strong>{expires_minutes} minutes</strong> and can only be used once.</p>
        <p>If you did not request this, ignore this email. Your password will not change.</p>
        <p>Shortie Support</p></body></html>""",
        subtype="html",
    )

    if SMTP_USE_SSL:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            if SMTP_USERNAME:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(message)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.ehlo()
            if SMTP_USE_TLS:
                server.starttls()
                server.ehlo()
            if SMTP_USERNAME:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(message)


def exchange_google_authorization_code(code: str) -> str:
    """Exchange a GIS popup authorization code and return Google's ID token."""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(503, "Google sign-in is not fully configured")

    payload = urllib.parse.urlencode({
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": "postmessage",
        "grant_type": "authorization_code",
    }).encode("utf-8")
    request = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            token_data = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        logger.warning("Google authorization-code exchange failed: %s", exc)
        raise HTTPException(401, "Google authentication failed. Please try again.")

    id_token_value = token_data.get("id_token")
    if not id_token_value:
        raise HTTPException(401, "Google did not return a valid identity token")
    return id_token_value


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
    return {
    "enabled": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
    "client_id": GOOGLE_CLIENT_ID if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET else None
}


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
            if not data.terms_accepted:
                raise HTTPException(400, "Please accept the Terms and Privacy Policy before creating your account")
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
        "access_token": make_token(str(user["_id"]),user.get("token_version", 0),),
        "token_type": "bearer",
        "user": safe_user(user),
        "is_new_user": is_new_user,
    }


@app.post("/api/auth/forgot-password")
async def forgot_password(data: ForgotPasswordRequest):
    """Send a one-time 15-minute reset link without revealing whether an email exists."""
    if not _password_reset_email_configured():
        raise HTTPException(
            status_code=503,
            detail="Password recovery email is not configured yet. Please contact Shortie support.",
        )

    email = str(data.email).strip().lower()
    user = await users.find_one({"email": email, "is_active": True})
    if user and user.get("email"):
        now = datetime.now(timezone.utc)
        recent_request = await password_reset_tokens.find_one({
            "user_id": str(user["_id"]),
            "created_at": {"$gt": now - timedelta(seconds=60)},
        })
        if recent_request:
            return {
                "message": "If an active Shortie account exists for that email, a password reset link has been sent. Check your inbox and spam folder."
            }

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        expires_at = now + timedelta(minutes=PASSWORD_RESET_TTL_MINUTES)

        # A newer request invalidates older links for the same account.
        await password_reset_tokens.delete_many({"user_id": str(user["_id"])})
        await password_reset_tokens.insert_one({
            "user_id": str(user["_id"]),
            "token_hash": token_hash,
            "created_at": now,
            "expires_at": expires_at,
        })

        reset_url = (
            f"{FRONTEND_BASE_URL}/reset-password.html?token={quote(raw_token, safe='')}"
        )
        try:
            await asyncio.to_thread(
                _send_password_reset_email,
                email,
                reset_url,
                PASSWORD_RESET_TTL_MINUTES,
            )
        except Exception:
            # Do not leave a usable token behind if delivery fails.
            await password_reset_tokens.delete_one({"token_hash": token_hash})
            logger.exception("Password reset email could not be sent")
            raise HTTPException(
                status_code=503,
                detail="We could not send the reset email. Please try again later.",
            )

    return {
        "message": "If an active Shortie account exists for that email, a password reset link has been sent. Check your inbox and spam folder."
    }



@app.post("/api/auth/reset-password")
async def reset_password(data: ResetPasswordRequest):
    """Validate and consume a reset token, then replace the account password."""
    if not re.search(r"[A-Za-z]", data.new_password) or not re.search(r"\d", data.new_password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one letter and one number.",
        )

    now = datetime.now(timezone.utc)
    token_hash = hashlib.sha256(data.token.encode("utf-8")).hexdigest()

    # Calculate the password hash before opening the transaction.
    new_password_hash = password_hash.hash(data.new_password)

    async def reset_with_transaction(session):
        reset_record = await password_reset_tokens.find_one_and_delete(
            {
                "token_hash": token_hash,
                "expires_at": {"$gt": now},
            },
            session=session,
        )

        if not reset_record:
            raise HTTPException(
                status_code=400,
                detail="This reset link has expired or has already been used. Request a new link.",
            )

        try:
            user_id = ObjectId(reset_record["user_id"])
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="This reset link is invalid. Request a new link.",
            )

        result = await users.update_one(
            {"_id": user_id, "is_active": True},
            {
                "$set": {
                    "password_hash": new_password_hash
                },
                "$inc": {"token_version": 1},
            },
            session=session,
        )

        if result.modified_count != 1:
            raise HTTPException(
                status_code=400,
                detail="This account is unavailable. Request a new reset link.",
            )

        await password_reset_tokens.delete_many(
            {"user_id": str(user_id)},
            session=session,
        )

    async with client.start_session() as session:
        await session.with_transaction(reset_with_transaction)

    return {
        "message": "Your password has been reset successfully. You can now log in."
    }


@app.post("/api/auth/google/code")
async def google_auth_code(data: GoogleCodeAuthRequest):
    """Authenticate a custom frontend button using Google's supported OAuth code flow."""
    id_token_value = exchange_google_authorization_code(data.code)
    # Reuse the existing verified Google account creation/linking logic.
    return await google_auth(GoogleAuthRequest(
        credential=id_token_value,
        terms_accepted=data.terms_accepted,
    ))


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
        "access_token": make_token(str(user["_id"]),user.get("token_version", 0),),
        "token_type": "bearer",
        "user": safe_user(user),
    }


@app.get("/api/auth/me")
async def current_user(user: dict = Depends(get_current_user)):
    return {"user": user}


@app.get("/api/settings/link-defaults")
async def get_link_defaults(user: dict = Depends(get_current_user)):
    preferences = await get_link_preferences(user["id"])
    return {
        **preferences,
        "malicious_url_check_available": False,
        "malicious_url_check_message": (
            "URL reputation checking is not configured. This preference is saved, "
            "but destinations are not scanned or blocked."
        ),
    }


@app.patch("/api/settings/link-defaults")
async def update_link_defaults(
    data: LinkDefaultsUpdateRequest,
    user: dict = Depends(get_current_user),
):
    changes = data.model_dump(exclude_unset=True)
    if not changes or any(value is None for value in changes.values()):
        raise HTTPException(422, "Provide at least one valid link preference.")
    user_object_id = ObjectId(user["id"])
    account = await users.find_one({"_id": user_object_id}, {"preferences": 1})
    if not account:
        raise HTTPException(404, "Account not found.")
    stored = account.get("preferences", {})
    preferences = {
        **DEFAULT_LINK_PREFERENCES,
        **(stored if isinstance(stored, dict) else {}),
        **changes,
    }
    await users.update_one(
        {"_id": user_object_id},
        {"$set": {"preferences": preferences}},
    )
    saved = await get_link_preferences(user["id"])
    return {
        "message": (
            "Link defaults saved. URL reputation checking is unavailable, "
            "so destinations are not scanned or blocked."
        ),
        **saved,
        "malicious_url_check_available": False,
        "malicious_url_check_message": (
            "URL reputation checking is not configured. This preference is saved, "
            "but destinations are not scanned or blocked."
        ),
    }


@app.get("/api/campaigns")
async def list_campaigns(
    user: dict = Depends(require_api_scope("campaigns:read")),
):
    cursor = campaigns.find({"owner_id": user["id"]}).sort("created_at", -1)
    return {
        "campaigns": [
            await campaign_response(item, user["id"])
            async for item in cursor
        ]
    }


@app.post("/api/campaigns", status_code=201)
async def create_campaign(
    data: CampaignCreateRequest,
    user: dict = Depends(require_api_scope("campaigns:write")),
):
    name = data.name.strip()
    if not name:
        raise HTTPException(400, "Campaign name cannot be empty.")
    link_ids = await validate_campaign_links(data.link_ids, user["id"])
    now = datetime.now(timezone.utc)
    document = {
        "owner_id": user["id"],
        "name": name,
        "description": data.description.strip(),
        "channel": data.channel,
        "status": data.status,
        "link_ids": link_ids,
        "created_at": now,
        "updated_at": now,
    }
    result = await campaigns.insert_one(document)
    document["_id"] = result.inserted_id
    return {
        "campaign": await campaign_response(document, user["id"]),
        "message": "Campaign created.",
    }


@app.patch("/api/campaigns/{campaign_id}")
async def update_campaign(
    campaign_id: str,
    data: CampaignUpdateRequest,
    user: dict = Depends(require_api_scope("campaigns:write")),
):
    if not ObjectId.is_valid(campaign_id):
        raise HTTPException(400, "Invalid campaign ID.")
    query = {"_id": ObjectId(campaign_id), "owner_id": user["id"]}
    existing = await campaigns.find_one(query)
    if not existing:
        raise HTTPException(404, "Campaign not found.")
    supplied = data.model_dump(exclude_unset=True)
    if not supplied:
        raise HTTPException(400, "No campaign changes supplied.")
    changes = {}
    if "name" in supplied:
        name = (supplied["name"] or "").strip()
        if not name:
            raise HTTPException(400, "Campaign name cannot be empty.")
        changes["name"] = name
    if "description" in supplied:
        if supplied["description"] is None:
            raise HTTPException(400, "Campaign description cannot be null.")
        changes["description"] = supplied["description"].strip()
    if "channel" in supplied:
        if supplied["channel"] is None:
            raise HTTPException(400, "Campaign channel cannot be null.")
        changes["channel"] = supplied["channel"]
    if "status" in supplied:
        if supplied["status"] is None:
            raise HTTPException(400, "Campaign status cannot be null.")
        changes["status"] = supplied["status"]
    if "link_ids" in supplied:
        if supplied["link_ids"] is None:
            raise HTTPException(400, "Campaign links cannot be null.")
        changes["link_ids"] = await validate_campaign_links(
            supplied["link_ids"],
            user["id"],
        )
    changes["updated_at"] = datetime.now(timezone.utc)
    updated = await campaigns.find_one_and_update(
        query,
        {"$set": changes},
        return_document=ReturnDocument.AFTER,
    )
    if not updated:
        raise HTTPException(404, "Campaign not found.")
    return {
        "campaign": await campaign_response(updated, user["id"]),
        "message": "Campaign updated.",
    }


@app.delete("/api/campaigns/{campaign_id}")
async def delete_campaign(
    campaign_id: str,
    user: dict = Depends(require_api_scope("campaigns:write")),
):
    if not ObjectId.is_valid(campaign_id):
        raise HTTPException(400, "Invalid campaign ID.")
    result = await campaigns.delete_one({
        "_id": ObjectId(campaign_id),
        "owner_id": user["id"],
    })
    if not result.deleted_count:
        raise HTTPException(404, "Campaign not found.")
    return {"message": "Campaign deleted."}


@app.get("/api/api-keys")
async def list_api_keys(user: dict = Depends(get_current_user)):
    cursor = api_keys.find({"owner_id": user["id"]}).sort("created_at", -1)
    return {
        "api_keys": [serialize_api_key(item) async for item in cursor]
    }


@app.post("/api/api-keys", status_code=201)
async def create_api_key(
    data: APIKeyCreateRequest,
    user: dict = Depends(get_current_user),
):
    name = data.name.strip()
    if len(name) < 2:
        raise HTTPException(422, "API key name must contain at least 2 characters.")
    scopes = validate_api_key_scopes(data.scopes)
    raw_key = "sk_live_" + secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    document = {
        "owner_id": user["id"],
        "name": name,
        "key_prefix": raw_key[:16],
        "last_four": raw_key[-4:],
        "key_hash": hash_api_key(raw_key),
        "scopes": scopes,
        "active": True,
        "created_at": now,
        "last_used_at": None,
        "revoked_at": None,
        "usage_month": now.strftime("%Y-%m"),
        "monthly_usage": 0,
        "rate_window_start": now,
        "rate_window_count": 0,
    }
    result = await api_keys.insert_one(document)
    document["_id"] = result.inserted_id
    return {
        "message": "API key created. Copy the secret now; it will not be shown again.",
        "api_key": {**serialize_api_key(document), "key": raw_key},
    }


@app.delete("/api/api-keys/{key_id}")
async def revoke_api_key(key_id: str, user: dict = Depends(get_current_user)):
    if not ObjectId.is_valid(key_id):
        raise HTTPException(404, "API key not found.")
    result = await api_keys.update_one(
        {"_id": ObjectId(key_id), "owner_id": user["id"]},
        {
            "$set": {
                "active": False,
                "revoked_at": datetime.now(timezone.utc),
            }
        },
    )
    if not result.matched_count:
        raise HTTPException(404, "API key not found.")
    return {"message": "API key revoked."}


@app.patch("/api/api-keys/{key_id}/reactivate")
async def reactivate_api_key(
    key_id: str,
    user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(key_id):
        raise HTTPException(404, "API key not found.")
    result = await api_keys.update_one(
        {"_id": ObjectId(key_id), "owner_id": user["id"]},
        {
            "$set": {"active": True, "revoked_at": None},
        },
    )
    if not result.matched_count:
        raise HTTPException(404, "API key not found.")
    return {"message": "API key reactivated."}


@app.delete("/api/api-keys/{key_id}/permanent")
async def permanently_delete_api_key(
    key_id: str,
    user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(key_id):
        raise HTTPException(404, "API key not found.")
    result = await api_keys.delete_one({
        "_id": ObjectId(key_id),
        "owner_id": user["id"],
    })
    if not result.deleted_count:
        raise HTTPException(404, "API key not found.")
    return {"message": "API key permanently deleted."}


@app.get("/api/webhooks")
async def list_webhooks(user: dict = Depends(get_current_user)):
    cursor = webhooks.find({"owner_id": user["id"]}).sort("created_at", -1)
    return {"webhooks": [serialize_webhook(item) async for item in cursor]}


@app.post("/api/webhooks", status_code=201)
async def create_webhook(
    data: WebhookCreateRequest,
    user: dict = Depends(get_current_user),
):
    events = sorted(set(data.events))
    if len(events) != len(data.events):
        raise HTTPException(422, "Webhook events must not contain duplicates.")
    unsupported = sorted(set(events) - WEBHOOK_EVENTS)
    if unsupported:
        raise HTTPException(
            422,
            f"Unsupported webhook event: {', '.join(unsupported)}",
        )
    secret_nonce = secrets.token_urlsafe(32)
    signing_secret = derive_webhook_secret(secret_nonce)
    try:
        await resolve_public_webhook_target(data.url.strip())
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    now = datetime.now(timezone.utc)
    document = {
        "owner_id": user["id"],
        "url": data.url.strip(),
        "events": events,
        "secret_nonce": secret_nonce,
        "active": True,
        "created_at": now,
        "last_test_at": None,
    }
    result = await webhooks.insert_one(document)
    document["_id"] = result.inserted_id
    return {
        "message": "Webhook created. Copy its signing secret now; it will not be shown again.",
        "webhook": serialize_webhook(document),
        "signing_secret": signing_secret,
    }


@app.post("/api/webhooks/{webhook_id}/test", status_code=202)
async def test_webhook(
    webhook_id: str,
    user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(webhook_id):
        raise HTTPException(404, "Webhook not found.")
    webhook = await webhooks.find_one({
        "_id": ObjectId(webhook_id),
        "owner_id": user["id"],
        "active": True,
    })
    if not webhook:
        raise HTTPException(404, "Webhook not found.")
    now = datetime.now(timezone.utc)
    event_id = await enqueue_webhook_deliveries(
        user["id"],
        WEBHOOK_TEST_EVENT,
        {"message": "This is a Shortie test delivery."},
        [webhook],
    )
    await webhooks.update_one(
        {"_id": webhook["_id"], "owner_id": user["id"]},
        {"$set": {"last_test_at": now}},
    )
    return {
        "message": "Test event queued for delivery.",
        "event_id": event_id,
        "status": "pending",
    }


@app.delete("/api/webhooks/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(webhook_id):
        raise HTTPException(404, "Webhook not found.")
    result = await webhooks.delete_one({
        "_id": ObjectId(webhook_id),
        "owner_id": user["id"],
    })
    if not result.deleted_count:
        raise HTTPException(404, "Webhook not found.")
    return {"message": "Webhook deleted."}


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
    await users.update_one(
    {"_id": ObjectId(user["id"])},
    {
        "$set": {
            "password_hash": password_hash.hash(data.new_password)
        },
        "$inc": {"token_version": 1},
    },
)
    return {"message": "Password changed successfully"}


# URL shortening and link management

@app.post("/api/links", status_code=201)
async def create_link(
    data: CreateLinkRequest,
    user: dict = Depends(require_api_scope("links:write")),
):
    destination = str(data.original_url)

    if urlparse(destination).scheme not in ("http", "https"):
        raise HTTPException(400, "Only HTTP and HTTPS URLs are allowed")

    today = datetime.now(timezone.utc).date()
    expiry_date = data.expiry_date
    if expiry_date is None:
        preferences = await get_link_preferences(user["id"])
        default_expiry = preferences["default_expiry"]
        if default_expiry != "never":
            expiry_date = today + timedelta(days=int(default_expiry))
    if expiry_date and expiry_date < today:
        raise HTTPException(400, "Expiry date cannot be in the past")
    if data.activation_date and expiry_date and data.activation_date > expiry_date:
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
        datetime.combine(expiry_date, time.max, tzinfo=timezone.utc)
        if expiry_date else None
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
            await safely_enqueue_link_event(
                user["id"],
                "link.created",
                {
                    "link_id": str(document["_id"]),
                    "code": document["code"],
                    "short_url": f"{SHORTIE_BASE_URL}/s/{document['code']}",
                    "created_at": document["created_at"].isoformat(),
                },
            )
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
    user: dict = Depends(require_api_scope("links:write")),
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
    preferences = await get_link_preferences(user["id"])
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
            elif preferences["default_expiry"] != "never":
                expiry_day = datetime.now(timezone.utc).date() + timedelta(
                    days=int(preferences["default_expiry"])
                )
                expiry = datetime.combine(
                    expiry_day,
                    time.max,
                    tzinfo=timezone.utc,
                )
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
                    await safely_enqueue_link_event(
                        user["id"],
                        "link.created",
                        {
                            "link_id": str(document["_id"]),
                            "code": document["code"],
                            "short_url": f"{SHORTIE_BASE_URL}/s/{document['code']}",
                            "created_at": document["created_at"].isoformat(),
                        },
                    )
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
async def list_links(user: dict = Depends(require_api_scope("links:read"))):
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
    user: dict = Depends(require_api_scope("links:write")),
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
    user: dict = Depends(require_api_scope("links:write")),
):
    if not ObjectId.is_valid(link_id):
        raise HTTPException(400, "Invalid link ID")

    deleted_link = await links.find_one_and_delete({
        "_id": ObjectId(link_id),
        "owner_id": user["id"],
    })

    if not deleted_link:
        raise HTTPException(404, "Link not found")

    await safely_enqueue_link_event(
        user["id"],
        "link.deleted",
        {
            "link_id": str(deleted_link["_id"]),
            "code": deleted_link["code"],
            "deleted_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    return {"message": "Link deleted"}


# QR code endpoints

@app.post("/api/qr-codes", status_code=201)
async def save_qr_code(
    data: SaveQRCodeRequest,
    user: dict = Depends(require_api_scope("qr_codes:write")),
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
async def list_qr_codes(user: dict = Depends(require_api_scope("qr_codes:read"))):
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
    user: dict = Depends(require_api_scope("qr_codes:write")),
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


async def apply_bot_filter(owner_id: str, events: list[dict]):
    preferences = await get_link_preferences(owner_id)
    bot_events = [
        event for event in events
        if classify_user_agent(event.get("user_agent"))["device"] == "Bot"
    ]
    visible_events = (
        [
            event for event in events
            if classify_user_agent(event.get("user_agent"))["device"] != "Bot"
        ]
        if preferences["filter_known_bots"]
        else events
    )
    return visible_events, len(bot_events), preferences["filter_known_bots"]


# Analytics overview

@app.get("/api/analytics/overview")
async def analytics_overview(
    period: str = "daily",
    start_date: str | None = None,
    end_date: str | None = None,
    user: dict = Depends(require_api_scope("analytics:read")),
):
    start, end = analytics_date_range(period, start_date, end_date)
    events = await get_analytics_events(user["id"], start, end)
    metric_events, bot_count, filter_bots = await apply_bot_filter(
        user["id"],
        events,
    )

    devices = Counter()
    browsers = Counter()

    for event in metric_events:
        result = classify_user_agent(event.get("user_agent"))
        devices[result["device"]] += 1
        browsers[result["browser"]] += 1

    return {
        "period": period,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "total_clicks": len(metric_events),
        "bots_filtered": bot_count if filter_bots else 0,
        "bot_clicks": bot_count,
        "human_clicks": len(events) - bot_count,
        "filter_known_bots": filter_bots,
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
    user: dict = Depends(require_api_scope("analytics:read")),
):
    start, end = analytics_date_range(period, start_date, end_date)
    events = await get_analytics_events(user["id"], start, end)
    metric_events, bot_count, filter_bots = await apply_bot_filter(
        user["id"],
        events,
    )

    counts = Counter()
    for event in metric_events:
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

    return {
        "period": period,
        "data": output,
        "bot_clicks": bot_count,
        "filter_known_bots": filter_bots,
    }


# Top links


@app.get("/api/analytics/top-links")
async def analytics_top_links(
    period: str = "daily",
    start_date: str | None = None,
    end_date: str | None = None,
    user: dict = Depends(require_api_scope("analytics:read")),
):
    start, end = analytics_date_range(period, start_date, end_date)
    events = await get_analytics_events(user["id"], start, end)
    metric_events, _, _ = await apply_bot_filter(user["id"], events)
    click_counts = Counter(
        event.get("link_id")
        for event in metric_events
        if event.get("link_id")
    )
    results = click_counts.most_common(10)

    output = []

    for link_id, count in results:

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
                "clicks": count,
            })

    return {"links": output}

# CSV export


@app.get("/api/analytics/export")
async def analytics_export(
    period: str = "daily",
    start_date: str | None = None,
    end_date: str | None = None,
    user: dict = Depends(require_api_scope("analytics:read")),
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
    metric_events, _, _ = await apply_bot_filter(user["id"], events)

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

    for event in metric_events:
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
    await record_click_event(link, request, visitor_id, now)
    response = JSONResponse({"destination_url": link["original_url"]})
    return set_visitor_cookie(response, cookie_value, is_new_visitor)


# Dashboard metric: distinct tracked visitors for the signed-in owner's links.
@app.get("/api/analytics/unique-visitors")
async def unique_visitors(
    user: dict = Depends(require_api_scope("analytics:read")),
):
    events = [
        event async for event in click_events.find({
            "owner_id": user["id"],
            "visitor_id": {"$exists": True, "$ne": None},
        })
    ]
    metric_events, _, filter_bots = await apply_bot_filter(user["id"], events)
    return {
        "unique_visitors": len({
            event["visitor_id"]
            for event in metric_events
            if event.get("visitor_id")
        }),
        "filter_known_bots": filter_bots,
    }


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
    await record_click_event(
        link,
        request,
        visitor_id,
        datetime.now(timezone.utc),
        increment_if_unrecorded=True,
    )

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
async def list_domains(user: dict = Depends(require_api_scope("domains:read"))):
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

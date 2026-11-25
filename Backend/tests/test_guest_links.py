import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException, Request
from pydantic import ValidationError
from pymongo.errors import DuplicateKeyError

from test_feature_helpers import main


class GuestLinkTests(unittest.IsolatedAsyncioTestCase):
    async def test_guest_link_has_five_minute_expiry_and_retries_duplicate_code(self):
        request = Request({"type": "http", "client": ("192.0.2.10", 1234)})
        data = main.CreateGuestLinkRequest(original_url="https://example.org/path")
        start = datetime.now(timezone.utc)
        with (
            patch.object(main, "guest_link_rate_windows") as windows,
            patch.object(main, "guest_links") as links,
            patch.object(main, "generate_code", side_effect=["first", "second"]),
        ):
            windows.update_one = AsyncMock()
            links.insert_one = AsyncMock(side_effect=[DuplicateKeyError("collision"), None])
            result = await main.create_guest_link(data, request)
            self.assertEqual(result["short_url"], f"{main.SHORTIE_BASE_URL}/g/second")
            self.assertGreaterEqual(result["expires_at"], start + timedelta(minutes=5))
            self.assertLessEqual(result["expires_at"], datetime.now(timezone.utc) + timedelta(minutes=5))
            self.assertEqual(links.insert_one.await_args.args[0], {
                "_id": "second",
                "original_url": "https://example.org/path",
                "expires_at": result["expires_at"],
            })

    async def test_expired_record_cannot_redirect_while_waiting_for_cleanup(self):
        now = datetime.now(timezone.utc)
        record = {"_id": "test-code", "original_url": "https://example.org/", "expires_at": now}

        async def find_one(query):
            if record["_id"] == query["_id"] and record["expires_at"] > query["expires_at"]["$gt"]:
                return record

        with patch.object(main, "guest_links") as links:
            links.find_one = AsyncMock(side_effect=find_one)
            with self.assertRaises(HTTPException) as error:
                await main.redirect_guest_link("test-code")
            self.assertEqual(error.exception.status_code, 404)
            self.assertEqual(error.exception.headers["Cache-Control"], "no-store")

            record["expires_at"] += timedelta(minutes=1)
            response = await main.redirect_guest_link("test-code")
            self.assertEqual(response.status_code, 307)
            self.assertEqual(response.headers["location"], "https://example.org/")
            self.assertEqual(response.headers["Cache-Control"], "no-store")

    async def test_rate_limit_denies_new_link_and_returns_retry_after(self):
        request = Request({"type": "http", "client": ("192.0.2.10", 1234)})
        data = main.CreateGuestLinkRequest(original_url="https://example.org/")
        with (
            patch.object(main, "guest_link_rate_windows") as windows,
            patch.object(main, "guest_links") as links,
        ):
            windows.update_one = AsyncMock(side_effect=[
                DuplicateKeyError("bucket already exists"),
                SimpleNamespace(matched_count=0),
            ])
            links.insert_one = AsyncMock()
            with self.assertRaises(HTTPException) as error:
                await main.create_guest_link(data, request)
            self.assertEqual(error.exception.status_code, 429)
            self.assertIn(int(error.exception.headers["Retry-After"]), range(1, 61))
            links.insert_one.assert_not_awaited()

    def test_guest_destination_requires_http_or_https(self):
        with self.assertRaises(ValidationError):
            main.CreateGuestLinkRequest(original_url="ftp://example.org/")


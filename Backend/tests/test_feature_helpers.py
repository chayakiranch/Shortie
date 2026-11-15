import asyncio
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ["MONGODB_URL"] = "mongodb://127.0.0.1:27017"
os.environ["JWT_SECRET"] = "test-only-jwt-secret-0123456789-abcdefghijklmnopqrstuvwxyz"
os.environ["API_KEY_PEPPER"] = "test-only-api-pepper-0123456789-abcdefghijklmnopqrstuvwxyz"
os.environ["WEBHOOK_SECRET_PEPPER"] = (
    "test-only-webhook-pepper-0123456789-abcdefghijklmnopqrstuvwxyz"
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main


class EmptyAsyncCursor:
    def __aiter__(self):
        async def iterate():
            return
            yield None

        return iterate()


class ListAsyncCursor:
    def __init__(self, documents):
        self.documents = documents

    def __aiter__(self):
        async def iterate():
            for document in self.documents:
                yield document

        return iterate()


class FakeCursor(ListAsyncCursor):
    def sort(self, field, direction):
        self.documents.sort(
            key=lambda document: document.get(field),
            reverse=direction < 0,
        )
        return self


class FakeInsertCollection:
    def __init__(self):
        self.documents = []

    async def insert_one(self, document):
        stored = dict(document)
        stored["_id"] = main.ObjectId()
        self.documents.append(stored)
        return SimpleNamespace(inserted_id=stored["_id"])


class FakeUsers:
    def __init__(self, user_id, preferences=None, extra=None):
        self.user_id = main.ObjectId(user_id)
        self.document = {
            "_id": self.user_id,
            "preferences": preferences or {},
            **(extra or {}),
        }

    async def find_one(self, query, projection=None):
        if query.get("_id") != self.user_id:
            return None
        return dict(self.document)

    async def update_one(self, query, update):
        self.document.update(update["$set"])
        return SimpleNamespace(matched_count=1)


class FakeAPIKeys:
    def __init__(self, document):
        self.document = document

    def find(self, query, projection=None):
        matches = (
            [self.document]
            if self.document.get("key_prefix") == query.get("key_prefix")
            else []
        )
        return ListAsyncCursor(matches)

    async def update_one(self, query, pipeline):
        if query.get("_id") != self.document["_id"] or not self.document["active"]:
            return SimpleNamespace(matched_count=0)
        now = datetime.now(timezone.utc)
        window_start = self.document.get("rate_window_start")
        if not window_start or (now - window_start).total_seconds() >= 60:
            self.document["rate_window_start"] = now
            self.document["rate_window_count"] = 1
        else:
            self.document["rate_window_count"] += 1
        month = now.strftime("%Y-%m")
        if self.document.get("usage_month") == month:
            self.document["monthly_usage"] += 1
        else:
            self.document["usage_month"] = month
            self.document["monthly_usage"] = 1
        self.document["last_used_at"] = now
        return SimpleNamespace(matched_count=1)

    async def find_one(self, query, projection=None):
        if query.get("_id") != self.document["_id"]:
            return None
        return {
            "rate_window_count": self.document["rate_window_count"],
            "rate_window_start": self.document["rate_window_start"],
        }


class FakeLinks(FakeInsertCollection):
    def __init__(self, documents=None):
        super().__init__()
        self.documents = documents or []

    async def count_documents(self, query):
        wanted = set(query["_id"]["$in"])
        owner_id = query["owner_id"]
        return sum(
            1 for document in self.documents
            if document["_id"] in wanted and document["owner_id"] == owner_id
        )

    def find(self, query, projection=None):
        wanted = set(query.get("_id", {}).get("$in", []))
        matches = [
            document for document in self.documents
            if document["_id"] in wanted
            and document["owner_id"] == query.get("owner_id")
        ]
        return FakeCursor(matches)


class FakeCampaigns(FakeInsertCollection):
    def find(self, query):
        return FakeCursor([
            document for document in self.documents
            if document["owner_id"] == query.get("owner_id")
        ])

    async def find_one(self, query):
        return next(
            (
                document for document in self.documents
                if document["_id"] == query.get("_id")
                and document["owner_id"] == query.get("owner_id")
            ),
            None,
        )

    async def find_one_and_update(self, query, update, return_document=None):
        document = await self.find_one(query)
        if document:
            document.update(update["$set"])
        return document

    async def delete_one(self, query):
        document = await self.find_one(query)
        if document:
            self.documents.remove(document)
        return SimpleNamespace(deleted_count=1 if document else 0)


class FakeClickEvents:
    def __init__(self, documents=None):
        self.documents = documents or []

    async def count_documents(self, query):
        link_ids = set(query["link_id"]["$in"])
        owner_id = query["owner_id"]
        return sum(
            1 for event in self.documents
            if event["owner_id"] == owner_id and event["link_id"] in link_ids
        )


class FakeWebhooks:
    def find(self, query):
        return EmptyAsyncCursor()


class FakeDeliveries:
    def __init__(self):
        self.update = None

    async def update_one(self, query, update):
        self.update = update
        return SimpleNamespace(matched_count=1)


class FeatureHelperTests(unittest.TestCase):
    def test_api_key_scopes_reject_unknown_and_duplicate_values(self):
        self.assertEqual(
            main.validate_api_key_scopes(["links:read", "analytics:read"]),
            ["analytics:read", "links:read"],
        )
        with self.assertRaises(main.HTTPException):
            main.validate_api_key_scopes(["links:admin"])
        with self.assertRaises(main.HTTPException):
            main.validate_api_key_scopes(["links:read", "links:read"])

    def test_api_key_hash_is_keyed_and_not_the_raw_key(self):
        raw_key = "sk_live_test_only_secret_value"
        digest = main.hash_api_key(raw_key)
        self.assertEqual(len(digest), 64)
        self.assertNotEqual(digest, raw_key)
        self.assertEqual(digest, main.hash_api_key(raw_key))

    def test_api_key_authentication_checks_scope_and_active_owner(self):
        raw_key = "sk_live_" + main.secrets.token_urlsafe(32)
        owner_id = str(main.ObjectId())
        now = datetime.now(timezone.utc)
        key_record = {
            "_id": main.ObjectId(),
            "owner_id": owner_id,
            "key_prefix": raw_key[:16],
            "key_hash": main.hash_api_key(raw_key),
            "scopes": ["links:read"],
            "active": True,
            "rate_window_start": now,
            "rate_window_count": 0,
            "usage_month": now.strftime("%Y-%m"),
            "monthly_usage": 0,
        }
        previous_api_keys = main.api_keys
        previous_users = main.users
        main.api_keys = FakeAPIKeys(key_record)
        main.users = FakeUsers(
            owner_id,
            extra={
                "full_name": "Test Owner",
                "email": "test@example.com",
                "is_active": True,
            },
        )
        try:
            owner = asyncio.run(
                main.authenticate_api_key(raw_key, "links:read")
            )
            self.assertEqual(owner["id"], owner_id)
            self.assertEqual(key_record["rate_window_count"], 1)

            with self.assertRaises(main.HTTPException) as error:
                asyncio.run(
                    main.authenticate_api_key(raw_key, "links:write")
                )
            self.assertEqual(error.exception.status_code, 403)

            key_record["active"] = False
            with self.assertRaises(main.HTTPException) as error:
                asyncio.run(
                    main.authenticate_api_key(raw_key, "links:read")
                )
            self.assertEqual(error.exception.status_code, 401)
        finally:
            main.api_keys = previous_api_keys
            main.users = previous_users

    def test_api_key_is_limited_to_60_requests_per_minute(self):
        raw_key = "sk_live_" + main.secrets.token_urlsafe(32)
        owner_id = str(main.ObjectId())
        now = datetime.now(timezone.utc)
        key_record = {
            "_id": main.ObjectId(),
            "owner_id": owner_id,
            "key_prefix": raw_key[:16],
            "key_hash": main.hash_api_key(raw_key),
            "scopes": ["links:read"],
            "active": True,
            "rate_window_start": now,
            "rate_window_count": 0,
            "usage_month": now.strftime("%Y-%m"),
            "monthly_usage": 0,
        }
        previous_api_keys = main.api_keys
        previous_users = main.users
        main.api_keys = FakeAPIKeys(key_record)
        main.users = FakeUsers(
            owner_id,
            extra={
                "full_name": "Test Owner",
                "email": "test@example.com",
                "is_active": True,
            },
        )
        try:
            for _ in range(main.API_KEY_RATE_LIMIT):
                asyncio.run(
                    main.authenticate_api_key(raw_key, "links:read")
                )
            with self.assertRaises(main.HTTPException) as error:
                asyncio.run(
                    main.authenticate_api_key(raw_key, "links:read")
                )
            self.assertEqual(error.exception.status_code, 429)
        finally:
            main.api_keys = previous_api_keys
            main.users = previous_users

    def test_webhook_signature_covers_timestamp_and_exact_body(self):
        secret = "whsec_test"
        timestamp = "1794691200"
        body = b'{"id":"evt_test","type":"link.created"}'
        signature = main._build_webhook_signature(secret, timestamp, body)
        import hashlib
        import hmac

        expected = hmac.new(
            secret.encode(),
            timestamp.encode() + b"." + body,
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(signature, "sha256=" + expected)
        self.assertNotEqual(
            signature,
            main._build_webhook_signature(secret, str(int(timestamp) + 1), body),
        )

    def test_webhook_target_validation_blocks_private_hosts(self):
        for url in (
            "http://example.com/hook",
            "https://localhost/hook",
            "https://127.0.0.1/hook",
            "https://service.localhost/hook",
            "https://10.0.0.1/hook",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    asyncio.run(main.resolve_public_webhook_target(url))

    def test_webhook_target_returns_public_ip_for_pinned_request(self):
        target = asyncio.run(
            main.resolve_public_webhook_target("https://8.8.8.8/hook?source=test")
        )
        self.assertEqual(
            target,
            ("8.8.8.8", "8.8.8.8", 443, "/hook?source=test"),
        )

    def test_campaign_links_must_belong_to_authenticated_owner(self):
        own_id = main.ObjectId()
        other_id = main.ObjectId()
        previous_links = main.links
        main.links = FakeLinks([
            {"_id": own_id, "owner_id": "owner-a"},
            {"_id": other_id, "owner_id": "owner-b"},
        ])
        try:
            own = asyncio.run(
                main.validate_campaign_links([str(own_id)], "owner-a")
            )
            self.assertEqual(own, [str(own_id)])
            with self.assertRaises(main.HTTPException) as error:
                asyncio.run(
                    main.validate_campaign_links([str(other_id)], "owner-a")
                )
            self.assertEqual(error.exception.status_code, 400)
        finally:
            main.links = previous_links

    def test_campaign_crud_is_owner_scoped_and_uses_recorded_clicks(self):
        owner_id = str(main.ObjectId())
        foreign_owner_id = str(main.ObjectId())
        link_id = main.ObjectId()
        campaign_store = FakeCampaigns()
        link_store = FakeLinks([
            {"_id": link_id, "owner_id": owner_id},
        ])
        click_store = FakeClickEvents([
            {"owner_id": owner_id, "link_id": str(link_id)}
            for _ in range(3)
        ])
        previous = (main.campaigns, main.links, main.click_events)
        main.campaigns = campaign_store
        main.links = link_store
        main.click_events = click_store
        try:
            created = asyncio.run(
                main.create_campaign(
                    main.CampaignCreateRequest(
                        name="Spring campaign",
                        channel="Email",
                        link_ids=[str(link_id)],
                    ),
                    {"id": owner_id},
                )
            )["campaign"]
            self.assertEqual(created["link_count"], 1)
            self.assertEqual(created["clicks"], 3)

            campaign_store.documents.append({
                **campaign_store.documents[0],
                "_id": main.ObjectId(),
                "owner_id": foreign_owner_id,
                "name": "Other user's campaign",
            })
            listed = asyncio.run(main.list_campaigns({"id": owner_id}))
            self.assertEqual(len(listed["campaigns"]), 1)

            changed = asyncio.run(
                main.update_campaign(
                    created["id"],
                    main.CampaignUpdateRequest(status="paused"),
                    {"id": owner_id},
                )
            )
            self.assertEqual(changed["campaign"]["status"], "paused")

            with self.assertRaises(main.HTTPException) as error:
                asyncio.run(
                    main.update_campaign(
                        str(campaign_store.documents[1]["_id"]),
                        main.CampaignUpdateRequest(status="active"),
                        {"id": owner_id},
                    )
                )
            self.assertEqual(error.exception.status_code, 404)

            deleted = asyncio.run(
                main.delete_campaign(created["id"], {"id": owner_id})
            )
            self.assertEqual(deleted["message"], "Campaign deleted.")
            self.assertEqual(len(link_store.documents), 1)
        finally:
            main.campaigns, main.links, main.click_events = previous

    def test_api_key_creation_only_stores_the_hash(self):
        previous_api_keys = main.api_keys
        fake = FakeInsertCollection()
        main.api_keys = fake
        try:
            response = asyncio.run(
                main.create_api_key(
                    main.APIKeyCreateRequest(
                        name="Test integration",
                        scopes=["links:read"],
                    ),
                    {"id": str(main.ObjectId())},
                )
            )
            raw_key = response["api_key"]["key"]
            self.assertTrue(raw_key.startswith("sk_live_"))
            self.assertNotIn(raw_key, str(fake.documents[0]))
            self.assertNotIn("key_hash", response["api_key"])
        finally:
            main.api_keys = previous_api_keys

    def test_webhook_creation_returns_secret_without_storing_it(self):
        previous_webhooks = main.webhooks
        previous_resolver = main.resolve_public_webhook_target
        fake = FakeInsertCollection()

        async def public_target(_url):
            return "hooks.example.com", "8.8.8.8", 443, "/"

        main.webhooks = fake
        main.resolve_public_webhook_target = public_target
        try:
            response = asyncio.run(
                main.create_webhook(
                    main.WebhookCreateRequest(
                        url="https://hooks.example.com/hook",
                        events=["link.created"],
                    ),
                    {"id": str(main.ObjectId())},
                )
            )
            signing_secret = response["signing_secret"]
            self.assertTrue(signing_secret.startswith("whsec_"))
            self.assertNotIn(signing_secret, str(fake.documents[0]))
            self.assertNotIn("secret_nonce", response["webhook"])
        finally:
            main.webhooks = previous_webhooks
            main.resolve_public_webhook_target = previous_resolver

    def test_link_creation_applies_and_preserves_expiry_dates(self):
        user_id = str(main.ObjectId())
        previous_users = main.users
        previous_links = main.links
        previous_webhooks = main.webhooks
        stored_links = FakeInsertCollection()
        main.users = FakeUsers(
            user_id,
            {"default_expiry": "7"},
        )
        main.links = stored_links
        main.webhooks = FakeWebhooks()
        try:
            today = datetime.now(timezone.utc).date()
            result = asyncio.run(
                main.create_link(
                    main.CreateLinkRequest(original_url="https://example.com"),
                    {"id": user_id},
                )
            )
            self.assertEqual(
                result["expiry_date"].date(),
                today + timedelta(days=7),
            )

            explicit_day = today + timedelta(days=30)
            explicit = asyncio.run(
                main.create_link(
                    main.CreateLinkRequest(
                        original_url="https://example.com",
                        expiry_date=explicit_day,
                    ),
                    {"id": user_id},
                )
            )
            self.assertEqual(explicit["expiry_date"].date(), explicit_day)
        finally:
            main.users = previous_users
            main.links = previous_links
            main.webhooks = previous_webhooks

    def test_link_defaults_patch_preserves_other_saved_preferences(self):
        user_id = str(main.ObjectId())
        previous_users = main.users
        fake = FakeUsers(
            user_id,
            {
                "custom_setting": "keep",
                "filter_known_bots": False,
                "default_expiry": "7",
            },
        )
        main.users = fake
        try:
            result = asyncio.run(
                main.update_link_defaults(
                    main.LinkDefaultsUpdateRequest(default_expiry="90"),
                    {"id": user_id},
                )
            )
            self.assertEqual(result["default_expiry"], "90")
            self.assertFalse(fake.document["preferences"]["filter_known_bots"])
            self.assertEqual(
                fake.document["preferences"]["custom_setting"],
                "keep",
            )
            self.assertFalse(result["malicious_url_check_available"])
        finally:
            main.users = previous_users

    def test_bot_filter_setting_changes_analytics_event_set(self):
        owner_id = str(main.ObjectId())
        events = [
            {"user_agent": "Googlebot/2.1"},
            {
                "user_agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
                )
            },
        ]
        previous_users = main.users
        try:
            main.users = FakeUsers(
                owner_id,
                {"filter_known_bots": True},
            )
            filtered, bot_count, enabled = asyncio.run(
                main.apply_bot_filter(owner_id, events)
            )
            self.assertTrue(enabled)
            self.assertEqual(bot_count, 1)
            self.assertEqual(len(filtered), 1)

            main.users = FakeUsers(
                owner_id,
                {"filter_known_bots": False},
            )
            included, bot_count, enabled = asyncio.run(
                main.apply_bot_filter(owner_id, events)
            )
            self.assertFalse(enabled)
            self.assertEqual(bot_count, 1)
            self.assertEqual(len(included), 2)
        finally:
            main.users = previous_users

    def test_failed_webhook_delivery_is_retried_then_terminal(self):
        previous_deliveries = main.webhook_deliveries
        fake = FakeDeliveries()
        main.webhook_deliveries = fake
        now = datetime.now(timezone.utc)
        delivery = {
            "_id": main.ObjectId(),
            "attempts": 1,
            "max_attempts": 3,
            "lease_token": "lease",
        }
        try:
            asyncio.run(
                main._finish_webhook_delivery(
                    delivery,
                    delivered=False,
                    error="temporary failure",
                )
            )
            changes = fake.update["$set"]
            self.assertEqual(changes["status"], "pending")
            self.assertGreater(changes["next_attempt_at"], now)

            delivery["attempts"] = 3
            asyncio.run(
                main._finish_webhook_delivery(
                    delivery,
                    delivered=False,
                    error="permanent failure",
                )
            )
            self.assertEqual(fake.update["$set"]["status"], "failed")
        finally:
            main.webhook_deliveries = previous_deliveries


if __name__ == "__main__":
    unittest.main()

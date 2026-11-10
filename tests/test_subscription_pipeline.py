import unittest
import os
import tempfile
from pathlib import Path

from app.database import DatabaseManager
from app.stripe_service import StripeService
from app.github_client import GitHubClient

class TestSubscriptionPipeline(unittest.TestCase):
    def setUp(self):
        # Create a temporary database for test isolation
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        self.db = DatabaseManager(db_path=self.temp_db.name)

    def tearDown(self):
        try:
            os.remove(self.temp_db.name)
        except OSError:
            pass

    def test_database_free_tier_quota_limit(self):
        org = "cyber-corp"
        quota = self.db.check_scan_quota(org)
        self.assertEqual(quota["tier"], "free")
        self.assertEqual(quota["used"], 0)
        self.assertEqual(quota["limit"], 10)
        self.assertTrue(quota["allowed"])

        # Simulate 10 scans
        for i in range(10):
            self.db.record_scan(org, "backend-repo", i + 1, 45, "MEDIUM")

        # Quota should now be exhausted
        quota_after_10 = self.db.check_scan_quota(org)
        self.assertEqual(quota_after_10["used"], 10)
        self.assertFalse(quota_after_10["allowed"])
        self.assertTrue(quota_after_10["is_over_limit"])

    def test_stripe_upgrade_unlocks_unlimited_scans(self):
        org = "fintech-startup"

        # Fill free quota
        for i in range(10):
            self.db.record_scan(org, "payments-repo", i + 1, 80, "CRITICAL")
        self.assertFalse(self.db.check_scan_quota(org)["allowed"])

        # Simulate Stripe Checkout Completed event
        self.db.upgrade_subscription(
            org_name=org,
            plan_tier="pro",
            stripe_customer_id="cus_12345",
            stripe_subscription_id="sub_67890"
        )

        # Quota should now be unlimited and allowed
        pro_quota = self.db.check_scan_quota(org)
        self.assertEqual(pro_quota["tier"], "pro")
        self.assertEqual(pro_quota["limit"], "unlimited")
        self.assertTrue(pro_quota["allowed"])

    def test_stripe_webhook_event_processing(self):
        stripe_svc = StripeService()
        # Mock event
        event = {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "client_reference_id": "security-lab",
                    "customer": "cus_test_99",
                    "subscription": "sub_test_99"
                }
            }
        }

        # Process with global db instance
        from app.database import db as global_db
        result = stripe_svc.process_webhook_event(event)
        self.assertEqual(result["status"], "upgraded")
        self.assertEqual(result["org_name"], "security-lab")

        quota = global_db.check_scan_quota("security-lab")
        self.assertEqual(quota["tier"], "pro")

    def test_github_paywall_comment_generation(self):
        gh = GitHubClient()
        checkout_url = "https://buy.stripe.com/test?client_reference_id=acme"
        comment = gh.build_paywall_comment(
            org_name="acme",
            used=10,
            limit=10,
            checkout_url=checkout_url
        )

        self.assertIn("## 🔒 RiskRadar Free Limit Reached", comment)
        self.assertIn("10/10 PRs Used", comment)
        self.assertIn(checkout_url, comment)

if __name__ == "__main__":
    unittest.main()

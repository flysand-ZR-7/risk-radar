import os
import hmac
import hashlib
import json
import time
from typing import Dict, Any, Optional
from app.database import db

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PAYMENT_LINK = os.getenv(
    "STRIPE_PAYMENT_LINK",
    "https://buy.stripe.com/test_riskradar_pro_29mo"
)

class StripeService:
    def __init__(self):
        self.secret_key = STRIPE_SECRET_KEY
        self.webhook_secret = STRIPE_WEBHOOK_SECRET
        self.payment_link = STRIPE_PAYMENT_LINK

    def get_checkout_url(self, org_name: str) -> str:
        """
        Builds a customized checkout link passing client_reference_id
        so payments are tied directly to the GitHub organization.
        """
        delimiter = "&" if "?" in self.payment_link else "?"
        return f"{self.payment_link}{delimiter}client_reference_id={org_name}"

    def verify_webhook_signature(self, payload_bytes: bytes, sig_header: Optional[str]) -> bool:
        """
        Cryptographic HMAC-SHA256 verification of Stripe webhook signature.
        Supports standard Stripe signature format: t=timestamp,v1=signature.
        """
        if not self.webhook_secret:
            # In test mode without secret configured, accept payload
            return True

        if not sig_header:
            return False

        try:
            elements = sig_header.split(",")
            timestamp = None
            signatures = []

            for element in elements:
                parts = element.split("=", 1)
                if len(parts) == 2:
                    key, val = parts[0].strip(), parts[1].strip()
                    if key == "t":
                        timestamp = val
                    elif key == "v1":
                        signatures.append(val)

            if not timestamp or not signatures:
                return False

            # Verify timestamp freshness (prevent replay attacks, 5 min tolerance)
            if abs(time.time() - int(timestamp)) > 300:
                return False

            signed_payload = f"{timestamp}.".encode("utf-8") + payload_bytes
            expected_sig = hmac.new(
                self.webhook_secret.encode("utf-8"),
                signed_payload,
                hashlib.sha256
            ).hexdigest()

            return any(hmac.compare_digest(expected_sig, sig) for sig in signatures)
        except Exception as e:
            print(f"[Stripe Webhook Auth Error] {e}")
            return False

    def process_webhook_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes critical Stripe subscription lifecycle events:
        - checkout.session.completed -> Upgrades org to Pro
        - customer.subscription.deleted -> Downgrades org to Free
        - invoice.payment_succeeded -> Resets monthly scan counter
        """
        event_type = event_data.get("type")
        data_object = event_data.get("data", {}).get("object", {})

        if event_type == "checkout.session.completed":
            # Extract organization from client_reference_id or metadata
            org_name = data_object.get("client_reference_id") or data_object.get("metadata", {}).get("org_name")
            customer_id = data_object.get("customer", "")
            subscription_id = data_object.get("subscription", "")

            if org_name:
                db.upgrade_subscription(
                    org_name=org_name,
                    plan_tier="pro",
                    stripe_customer_id=customer_id,
                    stripe_subscription_id=subscription_id
                )
                return {
                    "status": "upgraded",
                    "org_name": org_name,
                    "tier": "pro",
                    "message": f"Successfully upgraded {org_name} to Pro tier."
                }
            return {"status": "ignored", "reason": "No org_name / client_reference_id found"}

        elif event_type in ["customer.subscription.deleted", "customer.subscription.paused"]:
            customer_id = data_object.get("customer")
            # If org_name is passed in subscription metadata
            org_name = data_object.get("metadata", {}).get("org_name")

            if org_name:
                db.cancel_subscription(org_name)
                return {"status": "downgraded", "org_name": org_name, "tier": "free"}

            return {"status": "processed", "event": event_type}

        elif event_type == "invoice.payment_succeeded":
            # Monthly recurring payment succeeded -> reset scan quota
            org_name = data_object.get("subscription_details", {}).get("metadata", {}).get("org_name")
            if org_name:
                db.reset_monthly_scans(org_name)
                return {"status": "reset_scans", "org_name": org_name}

            return {"status": "invoice_paid", "customer": data_object.get("customer")}

        return {"status": "unhandled_event", "type": event_type}

stripe_service = StripeService()

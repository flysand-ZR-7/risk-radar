import sqlite3
import os
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
from contextlib import contextmanager

DEFAULT_DB_PATH = os.getenv("DATABASE_PATH", str(Path(__file__).parent.parent / "riskradar.db"))

@contextmanager
def get_db_cursor(db_path: str = DEFAULT_DB_PATH):
    """Context manager that guarantees transaction commit and connection closure."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn.cursor()
    finally:
        conn.close()

def init_db(db_path: str = DEFAULT_DB_PATH):
    """Initializes SQLite database tables for organizations, subscriptions, and scan logs."""
    with get_db_cursor(db_path) as cursor:
        # Organizations & Subscription state
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                org_name TEXT PRIMARY KEY,
                installation_id INTEGER,
                plan_tier TEXT DEFAULT 'free',
                monthly_scans_used INTEGER DEFAULT 0,
                monthly_scan_limit INTEGER DEFAULT 10,
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                subscription_status TEXT DEFAULT 'inactive',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Audit log of each scanned PR
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_name TEXT NOT NULL,
                repo_name TEXT NOT NULL,
                pr_number INTEGER NOT NULL,
                risk_score INTEGER,
                risk_level TEXT,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (org_name) REFERENCES organizations (org_name)
            );
        """)

class DatabaseManager:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        init_db(self.db_path)

    def get_or_create_org(self, org_name: str, installation_id: Optional[int] = None) -> Dict[str, Any]:
        """Fetches an existing organization or creates a new one on the Free tier (10 scans/mo)."""
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("SELECT * FROM organizations WHERE org_name = ?", (org_name,))
            row = cursor.fetchone()

            if row:
                if installation_id and row["installation_id"] != installation_id:
                    cursor.execute(
                        "UPDATE organizations SET installation_id = ?, updated_at = CURRENT_TIMESTAMP WHERE org_name = ?",
                        (installation_id, org_name)
                    )
                return dict(row)

            # Create default Free tier org
            cursor.execute("""
                INSERT OR IGNORE INTO organizations (org_name, installation_id, plan_tier, monthly_scans_used, monthly_scan_limit, subscription_status)
                VALUES (?, ?, 'free', 0, 10, 'inactive')
            """, (org_name, installation_id))

            cursor.execute("SELECT * FROM organizations WHERE org_name = ?", (org_name,))
            return dict(cursor.fetchone())

    def check_scan_quota(self, org_name: str) -> Dict[str, Any]:
        """
        Enforces the usage limits:
        - Free: 10 PRs per month
        - Pro / Enterprise: Unlimited PRs (limit = -1)
        """
        org = self.get_or_create_org(org_name)
        tier = org["plan_tier"]
        used = org["monthly_scans_used"]
        limit = org["monthly_scan_limit"]

        # Pro / Team / Enterprise tiers have unlimited scans
        if tier in ["pro", "team", "enterprise"]:
            return {
                "allowed": True,
                "tier": tier,
                "used": used,
                "limit": "unlimited",
                "remaining": "unlimited",
                "is_over_limit": False
            }

        # Free tier limit enforcement
        remaining = max(0, limit - used)
        allowed = used < limit

        return {
            "allowed": allowed,
            "tier": tier,
            "used": used,
            "limit": limit,
            "remaining": remaining,
            "is_over_limit": not allowed
        }

    def record_scan(self, org_name: str, repo_name: str, pr_number: int, risk_score: int, risk_level: str):
        """Records an audit log entry and increments the organization's monthly scan counter."""
        # Ensure org exists
        self.get_or_create_org(org_name)

        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("""
                INSERT INTO scan_logs (org_name, repo_name, pr_number, risk_score, risk_level)
                VALUES (?, ?, ?, ?, ?)
            """, (org_name, repo_name, pr_number, risk_score, risk_level))

            cursor.execute("""
                UPDATE organizations
                SET monthly_scans_used = monthly_scans_used + 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE org_name = ?
            """, (org_name,))

    def upgrade_subscription(self, org_name: str, plan_tier: str, stripe_customer_id: str, stripe_subscription_id: str):
        """Activates a paid Pro/Team plan via Stripe webhook."""
        # Ensure org exists
        self.get_or_create_org(org_name)

        with get_db_cursor(self.db_path) as cursor:
            limit = -1 if plan_tier in ["pro", "team", "enterprise"] else 10

            cursor.execute("""
                UPDATE organizations
                SET plan_tier = ?,
                    monthly_scan_limit = ?,
                    stripe_customer_id = ?,
                    stripe_subscription_id = ?,
                    subscription_status = 'active',
                    updated_at = CURRENT_TIMESTAMP
                WHERE org_name = ?
            """, (plan_tier, limit, stripe_customer_id, stripe_subscription_id, org_name))

    def cancel_subscription(self, org_name: str):
        """Downgrades an organization back to Free on cancellation."""
        self.get_or_create_org(org_name)

        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("""
                UPDATE organizations
                SET plan_tier = 'free',
                    monthly_scan_limit = 10,
                    subscription_status = 'canceled',
                    updated_at = CURRENT_TIMESTAMP
                WHERE org_name = ?
            """, (org_name,))

    def reset_monthly_scans(self, org_name: Optional[str] = None):
        """Resets the usage counter at the start of a billing cycle."""
        with get_db_cursor(self.db_path) as cursor:
            if org_name:
                cursor.execute("UPDATE organizations SET monthly_scans_used = 0 WHERE org_name = ?", (org_name,))
            else:
                cursor.execute("UPDATE organizations SET monthly_scans_used = 0")

db = DatabaseManager()

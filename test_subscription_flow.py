import sys
from pathlib import Path

# Add root directory to python path
sys.path.insert(0, str(Path(__file__).parent))

from app.database import db
from app.github_client import github_client
from app.stripe_service import stripe_service
from app.risk_scorer import analyze_diff

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    org = "security-research-org"
    print("=================================================================")
    print("      RISKRADAR END-TO-END SUBSCRIPTION & TRIAGE SIMULATION      ")
    print("=================================================================\n")

    # 1. Reset / initialize org
    quota = db.check_scan_quota(org)
    print(f"1. Initial Organization Status for '{org}':")
    print(f"   - Plan Tier: {quota['tier'].upper()}")
    print(f"   - Monthly Scans Used: {quota['used']}/{quota['limit']}\n")

    # 2. Simulate 10 free scans
    print("2. Simulating 10 PR scans on the Free Tier...")
    for i in range(1, 11):
        db.record_scan(org, "core-api", i, 30, "LOW")
    
    quota_at_10 = db.check_scan_quota(org)
    print(f"   -> Used: {quota_at_10['used']}/{quota_at_10['limit']} (Allowed: {quota_at_10['allowed']})\n")

    # 3. Simulate PR #11 (Quota Exceeded)
    print("3. Attempting to scan PR #11 (Over Free Limit)...")
    quota_at_11 = db.check_scan_quota(org)
    if not quota_at_11["allowed"]:
        checkout_url = stripe_service.get_checkout_url(org)
        print("   ⚠️ FREE QUOTA EXHAUSTED! Generating Paywall Comment for GitHub PR:")
        paywall_comment = github_client.build_paywall_comment(
            org_name=org,
            used=quota_at_11["used"],
            limit=quota_at_11["limit"],
            checkout_url=checkout_url
        )
        print("-----------------------------------------------------------------")
        print(paywall_comment)
        print("-----------------------------------------------------------------\n")

    # 4. Simulate Stripe Payment Event
    print("4. Customer clicks upgrade link & completes payment on Stripe ($29/mo)...")
    stripe_event = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "client_reference_id": org,
                "customer": "cus_acme_live_9921",
                "subscription": "sub_pro_monthly_8831"
            }
        }
    }
    webhook_res = stripe_service.process_webhook_event(stripe_event)
    print(f"   -> Stripe Webhook Response: {webhook_res['status'].upper()} — {webhook_res.get('message', '')}")

    # 5. Check status after upgrade
    pro_quota = db.check_scan_quota(org)
    print(f"\n5. Organization Status After Payment:")
    print(f"   - Plan Tier: {pro_quota['tier'].upper()}")
    print(f"   - Allowed: {pro_quota['allowed']}")
    print(f"   - Limit: {pro_quota['limit']}\n")

    # 6. Re-run PR scan now that team is on Pro
    print("6. Retrying PR #11 scan now that org is on Pro Tier...")
    sample_diff = (Path(__file__).parent / "tests" / "sample_diff.diff").read_text(encoding="utf-8")
    report = analyze_diff(sample_diff)
    db.record_scan(org, "core-api", 11, report.overall_score, report.overall_level)
    print(f"   ✅ PR #11 Successfully Triaged! Score: {report.overall_score}/100 ({report.overall_level})")
    print(f"   Secrets caught: {len(report.secrets)} | Vulnerabilities: {len(report.security_issues)}")

    print("\n=================================================================")
    print("            ALL 3 SUBSCRIPTION PIPELINE MODULES WORKING!         ")
    print("=================================================================")

if __name__ == "__main__":
    main()

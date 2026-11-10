from fastapi import FastAPI, HTTPException, Request, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any

from app.risk_scorer import analyze_diff
from app.database import db
from app.github_client import github_client
from app.stripe_service import stripe_service

app = FastAPI(
    title="RiskRadar AI — PR Risk Triager & Subscription API",
    description="Automated pull request security triager with subscription limits, Stripe webhook handling, and GitHub comment bot.",
    version="1.1.0"
)

class AnalyzeDiffRequest(BaseModel):
    diff: str
    org_name: Optional[str] = "demo-org"
    format: Optional[str] = "markdown"

class AnalyzeDiffResponse(BaseModel):
    overall_score: int
    overall_level: str
    report_markdown: str
    usage: Dict[str, Any]
    data: Dict[str, Any]

@app.get("/health")
def health():
    return {"status": "ok", "service": "RiskRadar AI", "version": "1.1.0"}

# -------------------------------------------------------------
# 1. Direct Analysis API (with usage quota enforcement)
# -------------------------------------------------------------
@app.post("/api/v1/analyze", response_model=AnalyzeDiffResponse)
def analyze_pr_diff(payload: AnalyzeDiffRequest):
    if not payload.diff.strip():
        raise HTTPException(status_code=400, detail="Diff cannot be empty.")

    org_name = payload.org_name or "demo-org"
    quota = db.check_scan_quota(org_name)

    if not quota["allowed"]:
        checkout_url = stripe_service.get_checkout_url(org_name)
        raise HTTPException(
            status_code=402,
            detail={
                "error": "Scan limit reached",
                "message": f"Organization '{org_name}' has reached the {quota['limit']} free monthly PR scans limit.",
                "checkout_url": checkout_url
            }
        )

    # Run analysis
    report = analyze_diff(payload.diff)

    # Record scan in database
    db.record_scan(
        org_name=org_name,
        repo_name="api-direct",
        pr_number=0,
        risk_score=report.overall_score,
        risk_level=report.overall_level
    )

    # Get updated quota
    updated_quota = db.check_scan_quota(org_name)

    return AnalyzeDiffResponse(
        overall_score=report.overall_score,
        overall_level=report.overall_level,
        report_markdown=report.to_markdown(),
        usage=updated_quota,
        data=report.to_dict()
    )

# -------------------------------------------------------------
# 2. GitHub App Webhook Receiver & Automated Commenter
# -------------------------------------------------------------
@app.post("/api/v1/github/webhook")
async def github_webhook(request: Request, x_github_event: Optional[str] = Header(None)):
    """
    Handles GitHub pull_request webhooks:
    - Enforces free tier 10-PR limits
    - Posts Paywall comment if limit reached
    - Posts Risk Triage checklist comment if allowed
    """
    event = x_github_event or "unknown"
    payload = await request.json()

    action = payload.get("action")
    pr_data = payload.get("pull_request")
    installation = payload.get("installation", {})
    installation_id = installation.get("id")

    if event == "pull_request" and action in ["opened", "synchronize", "reopened"]:
        pr_number = pr_data.get("number")
        repo_data = payload.get("repository", {})
        repo_full_name = repo_data.get("full_name", "unknown/repo")
        owner = repo_data.get("owner", {}).get("login", "unknown")
        repo_name = repo_data.get("name", "repo")

        # 1. Check Usage Quota
        quota = db.check_scan_quota(owner)
        checkout_url = stripe_service.get_checkout_url(owner)

        if not quota["allowed"]:
            # Quota exceeded -> Post Paywall comment to PR
            paywall_comment = github_client.build_paywall_comment(
                org_name=owner,
                used=quota["used"],
                limit=quota["limit"],
                checkout_url=checkout_url
            )
            comment_result = github_client.post_pr_comment(
                owner=owner,
                repo=repo_name,
                pull_number=pr_number,
                markdown_body=paywall_comment,
                installation_id=installation_id
            )
            return {
                "status": "limit_reached",
                "org": owner,
                "used": quota["used"],
                "limit": quota["limit"],
                "comment": comment_result
            }

        # 2. Quota is OK -> Fetch diff
        diff_text = github_client.fetch_pr_diff(
            owner=owner,
            repo=repo_name,
            pull_number=pr_number,
            installation_id=installation_id
        )

        if not diff_text:
            diff_text = payload.get("diff_content", "")

        if not diff_text:
            return {"status": "skipped", "reason": "No diff content available."}

        # 3. Analyze diff
        report = analyze_diff(diff_text)
        report_markdown = report.to_markdown()

        # Add upgrade / pro footer
        if quota["tier"] == "free":
            footer = f"\n> ℹ️ **{owner}** has used {quota['used'] + 1}/{quota['limit']} free monthly scans. [Upgrade to Pro]({checkout_url})"
            report_markdown += footer

        # 4. Post Review Comment to GitHub PR
        comment_result = github_client.post_pr_comment(
            owner=owner,
            repo=repo_name,
            pull_number=pr_number,
            markdown_body=report_markdown,
            installation_id=installation_id
        )

        # 5. Record scan in database
        db.record_scan(
            org_name=owner,
            repo_name=repo_full_name,
            pr_number=pr_number,
            risk_score=report.overall_score,
            risk_level=report.overall_level
        )

        return {
            "status": "scanned",
            "org": owner,
            "pr_number": pr_number,
            "risk_score": report.overall_score,
            "risk_level": report.overall_level,
            "comment": comment_result
        }

    return {"status": "ignored", "event": event, "action": action}

# -------------------------------------------------------------
# 3. Stripe Subscription Webhook Handler
# -------------------------------------------------------------
@app.post("/api/v1/stripe/webhook")
async def stripe_webhook(request: Request, stripe_signature: Optional[str] = Header(None)):
    """
    Receives Stripe webhooks to automatically upgrade/downgrade organizations.
    """
    body_bytes = await request.body()

    # Cryptographic signature validation
    if not stripe_service.verify_webhook_signature(body_bytes, stripe_signature):
        raise HTTPException(status_code=400, detail="Invalid Stripe signature.")

    try:
        event_data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    result = stripe_service.process_webhook_event(event_data)
    return {"received": True, "result": result}

# -------------------------------------------------------------
# 4. Billing & Organization Management Endpoints
# -------------------------------------------------------------
@app.get("/api/v1/billing/status")
def get_billing_status(org: str):
    """Returns current tier, scan usage, and limits for an organization."""
    return db.check_scan_quota(org)

@app.get("/api/v1/billing/checkout-url")
def get_checkout_url(org: str):
    """Returns a direct Stripe Checkout URL configured for this organization."""
    return {
        "org": org,
        "checkout_url": stripe_service.get_checkout_url(org)
    }

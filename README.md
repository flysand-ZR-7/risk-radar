# 🛡️ RiskRadar AI — Automated PR Risk Triager

> Stop rubber-stamping massive AI-generated pull requests. Tell reviewers where to focus in seconds.

## 💡 The Problem
With AI coding assistants (Copilot, Cursor, Devin, Claude Code), pull requests have grown from 150 lines to 3,000–30,000 lines. Engineering teams are overwhelmed and rubber-stamping changes without reading them, allowing hardcoded secrets, misconfigured CORS, and severe security flaws to enter production.

## 🚀 What RiskRadar Does
- **Triage & Priority Ranking**: Computes an objective risk score (0-100) per file and outputs a clean, prioritized review order.
- **Secret & Token Leak Scanner**: Detects exposed Stripe keys, OpenAI tokens, AWS credentials, and private keys in newly added lines before they are merged.
- **Security Anti-Pattern Detection**: Flags permissive CORS (`allow_origins=["*"]` + `credentials=True`), dynamic SQL injections, RCE sinks, and unauthenticated debug backdoors.
- **Test Ratio Alerting**: Calculates production-to-test code churn and warns teams when large business logic diffs arrive without tests.

---

## 🛠️ Quick Start

### 1. Test Demo Diff Directly
Run the standalone demo script against a sample AI-generated pull request:
```bash
python run_demo.py
```

### 2. Run API Server (FastAPI)
Install dependencies and run the server:
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
Open interactive Swagger docs at: `http://localhost:8000/docs`

### 3. Run Test Suite
```bash
python -m unittest discover -s tests
```

---

## 🔌 API Endpoints

### `POST /api/v1/analyze`
Send raw git diff text to receive triage metrics and a formatted markdown comment:
```json
{
  "diff": "diff --git a/backend/main.py ...",
  "format": "markdown"
}
```

### `POST /api/v1/github/webhook`
Receives GitHub App webhook payloads (`pull_request.opened`, `pull_request.synchronize`) to post automated review checklists directly on PR threads.

---

## 💼 Monetization Model
- **Free Tier**: 10 PR scans / month (Acquisition funnel on GitHub Marketplace).
- **Pro Tier ($29/month)**: Unlimited PR scans, custom risk thresholds.
- **Team Tier ($19/seat/month)**: Full team triage, Slack/Discord alerts, custom regex rules.

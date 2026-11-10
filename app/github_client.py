import os
import time
import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

try:
    import jwt
    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False

GITHUB_APP_ID = os.getenv("GITHUB_APP_ID", "")
GITHUB_PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY", "")
GITHUB_PRIVATE_KEY_PATH = os.getenv("GITHUB_PRIVATE_KEY_PATH", "")

def get_private_key_pem() -> Optional[str]:
    """Retrieves GitHub App Private Key from env or file path."""
    if GITHUB_PRIVATE_KEY:
        return GITHUB_PRIVATE_KEY
    if GITHUB_PRIVATE_KEY_PATH and os.path.exists(GITHUB_PRIVATE_KEY_PATH):
        with open(GITHUB_PRIVATE_KEY_PATH, "r", encoding="utf-8") as f:
            return f.read()
    return None

class GitHubClient:
    def __init__(self):
        self.app_id = GITHUB_APP_ID
        self.private_key = get_private_key_pem()

    def is_configured(self) -> bool:
        """Returns True if GitHub App credentials are set up for live calls."""
        return bool(self.app_id and self.private_key and HAS_PYJWT)

    def _generate_app_jwt(self) -> Optional[str]:
        """Generates a 10-minute RS256 JWT for GitHub App authentication."""
        if not self.is_configured():
            return None

        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + (10 * 60),
            "iss": self.app_id
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    def get_installation_token(self, installation_id: int) -> Optional[str]:
        """Exchanges App JWT for an installation access token."""
        app_jwt = self._generate_app_jwt()
        if not app_jwt:
            return None

        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "RiskRadar-AI-Triage"
        }

        try:
            req = urllib.request.Request(url, headers=headers, method="POST")
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("token")
        except Exception as e:
            print(f"[RiskRadar GitHub Error] Failed to get installation token: {e}")
            return None

    def fetch_pr_diff(self, owner: str, repo: str, pull_number: int, installation_id: Optional[int] = None) -> Optional[str]:
        """Fetches the raw unified git diff for a pull request."""
        token = self.get_installation_token(installation_id) if installation_id else None
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pull_number}"

        headers = {
            "Accept": "application/vnd.github.v3.diff",
            "User-Agent": "RiskRadar-AI-Triage"
        }
        if token:
            headers["Authorization"] = f"token {token}"

        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            print(f"[RiskRadar GitHub Error] Failed to fetch PR diff: {e}")
            return None

    def post_pr_comment(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        markdown_body: str,
        installation_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Posts a triage checklist or paywall comment on the GitHub PR thread.
        Falls back to safe simulation mode if credentials are not configured.
        """
        if not self.is_configured() or not installation_id:
            # Simulated mode for local development / testing without live credentials
            return {
                "status": "simulated",
                "target": f"{owner}/{repo}#{pull_number}",
                "body_length": len(markdown_body),
                "message": "Comment prepared (simulated - configure GITHUB_APP_ID to post live)."
            }

        token = self.get_installation_token(installation_id)
        if not token:
            return {"status": "error", "message": "Could not authenticate with GitHub App token."}

        url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pull_number}/comments"
        payload = json.dumps({"body": markdown_body}).encode("utf-8")
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "RiskRadar-AI-Triage"
        }

        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                return {
                    "status": "success",
                    "comment_id": resp_data.get("id"),
                    "html_url": resp_data.get("html_url")
                }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @staticmethod
    def build_paywall_comment(org_name: str, used: int, limit: int, checkout_url: str) -> str:
        """Generates high-converting paywall markdown when free tier quota is reached."""
        return f"""## 🔒 RiskRadar Free Limit Reached ({used}/{limit} PRs Used)

Hello! Your organization **`{org_name}`** has exhausted the {limit} free monthly PR scans.

Large AI-generated diffs are now being merged without security triage.

### 🚀 Upgrade to RiskRadar Pro ($29/month)
- **Unlimited Pull Request Scans**
- **Automated Secret & API Key Leak Detection** (Stripe, OpenAI, AWS)
- **CORS Misconfiguration & SQL Injection Alerting**
- **Prioritized File-by-File Review Order**

👉 **[Click Here to Upgrade to Pro ($29/mo)]({checkout_url})**

*Once subscribed, this PR and all future PRs will be automatically triaged immediately.*
---
*Powered by [RiskRadar AI](https://github.com)*"""

github_client = GitHubClient()

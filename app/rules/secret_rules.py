import re
from typing import List, Dict, Any

SECRET_REGEX_PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "severity": "CRITICAL"
    },
    {
        "name": "OpenAI / LLM API Key",
        "pattern": r"sk-[a-zA-Z0-9]{20,T3BlbkFJ[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{40,}",
        "severity": "CRITICAL"
    },
    {
        "name": "GitHub Token",
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
        "severity": "CRITICAL"
    },
    {
        "name": "Stripe Live Secret Key",
        "pattern": r"(?:sk|rk)_live_[0-9a-zA-Z]{24,34}",
        "severity": "CRITICAL"
    },
    {
        "name": "Google API Key",
        "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
        "severity": "CRITICAL"
    },
    {
        "name": "Slack Webhook / Token",
        "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+|xox[baprs]-[0-9a-zA-Z]{10,48}",
        "severity": "CRITICAL"
    },
    {
        "name": "Private Key Block",
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "CRITICAL"
    },
    {
        "name": "Hardcoded Credential Assignment",
        "pattern": r"""(?i)(?:api_key|apikey|secret_key|auth_token|access_token|password|passwd|client_secret)\s*[:=]\s*['"][a-zA-Z0-9_\-\.\$\!\#\%\^\&\*]{10,}['"]""",
        "severity": "HIGH"
    }
]

# Patterns that look like mock/test secrets
FALSE_POSITIVE_PATTERNS = [
    r"example", r"dummy", r"mock", r"test", r"placeholder", r"<your-", r"xxxx", r"0000"
]

def scan_line_for_secrets(line: str, line_no: int = 0) -> List[Dict[str, Any]]:
    """Scans an added line of code for leaked secrets or API tokens."""
    findings = []
    line_clean = line.strip()

    for rule in SECRET_REGEX_PATTERNS:
        matches = re.finditer(rule["pattern"], line_clean)
        for match in matches:
            matched_str = match.group(0)
            
            # Check false positives
            if any(fp in matched_str.lower() for fp in FALSE_POSITIVE_PATTERNS):
                continue
                
            # Mask the secret for safe display
            if len(matched_str) > 8:
                masked = matched_str[:4] + "*" * (len(matched_str) - 8) + matched_str[-4:]
            else:
                masked = "****"

            findings.append({
                "rule": rule["name"],
                "severity": rule["severity"],
                "line_no": line_no,
                "masked_secret": masked,
                "description": f"Potential {rule['name']} detected: `{masked}`"
            })

    return findings

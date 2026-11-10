import re
from typing import List, Dict, Any

SECURITY_ANTI_PATTERNS = [
    {
        "name": "Permissive CORS with Credentials",
        "pattern": r"""(?i)(allow_origins\s*=\s*\[\s*['"]\*['"]\s*\][\s\S]{0,100}allow_credentials\s*=\s*True|allow_credentials\s*=\s*True[\s\S]{0,100}allow_origins\s*=\s*\[\s*['"]\*['"]\s*\])""",
        "line_pattern": r"""(?i)(allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|allow_credentials\s*=\s*True|access-control-allow-origin:\s*\*)""",
        "severity": "HIGH",
        "description": "Wildcard CORS origin (`*`) with credentials enabled or overly permissive origin matching."
    },
    {
        "name": "Dangerous Execution (RCE risk)",
        "pattern": None,
        "line_pattern": r"""(?i)(eval\(|exec\(|os\.system\(|subprocess\.Popen\(.*shell\s*=\s*True|child_process\.exec\()""",
        "severity": "CRITICAL",
        "description": "Dangerous execution sink detected (`eval`, `exec`, `os.system`, `shell=True`)."
    },
    {
        "name": "SQL Injection (Dynamic String Formatting)",
        "pattern": None,
        "line_pattern": r"""(?i)((?:sql|query|stmt|statement)\s*=\s*f['"].*(?:SELECT|INSERT|UPDATE|DELETE)|execute\s*\(\s*f['"].*(?:SELECT|INSERT|UPDATE|DELETE)|\.execute\s*\(\s*['"].*%\s*\(|\.execute\s*\(\s*(?:sql|query|stmt)\s*\))""",
        "severity": "HIGH",
        "description": "Unsanitized dynamic string interpolation inside a SQL execution block."
    },
    {
        "name": "TLS/SSL Verification Disabled",
        "pattern": None,
        "line_pattern": r"""(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]|CURLOPT_SSL_VERIFYPEER\s*,\s*0)""",
        "severity": "HIGH",
        "description": "TLS/SSL certificate validation explicitly disabled."
    },
    {
        "name": "Insecure Deserialization",
        "pattern": None,
        "line_pattern": r"""(?i)(pickle\.loads|yaml\.load\([^,)]+\)|unserialize\()""",
        "severity": "HIGH",
        "description": "Insecure object deserialization sink (e.g. unsafe pickle or yaml.load)."
    },
    {
        "name": "Exposed Debug or Internal Route",
        "pattern": None,
        "line_pattern": r"""(?i)(@(app|router)\.(get|post|put|delete)\(['"]/(debug|internal|admin/bypass|test-login|backdoor))""",
        "severity": "HIGH",
        "description": "Potentially unauthenticated debug, internal, or test endpoint exposed in API routes."
    }
]

def scan_hunk_for_security_issues(hunk_content: str, added_lines: List[tuple]) -> List[Dict[str, Any]]:
    """
    Scans a hunk's added lines for security vulnerabilities.
    added_lines: list of (line_no, line_content)
    """
    findings = []

    # Check multi-line pattern in the whole hunk block
    for anti_pattern in SECURITY_ANTI_PATTERNS:
        if anti_pattern.get("pattern"):
            if re.search(anti_pattern["pattern"], hunk_content):
                findings.append({
                    "rule": anti_pattern["name"],
                    "severity": anti_pattern["severity"],
                    "line_no": 0,
                    "description": anti_pattern["description"]
                })

    # Check line-by-line patterns
    for line_no, line in added_lines:
        line_clean = line.strip()
        for anti_pattern in SECURITY_ANTI_PATTERNS:
            line_regex = anti_pattern.get("line_pattern")
            if line_regex and re.search(line_regex, line_clean):
                # Avoid duplicate if already reported by multi-line regex
                if any(f["rule"] == anti_pattern["name"] and f["line_no"] == line_no for f in findings):
                    continue
                findings.append({
                    "rule": anti_pattern["name"],
                    "severity": anti_pattern["severity"],
                    "line_no": line_no,
                    "description": f"{anti_pattern['description']} (at line {line_no})"
                })

    return findings

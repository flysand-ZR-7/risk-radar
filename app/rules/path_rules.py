import re
from typing import Dict, Any

CRITICAL_PATH_PATTERNS = [
    r"(^|/)(auth|authentication|oauth|jwt|session|login|signup|password|crypto|cipher|kms)($|/|\.)",
    r"(^|/)(billing|payment|stripe|paypal|checkout|wallet|invoice)($|/|\.)",
    r"(^|/)(secret|credential|\.env|vault|privkey|id_rsa|cert|token)($|/|\.)",
    r"(^|/)(rbac|permission|role|iam|policy|firewall)($|/|\.)",
    r"(\.pem|\.key|\.p12|\.keystore)$",
]

HIGH_PATH_PATTERNS = [
    r"(^|/)(migration|alembic|flyway|seed)($|/|\.)",
    r"(^|/)(middleware|router|routes|api|endpoint|gateway)($|/|\.)",
    r"(^|/)(docker|dockerfile|k8s|kubernetes|terraform|helm|\.github/workflows)($|/|\.)",
    r"(\.ya?ml|\.tf|\.conf|\.toml|\.ini)$",
]

LOW_PATH_PATTERNS = [
    r"(^|/)(test|tests|spec|specs|__tests__|testing|mock|mocks|fixture|fixtures)($|/|\.)",
    r"(^|/)(doc|docs|documentation|readme|changelog|license)($|/|\.)",
    r"(\.md|\.txt|\.svg|\.png|\.jpg|\.jpeg|\.ico|\.css|\.scss)$",
]

def evaluate_path_risk(filepath: str) -> Dict[str, Any]:
    """
    Evaluates risk based on file location and naming.
    Returns:
        level: 'CRITICAL', 'HIGH', 'NORMAL', 'LOW'
        score_modifier: added risk weight
        reason: human-readable explanation
    """
    path_lower = filepath.lower().replace("\\", "/")

    for pattern in CRITICAL_PATH_PATTERNS:
        if re.search(pattern, path_lower):
            return {
                "level": "CRITICAL",
                "score": 35,
                "reason": "Modifies sensitive security/auth/payment/secret paths"
            }

    for pattern in HIGH_PATH_PATTERNS:
        if re.search(pattern, path_lower):
            return {
                "level": "HIGH",
                "score": 20,
                "reason": "Modifies core infra, routing, migration, or middleware logic"
            }

    for pattern in LOW_PATH_PATTERNS:
        if re.search(pattern, path_lower):
            return {
                "level": "LOW",
                "score": -10,
                "reason": "Test, documentation, or static asset file"
            }

    return {
        "level": "NORMAL",
        "score": 5,
        "reason": "Standard application code"
    }

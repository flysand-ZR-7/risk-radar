from typing import Dict, Any, List

def evaluate_complexity_and_volume(
    added_lines_count: int,
    deleted_lines_count: int,
    is_test_file: bool,
    max_indentation_observed: int = 0
) -> Dict[str, Any]:
    """
    Evaluates risk based on churn volume, code density, and test imbalance.
    """
    score = 0
    reasons = []

    total_changes = added_lines_count + deleted_lines_count

    # Size-based scoring
    if added_lines_count > 600:
        score += 35
        reasons.append(f"Massive addition (+{added_lines_count} lines) in a single file — high rubber-stamp probability")
    elif added_lines_count > 250:
        score += 20
        reasons.append(f"Large addition (+{added_lines_count} lines)")
    elif added_lines_count > 100:
        score += 10
        reasons.append(f"Moderate addition (+{added_lines_count} lines)")

    # Deep nesting check
    if max_indentation_observed >= 5:
        score += 15
        reasons.append(f"High cyclomatic complexity / deep nesting detected ({max_indentation_observed} indent levels)")

    # Test file adjustment
    if is_test_file:
        # If it's a test file, additions are generally good and low risk
        score = max(0, score - 15)

    return {
        "score": score,
        "reasons": reasons,
        "total_changes": total_changes
    }

def calculate_pr_test_ratio(files_summary: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculates the ratio of test additions to production code additions across the entire PR.
    """
    prod_additions = 0
    test_additions = 0

    for f in files_summary:
        if f.get("is_test"):
            test_additions += f.get("added_lines", 0)
        else:
            prod_additions += f.get("added_lines", 0)

    ratio = (test_additions / prod_additions) if prod_additions > 0 else 1.0

    risk_flag = None
    if prod_additions > 150 and test_additions == 0:
        risk_flag = "⚠️ Zero test coverage added for over 150+ lines of production changes."
    elif prod_additions > 300 and ratio < 0.15:
        risk_flag = f"⚠️ Low test ratio: Only {test_additions} test lines added for {prod_additions} prod lines ({ratio*100:.1f}%)."

    return {
        "prod_additions": prod_additions,
        "test_additions": test_additions,
        "ratio": round(ratio, 2),
        "warning": risk_flag
    }

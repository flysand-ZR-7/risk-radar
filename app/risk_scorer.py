from typing import List, Dict, Any
from app.diff_parser import parse_unified_diff, ParsedFileDiff
from app.rules.path_rules import evaluate_path_risk
from app.rules.secret_rules import scan_line_for_secrets
from app.rules.security_rules import scan_hunk_for_security_issues
from app.rules.complexity_rules import evaluate_complexity_and_volume, calculate_pr_test_ratio

class RiskReport:
    def __init__(self, overall_score: int, overall_level: str, files: List[Dict[str, Any]], secrets: List[Dict[str, Any]], security_issues: List[Dict[str, Any]], test_stats: Dict[str, Any]):
        self.overall_score = overall_score
        self.overall_level = overall_level
        self.files = files
        self.secrets = secrets
        self.security_issues = security_issues
        self.test_stats = test_stats

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "overall_level": self.overall_level,
            "files": self.files,
            "secrets_found": len(self.secrets),
            "secrets": self.secrets,
            "security_issues_found": len(self.security_issues),
            "security_issues": self.security_issues,
            "test_stats": self.test_stats
        }

    def to_markdown(self) -> str:
        """Generates a clean, developer-friendly GitHub review comment."""
        icon = "🔴" if self.overall_level in ["CRITICAL", "HIGH"] else ("🟡" if self.overall_level == "MEDIUM" else "🟢")
        
        md = []
        md.append(f"## {icon} RiskRadar Review Guide — PR Risk Score: **{self.overall_score}/100 ({self.overall_level})**\n")
        md.append("> *Automated risk triage to stop rubber-stamping large AI-generated diffs.*\n")

        # Critical Alerts: Secrets & Vulnerabilities
        if self.secrets:
            md.append("### 🚨 Secrets & Credentials Detected!")
            md.append("| File | Line | Secret Type | Masked Preview |")
            md.append("|------|------|-------------|----------------|")
            for s in self.secrets:
                md.append(f"| `{s['file']}` | L{s['line_no']} | **{s['rule']}** | `{s['masked_secret']}` |")
            md.append("\n> **Action:** Revoke or rotate these credentials immediately before merging.\n")

        if self.security_issues:
            md.append("### ⚠️ Security Vulnerability Signals")
            md.append("| File | Severity | Issue | Description |")
            md.append("|------|----------|-------|-------------|")
            for sec in self.security_issues:
                md.append(f"| `{sec['file']}` | **{sec['severity']}** | {sec['rule']} | {sec['description']} |")
            md.append("")

        # Test ratio alert
        if self.test_stats.get("warning"):
            md.append(f"> {self.test_stats['warning']}\n")

        # Prioritized File Checklist
        md.append("### 📋 Recommended Review Order")
        md.append("Spend review time on the highest-risk files first:\n")
        md.append("| Status | Score | File | Lines | Key Risk Factors |")
        md.append("|:------:|:-----:|------|:-----:|------------------|")

        for f in self.files:
            badge = "🔴" if f["score"] >= 65 else ("🟠" if f["score"] >= 45 else ("🟡" if f["score"] >= 25 else "🟢"))
            churn = f"+{f['added_lines']} / -{f['deleted_lines']}"
            reasons = ", ".join(f["reasons"][:2]) if f["reasons"] else "Standard change"
            md.append(f"| {badge} | **{f['score']}** | `{f['path']}` | {churn} | {reasons} |")

        md.append("\n---\n*Powered by RiskRadar AI PR Reviewer*")
        return "\n".join(md)

def analyze_diff(diff_text: str) -> RiskReport:
    """Analyzes a full pull request diff and calculates prioritized risk."""
    parsed_files = parse_unified_diff(diff_text)

    all_secrets: List[Dict[str, Any]] = []
    all_security_issues: List[Dict[str, Any]] = []
    file_summaries: List[Dict[str, Any]] = []

    for pf in parsed_files:
        path_eval = evaluate_path_risk(pf.path)
        is_test = path_eval["level"] == "LOW" and ("test" in pf.path.lower() or "spec" in pf.path.lower())

        file_score = 0
        file_reasons = []

        # Path risk
        if path_eval["score"] > 0:
            file_score += path_eval["score"]
            file_reasons.append(path_eval["reason"])

        # Scan hunks and lines
        file_max_indent = 0
        for hunk in pf.hunks:
            # Check indentation depth
            for lno, lcontent in hunk.added_lines:
                if lcontent.strip():
                    indent_level = (len(lcontent) - len(lcontent.lstrip())) // 4
                    if indent_level > file_max_indent:
                        file_max_indent = indent_level

                # Secret scan
                secrets_found = scan_line_for_secrets(lcontent, line_no=lno)
                for s in secrets_found:
                    s["file"] = pf.path
                    all_secrets.append(s)
                    file_score += 40
                    file_reasons.append(f"Hardcoded {s['rule']}")

            # Security scan
            hunk_raw = hunk.raw_added_text
            sec_issues = scan_hunk_for_security_issues(hunk_raw, hunk.added_lines)
            for sec in sec_issues:
                sec["file"] = pf.path
                all_security_issues.append(sec)
                file_score += 30 if sec["severity"] == "CRITICAL" else 20
                file_reasons.append(sec["rule"])

        # Complexity evaluation
        complexity = evaluate_complexity_and_volume(
            added_lines_count=pf.added_count,
            deleted_lines_count=pf.deleted_count,
            is_test_file=is_test,
            max_indentation_observed=file_max_indent
        )
        file_score += complexity["score"]
        file_reasons.extend(complexity["reasons"])

        # Cap score 0 - 100
        final_file_score = min(100, max(0, file_score))

        file_summaries.append({
            "path": pf.path,
            "score": final_file_score,
            "added_lines": pf.added_count,
            "deleted_lines": pf.deleted_count,
            "is_test": is_test,
            "reasons": list(dict.fromkeys(file_reasons)) # remove duplicates
        })

    # Sort files highest risk first
    file_summaries.sort(key=lambda x: x["score"], reverse=True)

    # Calculate overall PR score
    if file_summaries:
        top_scores = [f["score"] for f in file_summaries[:3]]
        overall_score = min(100, int(sum(top_scores) / len(top_scores) + (10 if len(all_secrets) > 0 else 0)))
    else:
        overall_score = 0

    if overall_score >= 70 or len(all_secrets) > 0:
        overall_level = "CRITICAL"
    elif overall_score >= 50:
        overall_level = "HIGH"
    elif overall_score >= 25:
        overall_level = "MEDIUM"
    else:
        overall_level = "LOW"

    test_stats = calculate_pr_test_ratio(file_summaries)

    return RiskReport(
        overall_score=overall_score,
        overall_level=overall_level,
        files=file_summaries,
        secrets=all_secrets,
        security_issues=all_security_issues,
        test_stats=test_stats
    )

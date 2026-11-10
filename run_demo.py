import sys
from pathlib import Path

# Fix Windows console encoding for emoji output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from app.risk_scorer import analyze_diff

def main():
    sample_diff_path = Path(__file__).parent / "tests" / "sample_diff.diff"
    diff_text = sample_diff_path.read_text(encoding="utf-8")

    print("=================================================================")
    print("           RISKRADAR AI PR TRIAGE ENGINE — DEMO RUN              ")
    print("=================================================================\n")

    report = analyze_diff(diff_text)

    # Print GitHub Markdown Checklist Output
    print(report.to_markdown())

if __name__ == "__main__":
    main()

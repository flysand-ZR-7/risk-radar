import unittest
from app.risk_scorer import analyze_diff
from app.rules.secret_rules import scan_line_for_secrets
from app.rules.path_rules import evaluate_path_risk

class TestRiskRadar(unittest.TestCase):
    def test_secret_detection_openai_and_stripe(self):
        stripe_line = 'STRIPE_KEY = "' + 'sk_live_' + '123456789012345678901234"'
        openai_line = 'OPENAI = "' + 'sk-proj-' + 'abcdefghijklmnopqrstuvwxyz1234567890123456"'

        stripe_results = scan_line_for_secrets(stripe_line)
        openai_results = scan_line_for_secrets(openai_line)

        self.assertTrue(any(r["rule"] == "Stripe Live Secret Key" for r in stripe_results))
        self.assertTrue(any(r["rule"] == "OpenAI / LLM API Key" for r in openai_results))

    def test_path_evaluation_critical_and_low(self):
        auth_eval = evaluate_path_risk("src/api/auth/jwt_handler.py")
        test_eval = evaluate_path_risk("tests/unit/test_auth.py")
        doc_eval = evaluate_path_risk("docs/README.md")

        self.assertEqual(auth_eval["level"], "CRITICAL")
        self.assertEqual(test_eval["level"], "LOW")
        self.assertEqual(doc_eval["level"], "LOW")

    def test_full_diff_analysis_finds_risks(self):
        sample_diff = """diff --git a/app/cors.py b/app/cors.py
new file mode 100644
--- /dev/null
+++ b/app/cors.py
@@ -0,0 +1,4 @@
+app.add_middleware(
+    CORSMiddleware,
+    allow_origins=["*"],
+    allow_credentials=True
+)
"""
        report = analyze_diff(sample_diff)
        self.assertGreater(len(report.security_issues), 0)
        self.assertGreater(report.files[0]["score"], 50)

if __name__ == "__main__":
    unittest.main()


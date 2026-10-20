"""
VulnGuard SAST v2.0 - Python CLI AST & SARIF Unit Tests
"""

import unittest
from cli.vulnguard import scan_code_string, generate_sarif


class TestVulnGuardPythonAST(unittest.TestCase):
    def test_ast_detects_multiline_taint_sqli(self) -> None:
        code = (
            'user = request.args.get("u")\n'
            'query = "SELECT * FROM users WHERE name = \'" + user + "\'"\n'
            "cursor.execute(query)\n"
        )
        findings = scan_code_string(code, "app.py")
        sqli = [f for f in findings if f["category"] == "SQLi"]
        self.assertGreaterEqual(len(sqli), 1)

    def test_ast_detects_rce_and_secrets(self) -> None:
        code = (
            'JWT_SECRET = "hardcoded_production_secret_9988"\n'
            'os.system("ping -c 1 " + host)\n'
            'subprocess.run(cmd, shell=True)\n'
        )
        findings = scan_code_string(code, "admin.py")
        categories = {f["category"] for f in findings}
        self.assertIn("SECRETS", categories)
        self.assertIn("RCE", categories)

    def test_zero_false_positives_on_parameterized_sql(self) -> None:
        code = (
            'import os\n'
            'JWT_SECRET = os.environ.get("JWT_SECRET")\n'
            'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
            'subprocess.run(["ping", "-c", "1", host], shell=False)\n'
        )
        findings = scan_code_string(code, "secure.py")
        self.assertEqual(len(findings), 0)

    def test_sarif_generation(self) -> None:
        code = 'os.system(f"ls {folder}")\n'
        findings = scan_code_string(code, "vuln.py")
        sarif = generate_sarif(findings)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)


if __name__ == "__main__":
    unittest.main()

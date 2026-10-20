/**
 * VulnGuard SAST v2.0 - Automated Unit Test Suite (Node.js Test Runner)
 * Verifies:
 * 1. Multi-line Source-to-Sink Taint Analysis (SQLi, RCE, LFI)
 * 2. Sanitizer Recognition (Zero False Positives on Hardened Code)
 * 3. Pattern Detection across Python, JavaScript/Node.js, and PHP
 * 4. OASIS SARIF v2.1.0 Schema Compliance
 */

import test from "node:test";
import assert from "node:assert/strict";
import { analyzeSourceCode, generateSarifReport } from "../js/engine.js";
import { CODE_SAMPLES } from "../js/samples.js";

test("1. Detects multi-line SQL Injection via Source-to-Sink Taint Tracking", () => {
  const snippet = `
    username = request.args.get("user")
    sql = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(sql)
  `;
  const report = analyzeSourceCode(snippet, "python", "taint_sqli.py");
  const sqli = report.findings.filter((f) => f.category === "SQLi");
  assert.ok(sqli.length >= 1, "Expected at least one SQLi finding from taint tracking");
  const taintFinding = report.findings.find((f) => f.taintTrace && f.taintTrace.length >= 2);
  assert.ok(taintFinding, "Expected a multi-hop Source-to-Sink taint trace");
});

test("2. Detects Remote Code Execution (RCE) and Insecure Deserialization", () => {
  const snippet = `
    import os, pickle
    host = request.args.get("host")
    os.system(f"ping -c 1 {host}")
    obj = pickle.loads(raw_bytes)
  `;
  const report = analyzeSourceCode(snippet, "python", "rce_test.py");
  const rce = report.findings.filter((f) => f.category === "RCE");
  assert.equal(rce.length, 2, "Expected both os.system and pickle.loads RCE detections");
});

test("3. Detects PHP Local File Inclusion (LFI) and Reflected XSS", () => {
  const report = analyzeSourceCode(
    CODE_SAMPLES.php_portal.code,
    "php",
    "portal_vulnerable.php"
  );
  assert.ok(report.categories.LFI >= 2, "Expected LFI & Path Traversal findings in PHP sample");
  assert.ok(report.categories.SQLi >= 1, "Expected SQLi finding in PHP sample");
  assert.ok(report.categories.RCE >= 1, "Expected RCE finding in PHP sample");
  assert.ok(report.categories.XSS >= 1, "Expected XSS finding in PHP sample");
});

test("4. Produces Zero False Positives (100/100 A+ Score) on Hardened Python Reference Code", () => {
  const report = analyzeSourceCode(
    CODE_SAMPLES.python_secure.code,
    "python",
    "app_hardened.py"
  );
  assert.equal(report.findings.length, 0, "Expected 0 findings on hardened code");
  assert.equal(report.score, 100, "Expected 100/100 security score");
  assert.equal(report.grade, "A+", "Expected A+ security grade");
});

test("5. Generates valid OASIS SARIF v2.1.0 report structure", () => {
  const report = analyzeSourceCode(
    CODE_SAMPLES.nodejs_express.code,
    "javascript",
    "server_vulnerable.js"
  );
  const sarif = generateSarifReport(report);
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].tool.driver.name, "VulnGuard SAST");
  assert.equal(sarif.runs[0].results.length, report.findings.length);
});

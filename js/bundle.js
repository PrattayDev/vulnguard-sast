(function () {
"use strict";
/**
 * VulnGuard SAST - Static Application Security Testing Rule Definitions
 * Detects insecure coding patterns across Python, JavaScript/TypeScript, and PHP
 * Maps findings to OWASP Top 10 (2021) and CWE identifiers with secure remediations.
 */

const SAST_RULES = [
  // ==========================================
  // 1. SQL INJECTION (SQLi) - CWE-89
  // ==========================================
  {
    id: "VG-SQLI-001",
    title: "SQL Injection via String Formatting / Concatenation (Python)",
    category: "SQLi",
    severity: "CRITICAL",
    cvss: 9.8,
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    languages: ["python"],
    pattern: /(?:cursor\.execute|db\.execute|session\.execute|engine\.execute)\s*\(\s*(?:f["']|["'].*?["']\s*%|["'].*?["']\s*\+|\s*["'].*?\{.*?\}.*?["']\.format)/i,
    description:
      "User-controlled variables are concatenated or formatted directly into a SQL query string passed to execute(). An attacker can manipulate the query structure to bypass authentication or read/modify unauthorized database records.",
    remediation:
      "Use parameterized queries (prepared statements) by passing query parameters as a separate tuple or dictionary argument to cursor.execute(). Never use f-strings, % formatting, or + concatenation to build SQL queries.",
    vulnerableExample: `cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")`,
    secureExample: `cursor.execute("SELECT * FROM users WHERE username = %s", (username,))`,
  },
  {
    id: "VG-SQLI-002",
    title: "Raw SQL Query String Assignment with Interpolation",
    category: "SQLi",
    severity: "HIGH",
    cvss: 8.8,
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    languages: ["python", "javascript", "php"],
    pattern: /(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[\w*,\s]+\s+(?:FROM|SET|WHERE|VALUES)\s+.*?(?:\+\s*\w+|\$\{.*?\}|\.\s*\$\w+|['"]\s*%\s*\w+)/i,
    description:
      "A raw SQL statement is dynamically constructed using string concatenation or template interpolation before execution. Dynamic SQL construction mixes code and data, enabling SQL Injection.",
    remediation:
      "Replace dynamic string interpolation with positional (?, $1, %s) or named (:param) bind parameters supported by your database driver or ORM.",
    vulnerableExample: `const query = \`SELECT * FROM accounts WHERE id = \${req.query.id}\`;\nawait db.query(query);`,
    secureExample: `const query = "SELECT * FROM accounts WHERE id = $1";\nawait db.query(query, [req.query.id]);`,
  },
  {
    id: "VG-SQLI-003",
    title: "SQL Injection in Node.js Database Query",
    category: "SQLi",
    severity: "CRITICAL",
    cvss: 9.8,
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    languages: ["javascript"],
    pattern: /(?:pool|db|connection|client|sequelize|knex)\.(?:query|raw)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|['"][^'"]*['"]\s*\+)/i,
    description:
      "Template literals (${...}) or string concatenation (+) are used directly inside a Node.js database query call. Untrusted input can alter SQL logic.",
    remediation:
      "Pass parameterized placeholders (? for MySQL/SQLite, $1 for PostgreSQL, or replacements in Sequelize) as the second argument to .query().",
    vulnerableExample: `db.query(\`SELECT * FROM orders WHERE user_id = \${req.params.userId}\`);`,
    secureExample: `db.query("SELECT * FROM orders WHERE user_id = ?", [req.params.userId]);`,
  },
  {
    id: "VG-SQLI-004",
    title: "SQL Injection in PHP Database Execution",
    category: "SQLi",
    severity: "CRITICAL",
    cvss: 9.8,
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    languages: ["php"],
    pattern: /(?:mysqli_query|mysql_query|\$\w+->query|\$\w+->exec)\s*\([^;]*(?:\$_(?:GET|POST|REQUEST|COOKIE)|concat|\.\s*\$\w+|"[^"]*\$\w+[^"]*")/i,
    description:
      "PHP variables or superglobals ($_GET, $_POST, $_REQUEST) are interpolated directly into a SQL query call without prepared statements.",
    remediation:
      "Use PDO or MySQLi prepared statements with prepare(), bindParam()/bind_param(), and execute().",
    vulnerableExample: `$stmt = $pdo->query("SELECT * FROM users WHERE email = '" . $_POST['email'] . "'");`,
    secureExample: `$stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");\n$stmt->execute(['email' => $_POST['email']]);`,
  },

  // ==========================================
  // 2. REMOTE CODE EXECUTION (RCE) & COMMAND INJECTION - CWE-78 / CWE-94
  // ==========================================
  {
    id: "VG-RCE-001",
    title: "OS Command Injection via os.system / os.popen (Python)",
    category: "RCE",
    severity: "CRITICAL",
    cvss: 9.8,
    cwe: "CWE-78",
    owasp: "A03:2021 - Injection",
    languages: ["python"],
    pattern: /\bos\.(?:system|popen)\s*\(/i,
    description:
      "os.system() and os.popen() execute commands through the underlying system shell (/bin/sh or cmd.exe). Any user input included in the command string allows shell metacharacter injection (;, |, &&, $()).",
    remediation:
      "Use subprocess.run() with a list of arguments and shell=False (the default). Validate and allowlist any user-supplied parameters.",
    vulnerableExample: `os.system(f"ping -c 1 {target_host}")`,
    secureExample: `subprocess.run(["ping", "-c", "1", target_host], shell=False, check=True)`,
  },
  {
    id: "VG-RCE-002",
    title: "Subprocess Execution with shell=True (Python)",
    category: "RCE",
    severity: "HIGH",
    cvss: 8.8,
    cwe: "CWE-78",
    owasp: "A03:2021 - Injection",
    languages: ["python"],
    pattern: /\bsubprocess\.(?:Popen|call|run|check_output|check_call)\s*\([^)]*shell\s*=\s*True/i,
    description:
      "Invoking subprocess functions with shell=True spawns a system shell to interpret the command string, exposing the application to OS command injection if external input reaches the command.",
    remediation:
      "Pass the command and its arguments as a Python list (e.g., ['ls', '-la', directory]) and set shell=False.",
    vulnerableExample: `subprocess.check_output(f"nslookup {domain}", shell=True)`,
    secureExample: `subprocess.check_output(["nslookup", domain], shell=False)`,
  },
  {
    id: "VG-RCE-003",
    title: "Dynamic Code Evaluation via eval() or exec()",
    category: "RCE",
    severity: "CRITICAL",
    cvss: 9.8,
    cwe: "CWE-94",
    owasp: "A03:2021 - Injection",
    languages: ["python", "javascript", "php"],
    pattern: /\b(?:eval|exec)\s*\(\s*(?!['"][^'"]*['"]\s*\))[^)]+\)/i,
    description:
      "Dynamic execution of strings as code via eval() or exec() allows arbitrary Remote Code Execution (RCE) if an attacker controls any portion of the evaluated input.",
    remediation:
      "Eliminate eval()/exec() completely. For parsing data, use JSON.parse() (JS), json.loads() or ast.literal_eval() (Python), or safe lookup tables for mathematical/dispatch logic.",
    vulnerableExample: `const result = eval(req.body.expression);`,
    secureExample: `const result = JSON.parse(req.body.jsonPayload);`,
  },
  {
    id: "VG-RCE-004",
    title: "Node.js child_process.exec() Shell Command Execution",
    category: "RCE",
    severity: "CRITICAL",
    cvss: 9.8,
    cwe: "CWE-78",
    owasp: "A03:2021 - Injection",
    languages: ["javascript"],
    pattern: /\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|['"][^'"]*['"]\s*\+)/i,
    description:
      "child_process.exec() and execSync() invoke a shell to execute the command string. Interpolating variables into the command string enables arbitrary command execution.",
    remediation:
      "Use child_process.execFile() or spawn() with an array of arguments instead of exec(), which avoids spawning a shell.",
    vulnerableExample: `exec(\`convert \${req.query.image} output.png\`, callback);`,
    secureExample: `execFile("convert", [req.query.image, "output.png"], callback);`,
  },
  {
    id: "VG-RCE-005",
    title: "Insecure Deserialization (pickle / yaml.load / unserialize)",
    category: "RCE",
    severity: "CRITICAL",
    cvss: 9.8,
    cwe: "CWE-502",
    owasp: "A08:2021 - Software and Data Integrity Failures",
    languages: ["python", "php"],
    pattern: /\b(?:pickle\.loads?|cPickle\.loads?|yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)|unserialize\s*\()/i,
    description:
      "Deserializing untrusted data with Python's pickle, PyYAML's default yaml.load(), or PHP's unserialize() allows attackers to instantiate arbitrary objects and execute arbitrary code immediately upon deserialization.",
    remediation:
      "Use safe serialization formats like JSON (json.loads / json_decode). For YAML in Python, always use yaml.safe_load().",
    vulnerableExample: `session_data = pickle.loads(base64.b64decode(cookie_val))`,
    secureExample: `session_data = json.loads(base64.b64decode(cookie_val).decode("utf-8"))`,
  },
  {
    id: "VG-RCE-006",
    title: "PHP System Command Execution (system / shell_exec / passthru)",
    category: "RCE",
    severity: "CRITICAL",
    cvss: 9.8,
    cwe: "CWE-78",
    owasp: "A03:2021 - Injection",
    languages: ["php"],
    pattern: /\b(?:system|shell_exec|passthru|proc_open|popen)\s*\(\s*[^)]*\$/i,
    description:
      "Passing PHP variables into system(), shell_exec(), or passthru() allows attackers to chain arbitrary OS commands if input is not strictly allowlisted.",
    remediation:
      "Avoid calling OS commands from web requests. If unavoidable, validate input against a strict allowlist and wrap arguments with escapeshellarg().",
    vulnerableExample: `$output = shell_exec("whois " . $_GET['domain']);`,
    secureExample: `$domain = escapeshellarg($_GET['domain']);\n$output = shell_exec("whois " . $domain);`,
  },

  // ==========================================
  // 3. LOCAL FILE INCLUSION (LFI) & PATH TRAVERSAL - CWE-22 / CWE-98
  // ==========================================
  {
    id: "VG-LFI-001",
    title: "Local File Inclusion (LFI) via Dynamic PHP Include/Require",
    category: "LFI",
    severity: "CRITICAL",
    cvss: 9.1,
    cwe: "CWE-98",
    owasp: "A03:2021 - Injection",
    languages: ["php"],
    pattern: /\b(?:include|include_once|require|require_once)\s*\(?\s*[^;]*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$\w+)/i,
    description:
      "Dynamically including or requiring files using user-controlled variables enables Local File Inclusion (LFI) and Remote File Inclusion (RFI). Attackers can use ../ traversal or PHP wrappers (php://filter) to read sensitive files or execute code.",
    remediation:
      "Map user input against a strict static allowlist of permitted template files instead of passing variables directly to include/require.",
    vulnerableExample: `include($_GET['page'] . ".php");`,
    secureExample: `$allowed = ['home' => 'home.php', 'about' => 'about.php'];\n$page = $allowed[$_GET['page']] ?? 'home.php';\ninclude(__DIR__ . '/views/' . $page);`,
  },
  {
    id: "VG-LFI-002",
    title: "Path Traversal / Arbitrary File Read in Python File Operations",
    category: "LFI",
    severity: "HIGH",
    cvss: 8.6,
    cwe: "CWE-22",
    owasp: "A01:2021 - Broken Access Control",
    languages: ["python"],
    pattern: /\b(?:open|send_file|os\.remove|shutil\.copy)\s*\(\s*(?:f["'][^"']*\{[^}]+\}|["'][^"']*["']\s*\+|os\.path\.join\s*\([^)]*request\.)/i,
    description:
      "Constructing file paths directly from user input using string formatting or os.path.join() without canonical path verification allows attackers to use '../' sequences or absolute paths (e.g., /etc/passwd) to read or overwrite arbitrary files.",
    remediation:
      "Use werkzeug.utils.secure_filename() or pathlib.Path.resolve() and verify that the resolved canonical path starts with the intended base directory.",
    vulnerableExample: `with open(f"/var/www/uploads/{request.args.get('file')}", "r") as f:`,
    secureExample: `base_dir = Path("/var/www/uploads").resolve()\ntarget = (base_dir / secure_filename(request.args.get("file", ""))).resolve()\nif not str(target).startswith(str(base_dir)):\n    abort(403)\nwith open(target, "r") as f:`,
  },
  {
    id: "VG-LFI-003",
    title: "Path Traversal in Node.js File System Access",
    category: "LFI",
    severity: "HIGH",
    cvss: 8.6,
    cwe: "CWE-22",
    owasp: "A01:2021 - Broken Access Control",
    languages: ["javascript"],
    pattern: /\b(?:fs\.(?:readFile|readFileSync|createReadStream|unlink|writeFile)|res\.(?:sendFile|download))\s*\(\s*(?:`[^`]*\$\{[^}]+\}|[^,)]*req\.(?:query|params|body)|path\.(?:join|resolve)\s*\([^)]*req\.)/i,
    description:
      "Passing request parameters (req.query, req.params, req.body) directly into fs.readFile() or res.sendFile() allows directory traversal via '../' sequences to read sensitive configuration or source files.",
    remediation:
      "Normalize the path using path.basename() or verify that path.resolve(baseDir, userInput) starts with baseDir + path.sep before reading the file.",
    vulnerableExample: `const data = fs.readFileSync(path.join(__dirname, "public", req.query.file));`,
    secureExample: `const safeName = path.basename(req.query.file);\nconst safePath = path.join(__dirname, "public", safeName);\nconst data = fs.readFileSync(safePath);`,
  },
  {
    id: "VG-LFI-004",
    title: "Arbitrary File Read in PHP file_get_contents / readfile",
    category: "LFI",
    severity: "HIGH",
    cvss: 8.6,
    cwe: "CWE-22",
    owasp: "A01:2021 - Broken Access Control",
    languages: ["php"],
    pattern: /\b(?:file_get_contents|readfile|fopen)\s*\(\s*[^)]*(?:\$_(?:GET|POST|REQUEST)|\.\s*\$\w+)/i,
    description:
      "Reading files using unvalidated user input in file_get_contents() or readfile() exposes the server to Local File Disclosure (LFD) and SSRF.",
    remediation:
      "Strip path components using basename() and validate with realpath() to ensure the target resides within the allowed base directory.",
    vulnerableExample: `echo file_get_contents("/var/data/" . $_GET['report']);`,
    secureExample: `$base = realpath("/var/data");\n$target = realpath($base . "/" . basename($_GET['report']));\nif ($target && strpos($target, $base) === 0) {\n    echo file_get_contents($target);\n}`,
  },

  // ==========================================
  // 4. CROSS-SITE SCRIPTING (XSS) - CWE-79
  // ==========================================
  {
    id: "VG-XSS-001",
    title: "DOM-Based Cross-Site Scripting via innerHTML / document.write",
    category: "XSS",
    severity: "HIGH",
    cvss: 7.5,
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    languages: ["javascript"],
    pattern: /(?:\.(?:innerHTML|outerHTML)\s*=\s*(?![\s]*['"][^'"]*['"]\s*;)[^;]+|\bdocument\.write\s*\([^)]+\)|\bdangerouslySetInnerHTML\s*=)/i,
    description:
      "Assigning dynamic content to innerHTML, outerHTML, or document.write() parses and executes embedded <script> tags and HTML event handlers (e.g., onerror), leading to Cross-Site Scripting (XSS).",
    remediation:
      "Use .textContent or .innerText for plain text rendering, or sanitize HTML with DOMPurify.sanitize() before rendering.",
    vulnerableExample: `document.getElementById("greeting").innerHTML = "Hello, " + userInput;`,
    secureExample: `document.getElementById("greeting").textContent = "Hello, " + userInput;`,
  },
  {
    id: "VG-XSS-002",
    title: "Reflected XSS / Server-Side Template Injection in Flask",
    category: "XSS",
    severity: "HIGH",
    cvss: 8.1,
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    languages: ["python"],
    pattern: /\brender_template_string\s*\(\s*(?:f["']|["'].*?["']\s*\+|["'].*?["']\s*%|.*?\.format)/i,
    description:
      "Formatting user input directly into render_template_string() before Jinja2 compilation causes both Cross-Site Scripting (XSS) and Server-Side Template Injection (SSTI -> RCE).",
    remediation:
      "Pass variables as keyword arguments to render_template() or render_template_string() so Jinja2 auto-escapes them safely.",
    vulnerableExample: `return render_template_string(f"<h1>Search results for {query}</h1>")`,
    secureExample: `return render_template_string("<h1>Search results for {{ query }}</h1>", query=query)`,
  },
  {
    id: "VG-XSS-003",
    title: "Reflected XSS via Unescaped PHP Superglobal Output",
    category: "XSS",
    severity: "HIGH",
    cvss: 7.5,
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    languages: ["php"],
    pattern: /\b(?:echo|print)\s+[^;]*\$_(?:GET|POST|REQUEST|SERVER)\b(?![^;]*htmlspecialchars)/i,
    description:
      "Directly echoing $_GET, $_POST, or $_REQUEST parameters into an HTML response without output encoding allows attackers to inject arbitrary JavaScript into victims' browsers.",
    remediation:
      "Wrap all untrusted output in htmlspecialchars($input, ENT_QUOTES, 'UTF-8') before rendering in HTML.",
    vulnerableExample: `echo "Welcome, " . $_GET['username'];`,
    secureExample: `echo "Welcome, " . htmlspecialchars($_GET['username'], ENT_QUOTES, 'UTF-8');`,
  },

  // ==========================================
  // 5. HARDCODED SECRETS & CRYPTO - CWE-798 / CWE-327
  // ==========================================
  {
    id: "VG-SEC-001",
    title: "Hardcoded API Key, Secret Token, or Password in Source Code",
    category: "SECRETS",
    severity: "HIGH",
    cvss: 8.2,
    cwe: "CWE-798",
    owasp: "A07:2021 - Identification and Authentication Failures",
    languages: ["python", "javascript", "php"],
    pattern: /(?:(?:api[_-]?key|secret[_-]?key|jwt[_-]?secret|db[_-]?password|password|passwd|private[_-]?key|access[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-!@#$%^&*+=]{8,}['"]|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]{16,})/i,
    description:
      "Hardcoding credentials, API keys, or JWT signing secrets in source code exposes them to anyone with repository access or leaked build artifacts.",
    remediation:
      "Move all sensitive credentials to environment variables (os.environ.get() / process.env / getenv()) or a dedicated secret manager, and rotate any exposed keys immediately.",
    vulnerableExample: `JWT_SECRET = "super_secret_prod_key_99887766"`,
    secureExample: `JWT_SECRET = os.environ.get("JWT_SECRET")`,
  },
  {
    id: "VG-SEC-002",
    title: "Weak Cryptographic Hash Algorithm (MD5 / SHA-1) Used for Security",
    category: "SECRETS",
    severity: "MEDIUM",
    cvss: 6.5,
    cwe: "CWE-327",
    owasp: "A02:2021 - Cryptographic Failures",
    languages: ["python", "javascript", "php"],
    pattern: /\b(?:hashlib\.(?:md5|sha1)|crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]\)|\b(?:md5|sha1)\s*\(\s*\$\w+)/i,
    description:
      "MD5 and SHA-1 are cryptographically broken and vulnerable to collision and fast GPU brute-force attacks. They must never be used for password hashing or security tokens.",
    remediation:
      "Use Argon2id, bcrypt, or PBKDF2 for password hashing, and SHA-256 / SHA-512 (with HMAC) for data integrity.",
    vulnerableExample: `password_hash = hashlib.md5(password.encode()).hexdigest()`,
    secureExample: `password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())`,
  },
  {
    id: "VG-SEC-003",
    title: "Disabled TLS/SSL Certificate Verification",
    category: "SECRETS",
    severity: "MEDIUM",
    cvss: 6.8,
    cwe: "CWE-295",
    owasp: "A02:2021 - Cryptographic Failures",
    languages: ["python", "javascript", "php"],
    pattern: /(?:\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0))/i,
    description:
      "Disabling TLS certificate validation allows Man-in-the-Middle (MitM) attackers to intercept or tamper with encrypted HTTPS traffic using self-signed certificates.",
    remediation:
      "Keep TLS verification enabled (verify=True / rejectUnauthorized: true) and configure a custom CA bundle if connecting to internal services.",
    vulnerableExample: `response = requests.get("https://api.internal.corp/data", verify=False)`,
    secureExample: `response = requests.get("https://api.internal.corp/data", verify=True)`,
  }
];

/**
 * VulnGuard SAST - Built-in Educational Code Samples
 * Demonstrates how SAST detects SQLi, RCE, LFI, XSS, and Hardcoded Secrets
 * across Python, JavaScript (Node.js), and PHP, plus a hardened A+ reference sample.
 */

const CODE_SAMPLES = {
  python_flask: {
    name: "Python (Flask API - Vulnerable)",
    language: "python",
    filename: "app_vulnerable.py",
    code: `import os
import pickle
import hashlib
import subprocess
import sqlite3
from flask import Flask, request, render_template_string, send_file

app = Flask(__name__)

# Hardcoded production credentials
JWT_SECRET = "prod_jwt_signing_key_987654321"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

@app.route("/api/user")
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Vulnerable to SQL Injection (CWE-89)
    cursor.execute(f"SELECT id, username, role FROM users WHERE username = '{username}'")
    # Multi-line Taint Flow: Source -> Propagation -> Sink
    sql_query = "SELECT * FROM audit_logs WHERE actor = '" + username + "'"
    cursor.execute(sql_query)
    return {"user": cursor.fetchone()}

@app.route("/api/diagnostics")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    # Vulnerable to OS Command Injection / RCE (CWE-78)
    os.system(f"ping -c 2 {host}")
    output = subprocess.check_output(f"traceroute {host}", shell=True)
    return {"trace": output.decode()}

@app.route("/api/download")
def download_report():
    # Vulnerable to Local File Inclusion / Path Traversal (CWE-22)
    filename = request.args.get("file", "summary.pdf")
    return send_file(f"/var/www/reports/{filename}")

@app.route("/api/session")
def load_session():
    raw_token = request.cookies.get("session_blob")
    # Vulnerable to Insecure Deserialization RCE (CWE-502)
    user_obj = pickle.loads(bytes.fromhex(raw_token))
    return {"loaded": str(user_obj)}

@app.route("/search")
def search_page():
    q = request.args.get("q", "")
    # Vulnerable to Reflected XSS & SSTI (CWE-79)
    return render_template_string(f"<h2>Results for: {q}</h2>")

def hash_user_password(password: str) -> str:
    # Weak cryptographic hash for password storage (CWE-327)
    return hashlib.md5(password.encode()).hexdigest()
`
  },

  nodejs_express: {
    name: "Node.js (Express Backend - Vulnerable)",
    language: "javascript",
    filename: "server_vulnerable.js",
    code: `const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const db = require("./db");

const app = express();
app.use(express.json());

// Hardcoded API key (CWE-798)
const api_key = "prod_api_secret_token_9988776655";

app.get("/api/orders", async (req, res) => {
  const accountId = req.query.accountId;
  // Vulnerable to SQL Injection via template literal (CWE-89)
  const rows = await db.query(\`SELECT * FROM orders WHERE account_id = \${accountId}\`);
  res.json(rows);
});

app.post("/api/convert", (req, res) => {
  const inputFile = req.body.filename;
  // Vulnerable to OS Command Injection / RCE (CWE-78)
  exec(\`ffmpeg -i \${inputFile} output.mp4\`, (err, stdout) => {
    res.send(stdout);
  });
});

app.post("/api/calc", (req, res) => {
  // Vulnerable to Arbitrary Code Evaluation RCE (CWE-94)
  const answer = eval(req.body.formula);
  res.json({ answer });
});

app.get("/api/logs", (req, res) => {
  // Vulnerable to Path Traversal / LFI (CWE-22)
  const logFile = fs.readFileSync(path.join(__dirname, "logs", req.query.name), "utf8");
  res.type("text/plain").send(logFile);
});

// Client-side helper snippet
function renderUserBanner(username) {
  // Vulnerable to DOM-based XSS (CWE-79)
  document.getElementById("user-banner").innerHTML = "Welcome back, " + username;
}

function legacyHash(secret) {
  // Weak hash algorithm (CWE-327)
  return crypto.createHash("sha1").update(secret).digest("hex");
}
`
  },

  php_portal: {
    name: "PHP (Legacy Web Portal - Vulnerable)",
    language: "php",
    filename: "portal_vulnerable.php",
    code: `<?php
// Hardcoded Database Password (CWE-798)
$db_password = "ProdDbAdminPassword2026!";
$conn = mysqli_connect("localhost", "admin", $db_password, "corp_portal");

// 1. Local File Inclusion (LFI - CWE-98)
$module = $_GET['module'];
include("modules/" . $module . ".php");

// 2. SQL Injection in Authentication Query (SQLi - CWE-89)
$user = $_POST['username'];
$result = mysqli_query($conn, "SELECT * FROM members WHERE username = '" . $user . "'");

// 3. Remote Command Execution via shell_exec (RCE - CWE-78)
$target = $_GET['ip'];
$ping_output = shell_exec("ping -c 3 " . $target);

// 4. Arbitrary File Read / Path Traversal (LFI - CWE-22)
$invoice = file_get_contents("/var/invoices/" . $_GET['doc']);

// 5. Reflected Cross-Site Scripting (XSS - CWE-79)
echo "<div class='alert'>Search query: " . $_GET['search'] . "</div>";
?>`
  },

  python_secure: {
    name: "Python (Hardened Flask API - A+ Grade)",
    language: "python",
    filename: "app_hardened.py",
    code: `import os
import json
import subprocess
import sqlite3
from pathlib import Path
from flask import Flask, request, render_template_string, send_file, abort
from werkzeug.utils import secure_filename
import bcrypt

app = Flask(__name__)

# Secrets loaded securely from environment variables
JWT_SECRET = os.environ.get("JWT_SECRET")
BASE_REPORT_DIR = Path("/var/www/reports").resolve()

@app.route("/api/user")
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Parameterized query prevents SQL Injection
    cursor.execute("SELECT id, username, role FROM users WHERE username = ?", (username,))
    return {"user": cursor.fetchone()}

@app.route("/api/diagnostics")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    # Argument list with shell=False prevents Command Injection
    result = subprocess.run(["ping", "-c", "2", host], shell=False, capture_output=True, text=True, check=True)
    return {"output": result.stdout}

@app.route("/api/download")
def download_report():
    # Canonical path validation prevents LFI / Path Traversal
    safe_name = secure_filename(request.args.get("file", "summary.pdf"))
    target_path = (BASE_REPORT_DIR / safe_name).resolve()
    if not str(target_path).startswith(str(BASE_REPORT_DIR)):
        abort(403)
    return send_file(target_path)

@app.route("/search")
def search_page():
    q = request.args.get("q", "")
    # Jinja2 parameter binding auto-escapes HTML to prevent XSS & SSTI
    return render_template_string("<h2>Results for: {{ query }}</h2>", query=q)

def hash_user_password(password: str) -> bytes:
    # Strong adaptive hashing with bcrypt
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
`
  }
};

/**
 * VulnGuard SAST & SCA Engine v2.0
 * 1. Multi-language Static Application Security Testing (SAST) with Source-to-Sink Taint Analysis
 * 2. Live Software Composition Analysis (SCA) against the OSV.dev CVE Database
 * 3. Public GitHub Repository Multi-File Scanner
 * 4. OASIS SARIF v2.1.0 Report Generator
 */



/**
 * Automatically detects the programming language of a source snippet.
 */
function detectLanguage(code) {
  if (/<\?php|\$_(?:GET|POST|REQUEST|SERVER)|mysqli_query|shell_exec/i.test(code)) {
    return "php";
  }
  if (/\b(?:def\s+\w+\s*\(|import\s+(?:os|subprocess|sqlite3|flask|pickle)|from\s+flask\s+import|cursor\.execute)\b/.test(code)) {
    return "python";
  }
  if (/\b(?:const|let|var|function|require\s*\(|module\.exports|document\.getElementById|req\.(?:query|body|params))\b/.test(code)) {
    return "javascript";
  }
  return "all";
}

function isCommentLine(trimmedLine) {
  return (
    trimmedLine.startsWith("#") ||
    trimmedLine.startsWith("//") ||
    trimmedLine.startsWith("/*") ||
    trimmedLine.startsWith("*") ||
    trimmedLine.startsWith("*/")
  );
}

/**
 * Multi-line Source-to-Sink Taint Analysis Engine.
 * Tracks untrusted user input sources -> variable propagations -> dangerous sinks,
 * while respecting sanitization functions.
 */
function runTaintAnalysis(lines, language) {
  // Map of variableName -> { sourceLine, sourceExpr, trace: [{line, code}] }
  const taintedVars = new Map();
  const taintFindings = [];

  const sourcePatterns = [
    { name: "Flask/Django Request Input", regex: /\brequest\.(?:args|form|values|json|cookies|headers|data)\b/ },
    { name: "Python Standard/CLI Input", regex: /\b(?:input\s*\(|sys\.argv\b)/ },
    { name: "Express/Node Request Input", regex: /\breq\.(?:query|body|params|headers|cookies)\b/ },
    { name: "Browser DOM URL/Storage Input", regex: /\b(?:location\.(?:search|hash|href)|document\.cookie|window\.name)\b/ },
    { name: "PHP Superglobal Input", regex: /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/ },
  ];

  const sanitizerPatterns = /\b(?:int\s*\(|float\s*\(|secure_filename\s*\(|escapeshellarg\s*\(|escapeshellcmd\s*\(|htmlspecialchars\s*\(|htmlentities\s*\(|DOMPurify\.sanitize\s*\(|path\.basename\s*\(|basename\s*\(|parseInt\s*\(|Number\s*\()/i;

  const sinkDefinitions = [
    {
      id: "VG-TAINT-SQLI",
      title: "Taint Flow: Untrusted User Input Reaches SQL Execution Sink",
      category: "SQLi",
      severity: "CRITICAL",
      cvss: 9.8,
      cwe: "CWE-89",
      owasp: "A03:2021 - Injection",
      sinkRegex: /\b(?:cursor\.execute|db\.execute|session\.execute|engine\.execute|db\.query|pool\.query|connection\.query|mysqli_query|mysql_query|\$\w+->query)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)/,
      description:
        "Multi-line taint analysis detected that a variable containing untrusted user input was dynamically interpolated into a query string and passed directly to a database execution sink without parameterization.",
      remediation:
        "Pass parameterized placeholders (?, %s, $1, :param) and bind the untrusted variable as a separate parameter tuple/array.",
      vulnerableExample: `user = request.args.get("user")\nsql = f"SELECT * FROM users WHERE name = '{user}'"\ncursor.execute(sql)`,
      secureExample: `user = request.args.get("user")\nsql = "SELECT * FROM users WHERE name = %s"\ncursor.execute(sql, (user,))`,
    },
    {
      id: "VG-TAINT-RCE",
      title: "Taint Flow: Untrusted User Input Reaches OS Command / Code Execution Sink",
      category: "RCE",
      severity: "CRITICAL",
      cvss: 9.8,
      cwe: "CWE-78",
      owasp: "A03:2021 - Injection",
      sinkRegex: /\b(?:os\.system|os\.popen|eval|exec|child_process\.exec|execSync|shell_exec|system|passthru| subprocess\.(?:Popen|run|call|check_output))\s*\(\s*([^)]+)\)/,
      description:
        "Multi-line taint analysis traced user-controlled data flowing into an OS command or dynamic code execution sink.",
      remediation:
        "Avoid passing user-derived strings to shell or eval sinks. Use subprocess.run([cmd, arg], shell=False) or strict allowlists.",
      vulnerableExample: `host = request.args.get("host")\ncmd = "ping -c 1 " + host\nos.system(cmd)`,
      secureExample: `host = request.args.get("host")\nsubprocess.run(["ping", "-c", "1", host], shell=False, check=True)`,
    },
    {
      id: "VG-TAINT-LFI",
      title: "Taint Flow: Untrusted User Input Reaches File System / Include Sink",
      category: "LFI",
      severity: "HIGH",
      cvss: 8.6,
      cwe: "CWE-22",
      owasp: "A01:2021 - Broken Access Control",
      sinkRegex: /\b(?:open|send_file|fs\.readFile|fs\.readFileSync|res\.sendFile|include|require|file_get_contents|readfile)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)/,
      description:
        "Multi-line taint analysis traced unvalidated user input into a file read or dynamic file inclusion sink, enabling Path Traversal or Local File Inclusion (LFI).",
      remediation:
        "Sanitize filenames with secure_filename() / path.basename() and verify the resolved canonical path stays inside an allowed base directory.",
      vulnerableExample: `target = request.args.get("report")\npath = "/var/reports/" + target\nreturn send_file(path)`,
      secureExample: `target = secure_filename(request.args.get("report", ""))\npath = (BASE_DIR / target).resolve()\nreturn send_file(path)`,
    },
  ];

  // Pass 1: Track variable assignments & taint propagation line by line
  lines.forEach((rawLine, idx) => {
    const lineNum = idx + 1;
    const trimmed = rawLine.trim();
    if (!trimmed || isCommentLine(trimmed)) return;

    // Match variable assignment: e.g. `const x = ...`, `x = ...`, `$x = ...`
    const assignMatch = trimmed.match(
      /^(?:(?:const|let|var)\s+)?(\$?[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/
    );

    if (assignMatch) {
      const lhsVar = assignMatch[1];
      const rhsExpr = assignMatch[2];

      // If RHS is wrapped in a known sanitizer, clear taint on lhsVar
      if (sanitizerPatterns.test(rhsExpr)) {
        taintedVars.delete(lhsVar);
        return;
      }

      // Check if RHS directly reads from an untrusted source
      for (const src of sourcePatterns) {
        if (src.regex.test(rhsExpr)) {
          taintedVars.set(lhsVar, {
            sourceName: src.name,
            sourceLine: lineNum,
            trace: [
              {
                line: lineNum,
                step: "Source",
                detail: `${lhsVar} assigned from ${src.name}`,
                code: trimmed,
              },
            ],
          });
          return;
        }
      }

      // Check if RHS references an already-tainted variable (taint propagation)
      for (const [tVar, taintInfo] of taintedVars.entries()) {
        const escapedVar = tVar.replace(/\$/g, "\\$");
        const varRefRegex = new RegExp(`(?:^|[^A-Za-z0-9_])${escapedVar}(?:$|[^A-Za-z0-9_])`);
        if (varRefRegex.test(rhsExpr)) {
          taintedVars.set(lhsVar, {
            sourceName: taintInfo.sourceName,
            sourceLine: taintInfo.sourceLine,
            trace: [
              ...taintInfo.trace,
              {
                line: lineNum,
                step: "Propagation",
                detail: `Taint propagated from ${tVar} into ${lhsVar}`,
                code: trimmed,
              },
            ],
          });
          return;
        }
      }
    }
  });

  // Pass 2: Check if any tainted variable reaches a sink
  lines.forEach((rawLine, idx) => {
    const lineNum = idx + 1;
    const trimmed = rawLine.trim();
    if (!trimmed || isCommentLine(trimmed)) return;

    for (const sink of sinkDefinitions) {
      const m = sink.sinkRegex.exec(trimmed);
      if (!m) continue;
      const argExpr = m[1];

      for (const [tVar, taintInfo] of taintedVars.entries()) {
        // Only trigger if source occurred before or on this line
        if (taintInfo.sourceLine > lineNum) continue;
        const escapedVar = tVar.replace(/\$/g, "\\$");
        const varRefRegex = new RegExp(`(?:^|[^A-Za-z0-9_])${escapedVar}(?:$|[^A-Za-z0-9_])`);
        if (varRefRegex.test(argExpr)) {
          const fullTrace = [
            ...taintInfo.trace,
            {
              line: lineNum,
              step: "Sink",
              detail: `Tainted variable '${tVar}' executed in sink`,
              code: trimmed,
            },
          ];

          taintFindings.push({
            id: `${sink.id}-L${lineNum}`,
            ruleId: sink.id,
            title: sink.title,
            category: sink.category,
            severity: sink.severity,
            cvss: sink.cvss,
            cwe: sink.cwe,
            owasp: sink.owasp,
            line: lineNum,
            column: m.index + 1,
            codeSnippet: trimmed,
            matchedToken: m[0],
            taintTrace: fullTrace,
            description: sink.description,
            remediation: sink.remediation,
            vulnerableExample: sink.vulnerableExample,
            secureExample: sink.secureExample,
          });
        }
      }
    }
  });

  return { taintedVars, taintFindings };
}

/**
 * Performs static code security analysis + multi-line taint analysis on source code.
 */
function analyzeSourceCode(code, selectedLanguage = "auto", filename = "snippet") {
  const startTime = performance.now();
  const resolvedLanguage =
    selectedLanguage === "auto" ? detectLanguage(code) : selectedLanguage;

  const lines = code.split(/\r?\n/);
  const findings = [];

  // 1. Run Multi-Line Source-to-Sink Taint Analysis first
  const { taintedVars, taintFindings } = runTaintAnalysis(lines, resolvedLanguage);

  // 2. Run Pattern & Contextual Rule Matching
  lines.forEach((rawLine, index) => {
    const lineNumber = index + 1;
    const trimmed = rawLine.trim();
    if (!trimmed || isCommentLine(trimmed)) return;

    SAST_RULES.forEach((rule) => {
      if (resolvedLanguage !== "all" && !rule.languages.includes(resolvedLanguage)) {
        return;
      }

      const match = rule.pattern.exec(rawLine);
      if (match) {
        const alreadyMatched = findings.some(
          (f) => f.line === lineNumber && f.category === rule.category
        );
        if (alreadyMatched) return;

        // Attach taint trace if any tainted variable is referenced on this line
        let attachedTrace = null;
        for (const [tVar, taintInfo] of taintedVars.entries()) {
          if (taintInfo.sourceLine <= lineNumber && rawLine.includes(tVar)) {
            attachedTrace = [
              ...taintInfo.trace,
              {
                line: lineNumber,
                step: "Sink",
                detail: `Tainted variable '${tVar}' reaches ${rule.category} sink`,
                code: trimmed,
              },
            ];
            break;
          }
        }

        findings.push({
          id: `${rule.id}-L${lineNumber}`,
          file: filename,
          ruleId: rule.id,
          title: rule.title,
          category: rule.category,
          severity: rule.severity,
          cvss: rule.cvss,
          cwe: rule.cwe,
          owasp: rule.owasp,
          line: lineNumber,
          column: match.index + 1,
          codeSnippet: trimmed,
          matchedToken: match[0],
          taintTrace: attachedTrace,
          description: rule.description,
          remediation: rule.remediation,
          vulnerableExample: rule.vulnerableExample,
          secureExample: rule.secureExample,
        });
      }
    });
  });

  // Merge any pure multi-line taint findings that weren't caught by single-line regex
  taintFindings.forEach((tf) => {
    const existsOnLine = findings.some(
      (f) => f.line === tf.line && f.category === tf.category
    );
    if (!existsOnLine) {
      findings.push({ ...tf, file: filename });
    }
  });

  const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  findings.sort((a, b) => {
    const diff = severityRank[b.severity] - severityRank[a.severity];
    return diff !== 0 ? diff : a.line - b.line;
  });

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const categories = { SQLi: 0, RCE: 0, LFI: 0, XSS: 0, SECRETS: 0 };

  findings.forEach((f) => {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
    categories[f.category] = (categories[f.category] || 0) + 1;
  });

  const penalty =
    counts.CRITICAL * 22 +
    counts.HIGH * 14 +
    counts.MEDIUM * 7 +
    counts.LOW * 3;
  const score = Math.max(0, 100 - penalty);

  let grade = "A+";
  if (score < 95) grade = "A";
  if (score < 85) grade = "B";
  if (score < 70) grade = "C";
  if (score < 50) grade = "D";
  if (score < 30 || counts.CRITICAL >= 2) grade = "F";

  const durationMs = Math.max(1, Math.round(performance.now() - startTime));

  return {
    filename,
    language: resolvedLanguage,
    totalLines: lines.length,
    taintedSourcesCount: taintedVars.size,
    durationMs,
    score,
    grade,
    counts,
    categories,
    findings,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Generates an OASIS SARIF v2.1.0 compliant JSON object for GitHub Code Scanning.
 */
function generateSarifReport(report) {
  const sarifSeverityMap = {
    CRITICAL: "error",
    HIGH: "error",
    MEDIUM: "warning",
    LOW: "note",
  };

  const uniqueRules = new Map();
  report.findings.forEach((f) => {
    if (!uniqueRules.has(f.ruleId)) {
      uniqueRules.set(f.ruleId, {
        id: f.ruleId,
        name: f.title.replace(/[^A-Za-z0-9]/g, ""),
        shortDescription: { text: f.title },
        fullDescription: { text: f.description },
        help: {
          text: `${f.remediation}\n\nSecure Example:\n${f.secureExample}`,
        },
        properties: {
          tags: ["security", f.cwe, f.owasp, f.category],
          "security-severity": String(f.cvss),
        },
      });
    }
  });

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "VulnGuard SAST",
            informationUri: "https://vulnguard-sast.vercel.app",
            version: "2.0.0",
            rules: Array.from(uniqueRules.values()),
          },
        },
        results: report.findings.map((f) => ({
          ruleId: f.ruleId,
          level: sarifSeverityMap[f.severity] || "warning",
          message: {
            text: `${f.title}: ${f.description} Remediation: ${f.remediation}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.file || report.filename || "snippet",
                },
                region: {
                  startLine: f.line,
                  startColumn: f.column,
                  snippet: { text: f.codeSnippet },
                },
              },
            },
          ],
        })),
      },
    ],
  };
}

/**
 * Scans a public GitHub repository by fetching its tree and analyzing source files.
 */
async function scanGitHubRepository(repoInput) {
  const clean = repoInput
    .trim()
    .replace(/^https?:\/\/github\.com\//i, "")
    .replace(/\.git$/i, "")
    .replace(/\/+$/, "");
  const parts = clean.split("/");
  if (parts.length < 2) {
    throw new Error("Enter a valid GitHub repository (e.g., 'owner/repo' or 'https://github.com/owner/repo').");
  }
  const [owner, repo] = parts;

  // 1. Get default branch
  const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`);
  if (!repoRes.ok) {
    throw new Error(`GitHub repository '${owner}/${repo}' not found or rate-limited (HTTP ${repoRes.status}).`);
  }
  const repoMeta = await repoRes.json();
  const branch = repoMeta.default_branch || "main";

  // 2. Get recursive git tree
  const treeRes = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`
  );
  if (!treeRes.ok) {
    throw new Error(`Could not fetch repository file tree (HTTP ${treeRes.status}).`);
  }
  const treeData = await treeRes.json();
  const codeExtensions = /\.(?:py|js|ts|php)$/i;

  const candidateFiles = (treeData.tree || [])
    .filter(
      (item) =>
        item.type === "blob" &&
        codeExtensions.test(item.path) &&
        !item.path.includes("node_modules/") &&
        !item.path.includes("vendor/") &&
        !item.path.includes(".min.js") &&
        (item.size || 0) < 120000
    )
    .slice(0, 12); // Scan up to 12 source files for fast interactive feedback

  if (candidateFiles.length === 0) {
    throw new Error("No Python (.py), JavaScript/TypeScript (.js/.ts), or PHP (.php) source files found in this repository.");
  }

  const fileReports = [];
  for (const fileNode of candidateFiles) {
    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${fileNode.path}`;
    const rawRes = await fetch(rawUrl);
    if (!rawRes.ok) continue;
    const code = await rawRes.text();
    const report = analyzeSourceCode(code, "auto", fileNode.path);
    fileReports.push({
      path: fileNode.path,
      code,
      report,
    });
  }

  return {
    owner,
    repo,
    branch,
    scannedFilesCount: fileReports.length,
    fileReports,
  };
}

/**
 * Parses dependency manifests (requirements.txt or package.json) and queries
 * the public OSV.dev CVE database for known vulnerabilities.
 */
async function scanDependenciesOSV(manifestContent) {
  const packages = [];
  const trimmed = manifestContent.trim();

  if (trimmed.startsWith("{")) {
    const parsed = JSON.parse(trimmed);
    const allDeps = {
      ...(parsed.dependencies || {}),
      ...(parsed.devDependencies || {}),
    };
    for (const [name, rawVer] of Object.entries(allDeps)) {
      const cleanVersion = String(rawVer).replace(/^[\^~>=<\s]+/, "").split(" ")[0];
      if (cleanVersion && /^\d/.test(cleanVersion)) {
        packages.push({ name, version: cleanVersion, ecosystem: "npm" });
      }
    }
  } else {
    const lines = trimmed.split(/\r?\n/);
    for (const line of lines) {
      const clean = line.split("#")[0].trim();
      if (!clean) continue;
      const match = clean.match(/^([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=)\s*([A-Za-z0-9_.\-]+)/);
      if (match) {
        packages.push({
          name: match[1],
          version: match[2],
          ecosystem: "PyPI",
        });
      }
    }
  }

  if (packages.length === 0) {
    throw new Error(
      "No pinned dependencies found. Provide a valid package.json or requirements.txt with version numbers (e.g., flask==2.0.1)."
    );
  }

  const queries = packages.map((pkg) => ({
    version: pkg.version,
    package: {
      name: pkg.name,
      ecosystem: pkg.ecosystem,
    },
  }));

  const batchRes = await fetch("https://api.osv.dev/v1/querybatch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ queries }),
  });

  if (!batchRes.ok) {
    throw new Error(`OSV API returned HTTP ${batchRes.status}`);
  }

  const batchData = await batchRes.json();
  const results = [];

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    const vulns = batchData.results?.[i]?.vulns || [];
    const detailedVulns = [];

    for (const v of vulns.slice(0, 3)) {
      try {
        const detailRes = await fetch(`https://api.osv.dev/v1/vulns/${v.id}`);
        if (detailRes.ok) {
          const detail = await detailRes.json();
          const aliases = detail.aliases || [];
          const cveId = aliases.find((a) => a.startsWith("CVE-")) || detail.id;
          detailedVulns.push({
            id: detail.id,
            cve: cveId,
            summary:
              detail.summary ||
              (detail.details ? detail.details.slice(0, 180) + "..." : "Known vulnerability reported in OSV database."),
            severity: detail.database_specific?.severity || "HIGH",
          });
        }
      } catch {
        detailedVulns.push({
          id: v.id,
          cve: v.id,
          summary: "Vulnerability entry reported in OSV database.",
          severity: "MEDIUM",
        });
      }
    }

    results.push({
      ...pkg,
      vulnCount: vulns.length,
      vulnerabilities: detailedVulns,
    });
  }

  return results;
}

/**
 * VulnGuard SAST v2.0 - Interactive Web Application Controller
 * Includes:
 * - Multi-line Source-to-Sink Taint Flow visualization
 * - Live Public GitHub Repository Multi-File Scanner
 * - OASIS SARIF v2.1.0, JSON, and Markdown Report Exporters
 * - OSV.dev Live Dependency CVE Scanner
 */





const SAMPLE_DEPENDENCY_MANIFESTS = {
  pypi: `# Sample Python requirements.txt with known historical CVEs
flask==2.0.1
Werkzeug==2.0.1
requests==2.25.0
PyYAML==5.3.1
jinja2==2.11.2
urllib3==1.26.4`,
  npm: `{
  "name": "legacy-web-service",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.17.1",
    "lodash": "4.17.19",
    "axios": "0.21.1",
    "jsonwebtoken": "8.5.1",
    "minimist": "1.2.5"
  }
}`,
};

let currentReport = null;
let activeCategoryFilter = "ALL";

document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  initSastEditor();
  initGitHubRepoScanner();
  initDependencyScanner();
  renderRulebookTable();

  loadCodeSample("python_flask");
});

function initNavigation() {
  const navButtons = document.querySelectorAll("[data-tab-target]");
  const sections = document.querySelectorAll("[data-tab-section]");

  navButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.getAttribute("data-tab-target");
      navButtons.forEach((b) => b.classList.remove("active-tab"));
      btn.classList.add("active-tab");

      sections.forEach((sec) => {
        sec.classList.toggle(
          "hidden",
          sec.getAttribute("data-tab-section") !== target
        );
      });
    });
  });
}

function initSastEditor() {
  const editor = document.getElementById("code-editor");
  const gutter = document.getElementById("line-gutter");
  const sampleSelect = document.getElementById("sample-select");
  const langSelect = document.getElementById("language-select");
  const scanBtn = document.getElementById("run-scan-btn");
  const clearBtn = document.getElementById("clear-code-btn");
  const fileInput = document.getElementById("file-upload-input");
  const exportSarifBtn = document.getElementById("export-sarif-btn");
  const exportJsonBtn = document.getElementById("export-json-btn");
  const exportMdBtn = document.getElementById("export-md-btn");

  editor.addEventListener("scroll", () => {
    gutter.scrollTop = editor.scrollTop;
  });

  editor.addEventListener("input", () => {
    executeSastScan();
  });

  sampleSelect.addEventListener("change", (e) => {
    if (e.target.value) {
      loadCodeSample(e.target.value);
    }
  });

  langSelect.addEventListener("change", () => {
    executeSastScan();
  });

  scanBtn.addEventListener("click", () => {
    executeSastScan();
  });

  clearBtn.addEventListener("click", () => {
    editor.value = "";
    sampleSelect.value = "";
    document.getElementById("current-filename").textContent = "untitled_snippet";
    updateLineGutter([]);
    executeSastScan();
  });

  fileInput.addEventListener("change", (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      editor.value = String(ev.target?.result || "");
      document.getElementById("current-filename").textContent = file.name;
      sampleSelect.value = "";
      langSelect.value = "auto";
      executeSastScan();
    };
    reader.readAsText(file);
  });

  document.querySelectorAll("[data-category-filter]").forEach((pill) => {
    pill.addEventListener("click", () => {
      activeCategoryFilter = pill.getAttribute("data-category-filter");
      document
        .querySelectorAll("[data-category-filter]")
        .forEach((p) => p.classList.remove("active-filter"));
      pill.classList.add("active-filter");
      if (currentReport) {
        renderFindingsList(currentReport.findings);
      }
    });
  });

  exportSarifBtn.addEventListener("click", exportReportSARIF);
  exportJsonBtn.addEventListener("click", exportReportJSON);
  exportMdBtn.addEventListener("click", exportReportMarkdown);
}

/**
 * Live Public GitHub Repository Scanner
 */
function initGitHubRepoScanner() {
  const repoInput = document.getElementById("github-repo-input");
  const scanRepoBtn = document.getElementById("scan-github-repo-btn");
  const filesBar = document.getElementById("github-repo-files-bar");

  if (!scanRepoBtn) return;

  scanRepoBtn.addEventListener("click", async () => {
    const repoQuery = repoInput.value.trim();
    if (!repoQuery) return;

    scanRepoBtn.disabled = true;
    scanRepoBtn.textContent = "Fetching Repo Files...";
    filesBar.classList.remove("hidden");
    filesBar.innerHTML = `<span class="text-xs text-slate-400">Scanning public GitHub repository <strong>${escapeHtml(repoQuery)}</strong> via GitHub API...</span>`;

    try {
      const repoScan = await scanGitHubRepository(repoQuery);
      const totalRepoFindings = repoScan.fileReports.reduce(
        (sum, f) => sum + f.report.findings.length,
        0
      );

      filesBar.innerHTML = `
        <div class="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs">
          <span class="font-semibold text-slate-200">
            Scanned <strong>${repoScan.scannedFilesCount}</strong> files in <code class="text-sky-400">${escapeHtml(repoScan.owner)}/${escapeHtml(repoScan.repo)}</code> (${escapeHtml(repoScan.branch)}) â€” Click any file to inspect:
          </span>
          <span class="rounded bg-slate-800 px-2.5 py-0.5 font-mono text-xs font-bold ${
            totalRepoFindings > 0 ? "text-amber-400" : "text-emerald-400"
          }">
            Total Repo Findings: ${totalRepoFindings}
          </span>
        </div>
        <div class="flex flex-wrap gap-1.5">
          ${repoScan.fileReports
            .map(
              (f, idx) => `
            <button type="button" data-repo-file-idx="${idx}"
                    class="rounded-lg border ${
                      f.report.findings.length > 0
                        ? "border-red-500/40 bg-red-500/10 text-red-300"
                        : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                    } px-2.5 py-1 font-mono text-xs hover:opacity-85 transition">
              ${escapeHtml(f.path)} (${f.report.findings.length})
            </button>
          `
            )
            .join("")}
        </div>
      `;

      filesBar.querySelectorAll("[data-repo-file-idx]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const idx = parseInt(btn.getAttribute("data-repo-file-idx"), 10);
          const selected = repoScan.fileReports[idx];
          if (selected) {
            document.getElementById("code-editor").value = selected.code;
            document.getElementById("current-filename").textContent = selected.path;
            document.getElementById("language-select").value = "auto";
            document.getElementById("sample-select").value = "";
            executeSastScan();
          }
        });
      });

      // Automatically load the first file with findings (or first file)
      const firstInteresting =
        repoScan.fileReports.find((f) => f.report.findings.length > 0) ||
        repoScan.fileReports[0];
      if (firstInteresting) {
        document.getElementById("code-editor").value = firstInteresting.code;
        document.getElementById("current-filename").textContent = firstInteresting.path;
        document.getElementById("language-select").value = "auto";
        document.getElementById("sample-select").value = "";
        executeSastScan();
      }
    } catch (err) {
      filesBar.innerHTML = `<span class="text-xs text-red-400"><strong>GitHub Scan Error:</strong> ${escapeHtml(err.message)}</span>`;
    } finally {
      scanRepoBtn.disabled = false;
      scanRepoBtn.textContent = "ðŸ” Scan GitHub Repo";
    }
  });
}

function loadCodeSample(sampleKey) {
  const sample = CODE_SAMPLES[sampleKey];
  if (!sample) return;

  const editor = document.getElementById("code-editor");
  const langSelect = document.getElementById("language-select");
  const filenameEl = document.getElementById("current-filename");

  editor.value = sample.code;
  langSelect.value = sample.language;
  filenameEl.textContent = sample.filename;

  executeSastScan();
}

function updateLineGutter(findings = []) {
  const editor = document.getElementById("code-editor");
  const gutter = document.getElementById("line-gutter");
  const lineCount = editor.value.split(/\r?\n/).length;

  const lineSeverityMap = {};
  findings.forEach((f) => {
    if (!lineSeverityMap[f.line] || f.severity === "CRITICAL") {
      lineSeverityMap[f.line] = f.severity;
    }
  });

  const html = [];
  for (let i = 1; i <= lineCount; i++) {
    const sev = lineSeverityMap[i];
    let badgeClass = "text-slate-500";
    let marker = "";
    if (sev === "CRITICAL") {
      badgeClass = "bg-red-500/20 text-red-400 font-bold";
      marker = "â— ";
    } else if (sev === "HIGH") {
      badgeClass = "bg-orange-500/20 text-orange-400 font-bold";
      marker = "â— ";
    } else if (sev === "MEDIUM") {
      badgeClass = "bg-yellow-500/20 text-yellow-300 font-semibold";
      marker = "â€¢ ";
    }
    html.push(
      `<div class="px-2 text-right select-none leading-6 ${badgeClass}" data-gutter-line="${i}">${marker}${i}</div>`
    );
  }
  gutter.innerHTML = html.join("");
}

function executeSastScan() {
  const editor = document.getElementById("code-editor");
  const langSelect = document.getElementById("language-select");
  const filename = document.getElementById("current-filename").textContent || "snippet";

  currentReport = analyzeSourceCode(editor.value, langSelect.value, filename);
  updateLineGutter(currentReport.findings);
  renderScoreDashboard(currentReport);
  renderFindingsList(currentReport.findings);
}

function renderScoreDashboard(report) {
  const scoreEl = document.getElementById("security-score-val");
  const gradeEl = document.getElementById("security-grade-badge");
  const metaEl = document.getElementById("scan-meta-info");

  scoreEl.textContent = `${report.score}/100`;
  gradeEl.textContent = report.grade;

  gradeEl.className =
    "px-3 py-1 rounded-lg text-lg font-extrabold tracking-tight border ";
  if (report.grade.startsWith("A")) {
    gradeEl.className += "bg-emerald-500/15 text-emerald-400 border-emerald-500/40";
  } else if (report.grade === "B" || report.grade === "C") {
    gradeEl.className += "bg-amber-500/15 text-amber-400 border-amber-500/40";
  } else {
    gradeEl.className += "bg-red-500/15 text-red-400 border-red-500/40";
  }

  const langLabel =
    report.language === "all" ? "Multi-Language" : report.language.toUpperCase();
  metaEl.textContent = `${langLabel} â€¢ ${report.totalLines} lines â€¢ ${report.taintedSourcesCount || 0} taint sources â€¢ ${report.durationMs}ms`;

  document.getElementById("count-critical").textContent = report.counts.CRITICAL;
  document.getElementById("count-high").textContent = report.counts.HIGH;
  document.getElementById("count-medium").textContent = `${report.counts.MEDIUM} Med`;
  document.getElementById("count-total").textContent = report.findings.length;

  document.getElementById("cat-count-all").textContent = report.findings.length;
  document.getElementById("cat-count-sqli").textContent = report.categories.SQLi;
  document.getElementById("cat-count-rce").textContent = report.categories.RCE;
  document.getElementById("cat-count-lfi").textContent = report.categories.LFI;
  document.getElementById("cat-count-xss").textContent = report.categories.XSS;
  document.getElementById("cat-count-secrets").textContent = report.categories.SECRETS;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function renderFindingsList(findings) {
  const container = document.getElementById("findings-container");
  const filtered =
    activeCategoryFilter === "ALL"
      ? findings
      : findings.filter((f) => f.category === activeCategoryFilter);

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-8 text-center">
        <div class="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-emerald-500/20 text-emerald-400 text-2xl">
          âœ“
        </div>
        <h3 class="text-lg font-semibold text-emerald-300">No Security Vulnerabilities Detected</h3>
        <p class="mt-1 text-sm text-slate-400">
          No ${activeCategoryFilter === "ALL" ? "" : activeCategoryFilter + " "}insecure patterns or taint flows matched across the current code snippet.
        </p>
      </div>
    `;
    return;
  }

  container.innerHTML = filtered
    .map((f, idx) => {
      const sevBadge =
        f.severity === "CRITICAL"
          ? "bg-red-500/20 text-red-400 border-red-500/40"
          : f.severity === "HIGH"
          ? "bg-orange-500/20 text-orange-400 border-orange-500/40"
          : "bg-yellow-500/20 text-yellow-300 border-yellow-500/40";

      const catBadge =
        {
          SQLi: "bg-purple-500/20 text-purple-300 border-purple-500/40",
          RCE: "bg-rose-500/20 text-rose-300 border-rose-500/40",
          LFI: "bg-cyan-500/20 text-cyan-300 border-cyan-500/40",
          XSS: "bg-amber-500/20 text-amber-300 border-amber-500/40",
          SECRETS: "bg-indigo-500/20 text-indigo-300 border-indigo-500/40",
        }[f.category] || "bg-slate-700 text-slate-300";

      const cweNum = f.cwe.replace("CWE-", "");

      const taintTraceHtml =
        f.taintTrace && f.taintTrace.length > 0
          ? `
        <div class="mt-3 rounded-lg border border-amber-500/30 bg-amber-950/15 p-3">
          <div class="mb-1.5 flex items-center justify-between text-[11px] font-bold uppercase tracking-wider text-amber-300">
            <span>ðŸ”— Source-to-Sink Data Flow Taint Trace (${f.taintTrace.length} hops)</span>
            <span>Taint Analysis</span>
          </div>
          <div class="space-y-1.5 font-mono text-xs">
            ${f.taintTrace
              .map(
                (hop) => `
              <div class="flex flex-wrap items-center gap-2 rounded bg-slate-950/80 px-2.5 py-1">
                <span class="rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${
                  hop.step === "Source"
                    ? "bg-sky-500/20 text-sky-300"
                    : hop.step === "Propagation"
                    ? "bg-amber-500/20 text-amber-300"
                    : "bg-red-500/20 text-red-300"
                }">${escapeHtml(hop.step)} (L${hop.line})</span>
                <span class="text-slate-400">${escapeHtml(hop.detail)}:</span>
                <code class="text-slate-200">${escapeHtml(hop.code)}</code>
              </div>
            `
              )
              .join("")}
          </div>
        </div>
      `
          : "";

      return `
      <article class="rounded-xl border border-slate-800 bg-slate-900/90 p-5 shadow-lg transition hover:border-slate-700">
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div class="flex flex-wrap items-center gap-2">
            <span class="rounded-md border px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider ${sevBadge}">
              ${escapeHtml(f.severity)} â€¢ CVSS ${f.cvss}
            </span>
            <span class="rounded-md border px-2.5 py-0.5 text-xs font-semibold ${catBadge}">
              ${escapeHtml(f.category)}
            </span>
            <span class="rounded-md bg-slate-800 px-2.5 py-0.5 font-mono text-xs text-slate-300">
              ${escapeHtml(f.ruleId)}
            </span>
            <a href="https://cwe.mitre.org/data/definitions/${escapeHtml(cweNum)}.html" target="_blank" rel="noopener noreferrer"
               class="rounded-md bg-slate-800/80 px-2.5 py-0.5 text-xs text-sky-400 hover:underline">
              ${escapeHtml(f.cwe)} â†—
            </a>
            <span class="rounded-md bg-slate-800/80 px-2.5 py-0.5 text-xs text-slate-400">
              ${escapeHtml(f.owasp)}
            </span>
          </div>

          <button type="button" data-jump-line="${f.line}"
                  class="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1 font-mono text-xs text-sky-300 hover:bg-slate-700">
            Line ${f.line}:${f.column}
          </button>
        </div>

        <h3 class="mt-3 text-base font-bold text-slate-100">
          ${escapeHtml(f.title)}
        </h3>

        <p class="mt-1.5 text-sm leading-relaxed text-slate-300">
          ${escapeHtml(f.description)}
        </p>

        <div class="mt-3 rounded-lg border border-red-500/30 bg-slate-950 p-3 font-mono text-xs">
          <div class="mb-1 flex items-center justify-between text-[11px] text-red-400">
            <span>DETECTED VULNERABLE SINK (LINE ${f.line})</span>
            <span>${f.taintTrace ? "Taint + Pattern Match" : "Pattern Match"}</span>
          </div>
          <pre class="overflow-x-auto text-red-300"><code>${escapeHtml(f.codeSnippet)}</code></pre>
        </div>

        ${taintTraceHtml}

        <div class="mt-3 rounded-lg border border-emerald-500/25 bg-emerald-950/15 p-3.5">
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold uppercase tracking-wider text-emerald-400">
              ðŸ›¡ï¸ Secure Remediation Guidance
            </span>
            <button type="button" data-copy-fix="${idx}"
                    class="rounded border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20">
              Copy Secure Pattern
            </button>
          </div>
          <p class="mt-1 text-xs leading-relaxed text-slate-300">
            ${escapeHtml(f.remediation)}
          </p>

          <div class="mt-3 grid grid-cols-1 gap-2.5 lg:grid-cols-2">
            <div class="rounded border border-red-500/20 bg-slate-950/90 p-2.5 font-mono text-xs">
              <div class="mb-1 text-[10px] font-semibold uppercase text-red-400">âŒ Vulnerable Pattern</div>
              <pre class="overflow-x-auto text-slate-300"><code>${escapeHtml(f.vulnerableExample)}</code></pre>
            </div>
            <div class="rounded border border-emerald-500/30 bg-slate-950/90 p-2.5 font-mono text-xs">
              <div class="mb-1 text-[10px] font-semibold uppercase text-emerald-400">âœ… Remediated Secure Code</div>
              <pre class="overflow-x-auto text-emerald-300"><code id="secure-fix-code-${idx}">${escapeHtml(f.secureExample)}</code></pre>
            </div>
          </div>
        </div>
      </article>
    `;
    })
    .join("");

  container.querySelectorAll("[data-jump-line]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const lineNum = parseInt(btn.getAttribute("data-jump-line"), 10);
      jumpToEditorLine(lineNum);
    });
  });

  container.querySelectorAll("[data-copy-fix]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = btn.getAttribute("data-copy-fix");
      const codeEl = document.getElementById(`secure-fix-code-${idx}`);
      if (codeEl && navigator.clipboard) {
        navigator.clipboard.writeText(codeEl.textContent);
        const original = btn.textContent;
        btn.textContent = "Copied âœ“";
        setTimeout(() => {
          btn.textContent = original;
        }, 1500);
      }
    });
  });
}

function jumpToEditorLine(lineNumber) {
  const editor = document.getElementById("code-editor");
  const lines = editor.value.split(/\r?\n/);
  let charOffset = 0;
  for (let i = 0; i < lineNumber - 1 && i < lines.length; i++) {
    charOffset += lines[i].length + 1;
  }
  const lineLength = (lines[lineNumber - 1] || "").length;

  editor.focus();
  editor.setSelectionRange(charOffset, charOffset + lineLength);
  editor.scrollTop = Math.max(0, (lineNumber - 4) * 24);
}

function exportReportSARIF() {
  if (!currentReport) return;
  const sarif = generateSarifReport(currentReport);
  const blob = new Blob([JSON.stringify(sarif, null, 2)], {
    type: "application/sarif+json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vulnguard-sast-${Date.now()}.sarif`;
  a.click();
  URL.revokeObjectURL(url);
}

function exportReportJSON() {
  if (!currentReport) return;
  const blob = new Blob([JSON.stringify(currentReport, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vulnguard-sast-report-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function exportReportMarkdown() {
  if (!currentReport) return;
  const r = currentReport;
  const lines = [
    `# VulnGuard SAST v2.0 Security Audit Report`,
    `- **File:** \`${r.filename}\``,
    `- **Timestamp:** ${r.timestamp}`,
    `- **Language:** ${r.language.toUpperCase()}`,
    `- **Security Score:** ${r.score}/100 (Grade: **${r.grade}**)`,
    `- **Total Findings:** ${r.findings.length} (Critical: ${r.counts.CRITICAL}, High: ${r.counts.HIGH}, Medium: ${r.counts.MEDIUM})`,
    ``,
    `## Findings Detail`,
    ``,
  ];

  r.findings.forEach((f, i) => {
    lines.push(`### ${i + 1}. [${f.severity}] ${f.title} (Line ${f.line})`);
    lines.push(
      `- **Rule ID:** \`${f.ruleId}\` | **Category:** \`${f.category}\` | **CWE:** ${f.cwe} | **OWASP:** ${f.owasp} | **CVSS:** ${f.cvss}`
    );
    lines.push(`- **Vulnerable Snippet:** \`${f.codeSnippet}\``);
    if (f.taintTrace) {
      lines.push(
        `- **Taint Flow:** ${f.taintTrace.map((t) => `${t.step} (L${t.line})`).join(" -> ")}`
      );
    }
    lines.push(`- **Risk Explanation:** ${f.description}`);
    lines.push(`- **Remediation:** ${f.remediation}`);
    lines.push(`- **Secure Code Example:**`);
    lines.push("```");
    lines.push(f.secureExample);
    lines.push("```");
    lines.push("");
  });

  const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vulnguard-audit-report-${Date.now()}.md`;
  a.click();
  URL.revokeObjectURL(url);
}

function initDependencyScanner() {
  const input = document.getElementById("dep-manifest-input");
  const loadPypiBtn = document.getElementById("load-pypi-sample");
  const loadNpmBtn = document.getElementById("load-npm-sample");
  const scanDepsBtn = document.getElementById("scan-deps-btn");
  const resultsEl = document.getElementById("dep-scan-results");

  input.value = SAMPLE_DEPENDENCY_MANIFESTS.pypi;

  loadPypiBtn.addEventListener("click", () => {
    input.value = SAMPLE_DEPENDENCY_MANIFESTS.pypi;
  });

  loadNpmBtn.addEventListener("click", () => {
    input.value = SAMPLE_DEPENDENCY_MANIFESTS.npm;
  });

  scanDepsBtn.addEventListener("click", async () => {
    scanDepsBtn.disabled = true;
    scanDepsBtn.textContent = "Querying OSV.dev CVE Database...";
    resultsEl.innerHTML = `
      <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-8 text-center text-sm text-slate-400">
        Querying live OSV.dev vulnerability database for package versions...
      </div>
    `;

    try {
      const results = await scanDependenciesOSV(input.value);
      const totalVulns = results.reduce((acc, r) => acc + r.vulnCount, 0);

      resultsEl.innerHTML = `
        <div class="mb-4 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div>
            <h4 class="font-bold text-slate-100">Scanned ${results.length} Dependencies via OSV.dev API</h4>
            <p class="text-xs text-slate-400">Live CVE & GHSA advisory lookup completed</p>
          </div>
          <span class="rounded-lg px-3 py-1 text-sm font-bold ${
            totalVulns > 0
              ? "bg-red-500/20 text-red-400 border border-red-500/40"
              : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
          }">
            ${totalVulns} Known Vulnerabilities Found
          </span>
        </div>
        <div class="space-y-3">
          ${results
            .map(
              (pkg) => `
            <div class="rounded-xl border ${
              pkg.vulnCount > 0
                ? "border-red-500/30 bg-slate-900"
                : "border-slate-800 bg-slate-900/60"
            } p-4">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-2">
                  <span class="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-sky-400">${escapeHtml(pkg.ecosystem)}</span>
                  <span class="font-mono text-sm font-bold text-slate-100">${escapeHtml(pkg.name)}@${escapeHtml(pkg.version)}</span>
                </div>
                <span class="rounded px-2.5 py-0.5 text-xs font-semibold ${
                  pkg.vulnCount > 0
                    ? "bg-red-500/20 text-red-400"
                    : "bg-emerald-500/20 text-emerald-400"
                }">
                  ${pkg.vulnCount > 0 ? `${pkg.vulnCount} Advisories` : "Clean âœ“"}
                </span>
              </div>
              ${
                pkg.vulnerabilities.length > 0
                  ? `<div class="mt-3 space-y-2 border-t border-slate-800 pt-2.5">
                      ${pkg.vulnerabilities
                        .map(
                          (v) => `
                        <div class="rounded bg-slate-950 p-2.5 text-xs">
                          <div class="flex items-center justify-between font-mono">
                            <a href="https://osv.dev/vulnerability/${escapeHtml(v.id)}" target="_blank" rel="noopener noreferrer" class="font-bold text-amber-400 hover:underline">
                              ${escapeHtml(v.cve)} (${escapeHtml(v.id)}) â†—
                            </a>
                            <span class="text-slate-400">${escapeHtml(v.severity)}</span>
                          </div>
                          <p class="mt-1 text-slate-300">${escapeHtml(v.summary)}</p>
                        </div>
                      `
                        )
                        .join("")}
                    </div>`
                  : ""
              }
            </div>
          `
            )
            .join("")}
        </div>
      `;
    } catch (err) {
      resultsEl.innerHTML = `
        <div class="rounded-xl border border-red-500/40 bg-red-950/20 p-4 text-sm text-red-300">
          <strong>Error:</strong> ${escapeHtml(err.message)}
        </div>
      `;
    } finally {
      scanDepsBtn.disabled = false;
      scanDepsBtn.textContent = "Scan Dependencies against CVE Database";
    }
  });
}

function renderRulebookTable() {
  const tbody = document.getElementById("rulebook-tbody");
  if (!tbody) return;

  tbody.innerHTML = SAST_RULES.map(
    (rule) => `
    <tr class="border-b border-slate-800/80 hover:bg-slate-900/60">
      <td class="px-4 py-3 font-mono text-xs font-bold text-sky-400">${escapeHtml(rule.id)}</td>
      <td class="px-4 py-3 text-xs font-semibold text-slate-200">${escapeHtml(rule.category)}</td>
      <td class="px-4 py-3 text-xs">
        <span class="rounded px-2 py-0.5 font-bold ${
          rule.severity === "CRITICAL"
            ? "bg-red-500/20 text-red-400"
            : rule.severity === "HIGH"
            ? "bg-orange-500/20 text-orange-400"
            : "bg-yellow-500/20 text-yellow-300"
        }">${escapeHtml(rule.severity)} (${rule.cvss})</span>
      </td>
      <td class="px-4 py-3 text-xs text-slate-200">${escapeHtml(rule.title)}</td>
      <td class="px-4 py-3 font-mono text-xs text-slate-400">${escapeHtml(rule.cwe)}</td>
      <td class="px-4 py-3 text-xs text-slate-400">${escapeHtml(rule.owasp)}</td>
      <td class="px-4 py-3 font-mono text-xs text-slate-400">${escapeHtml(rule.languages.join(", "))}</td>
    </tr>
  `
  ).join("");
}

})();
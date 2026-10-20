/**
 * VulnGuard SAST - Built-in Educational Code Samples
 * Demonstrates how SAST detects SQLi, RCE, LFI, XSS, and Hardcoded Secrets
 * across Python, JavaScript (Node.js), and PHP, plus a hardened A+ reference sample.
 */

export const CODE_SAMPLES = {
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

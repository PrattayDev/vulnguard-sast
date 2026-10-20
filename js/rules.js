/**
 * VulnGuard SAST - Static Application Security Testing Rule Definitions
 * Detects insecure coding patterns across Python, JavaScript/TypeScript, and PHP
 * Maps findings to OWASP Top 10 (2021) and CWE identifiers with secure remediations.
 */

export const SAST_RULES = [
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

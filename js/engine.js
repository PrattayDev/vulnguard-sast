/**
 * VulnGuard SAST & SCA Engine v2.0
 * 1. Multi-language Static Application Security Testing (SAST) with Source-to-Sink Taint Analysis
 * 2. Live Software Composition Analysis (SCA) against the OSV.dev CVE Database
 * 3. Public GitHub Repository Multi-File Scanner
 * 4. OASIS SARIF v2.1.0 Report Generator
 */

import { SAST_RULES } from "./rules.js";

/**
 * Automatically detects the programming language of a source snippet.
 */
export function detectLanguage(code) {
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
export function runTaintAnalysis(lines, language) {
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
export function analyzeSourceCode(code, selectedLanguage = "auto", filename = "snippet") {
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
export function generateSarifReport(report) {
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
export async function scanGitHubRepository(repoInput) {
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
export async function scanDependenciesOSV(manifestContent) {
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

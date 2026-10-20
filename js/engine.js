/**
 * VulnGuard SAST & SCA Engine
 * 1. Multi-language Static Application Security Testing (SAST) for SQLi, RCE, LFI, XSS, and Secrets
 * 2. Live Software Composition Analysis (SCA) against the OSV.dev CVE Database
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

/**
 * Checks whether a trimmed line of code is a single-line comment.
 */
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
 * Performs static code security analysis on the provided source code.
 */
export function analyzeSourceCode(code, selectedLanguage = "auto") {
  const startTime = performance.now();
  const resolvedLanguage =
    selectedLanguage === "auto" ? detectLanguage(code) : selectedLanguage;

  const lines = code.split(/\r?\n/);
  const findings = [];

  lines.forEach((rawLine, index) => {
    const lineNumber = index + 1;
    const trimmed = rawLine.trim();
    if (!trimmed || isCommentLine(trimmed)) {
      return;
    }

    SAST_RULES.forEach((rule) => {
      if (
        resolvedLanguage !== "all" &&
        !rule.languages.includes(resolvedLanguage)
      ) {
        return;
      }

      const match = rule.pattern.exec(rawLine);
      if (match) {
        // Avoid duplicate category hit on the exact same line if a higher-specificity rule already matched
        const alreadyMatchedSameCategoryOnLine = findings.some(
          (f) => f.line === lineNumber && f.category === rule.category
        );
        if (alreadyMatchedSameCategoryOnLine) {
          return;
        }

        const contextStart = Math.max(0, index - 1);
        const contextEnd = Math.min(lines.length - 1, index + 1);
        const contextLines = [];
        for (let i = contextStart; i <= contextEnd; i++) {
          contextLines.push({
            lineNumber: i + 1,
            content: lines[i],
            isTarget: i === index,
          });
        }

        findings.push({
          id: `${rule.id}-L${lineNumber}`,
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
          contextLines,
          description: rule.description,
          remediation: rule.remediation,
          vulnerableExample: rule.vulnerableExample,
          secureExample: rule.secureExample,
        });
      }
    });
  });

  // Sort findings by severity weight, then line number
  const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  findings.sort((a, b) => {
    const diff = severityRank[b.severity] - severityRank[a.severity];
    return diff !== 0 ? diff : a.line - b.line;
  });

  // Compute Security Score & Grade
  const counts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };
  const categories = {
    SQLi: 0,
    RCE: 0,
    LFI: 0,
    XSS: 0,
    SECRETS: 0,
  };

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
    language: resolvedLanguage,
    totalLines: lines.length,
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
 * Parses dependency manifests (requirements.txt or package.json) and queries
 * the public OSV.dev CVE database for known vulnerabilities.
 */
export async function scanDependenciesOSV(manifestContent) {
  const packages = [];
  const trimmed = manifestContent.trim();

  if (trimmed.startsWith("{")) {
    // Parse as package.json (npm)
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
    // Parse as requirements.txt (PyPI)
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

    // Fetch details for up to 3 vulnerabilities per package for speed
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

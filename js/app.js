/**
 * VulnGuard SAST v2.0 - Interactive Web Application Controller
 * Includes:
 * - Multi-line Source-to-Sink Taint Flow visualization
 * - Live Public GitHub Repository Multi-File Scanner
 * - OASIS SARIF v2.1.0, JSON, and Markdown Report Exporters
 * - OSV.dev Live Dependency CVE Scanner
 */

import { SAST_RULES } from "./rules.js";
import { CODE_SAMPLES } from "./samples.js";
import {
  analyzeSourceCode,
  scanDependenciesOSV,
  generateSarifReport,
  scanGitHubRepository,
} from "./engine.js";

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
            Scanned <strong>${repoScan.scannedFilesCount}</strong> files in <code class="text-sky-400">${escapeHtml(repoScan.owner)}/${escapeHtml(repoScan.repo)}</code> (${escapeHtml(repoScan.branch)}) — Click any file to inspect:
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
      scanRepoBtn.textContent = "🔍 Scan GitHub Repo";
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
      marker = "● ";
    } else if (sev === "HIGH") {
      badgeClass = "bg-orange-500/20 text-orange-400 font-bold";
      marker = "● ";
    } else if (sev === "MEDIUM") {
      badgeClass = "bg-yellow-500/20 text-yellow-300 font-semibold";
      marker = "• ";
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
  metaEl.textContent = `${langLabel} • ${report.totalLines} lines • ${report.taintedSourcesCount || 0} taint sources • ${report.durationMs}ms`;

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
          ✓
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
            <span>🔗 Source-to-Sink Data Flow Taint Trace (${f.taintTrace.length} hops)</span>
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
              ${escapeHtml(f.severity)} • CVSS ${f.cvss}
            </span>
            <span class="rounded-md border px-2.5 py-0.5 text-xs font-semibold ${catBadge}">
              ${escapeHtml(f.category)}
            </span>
            <span class="rounded-md bg-slate-800 px-2.5 py-0.5 font-mono text-xs text-slate-300">
              ${escapeHtml(f.ruleId)}
            </span>
            <a href="https://cwe.mitre.org/data/definitions/${escapeHtml(cweNum)}.html" target="_blank" rel="noopener noreferrer"
               class="rounded-md bg-slate-800/80 px-2.5 py-0.5 text-xs text-sky-400 hover:underline">
              ${escapeHtml(f.cwe)} ↗
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
              🛡️ Secure Remediation Guidance
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
              <div class="mb-1 text-[10px] font-semibold uppercase text-red-400">❌ Vulnerable Pattern</div>
              <pre class="overflow-x-auto text-slate-300"><code>${escapeHtml(f.vulnerableExample)}</code></pre>
            </div>
            <div class="rounded border border-emerald-500/30 bg-slate-950/90 p-2.5 font-mono text-xs">
              <div class="mb-1 text-[10px] font-semibold uppercase text-emerald-400">✅ Remediated Secure Code</div>
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
        btn.textContent = "Copied ✓";
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
                  ${pkg.vulnCount > 0 ? `${pkg.vulnCount} Advisories` : "Clean ✓"}
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
                              ${escapeHtml(v.cve)} (${escapeHtml(v.id)}) ↗
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

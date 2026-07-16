import type {
  AssetDTO,
  CandidateDTO,
  FindingDTO,
  ReportFile,
  ReportFormat,
  WstgTestDTO,
} from "./types";

export type ReportData = {
  tests: WstgTestDTO[];
  candidates: CandidateDTO[];
  findings: FindingDTO[];
  assets: AssetDTO[];
};

const SENSITIVE_KEY =
  "password|passwd|pwd|token|secret|api[_-]?key|client[_-]?secret|authorization|cookie|session";

export function buildReport(
  format: ReportFormat,
  data: ReportData,
  generatedAt = new Date().toISOString(),
): ReportFile {
  const safeTimestamp = generatedAt.replace(/[:.]/g, "-");
  if (format === "html")
    return {
      filename: `caido-wstg-flow-${safeTimestamp}.html`,
      mediaType: "text/html;charset=utf-8",
      content: htmlReport(data, generatedAt),
    };
  if (format === "json")
    return {
      filename: `caido-wstg-flow-${safeTimestamp}.json`,
      mediaType: "application/json;charset=utf-8",
      content: JSON.stringify(
        exportableReport(data, generatedAt),
        undefined,
        2,
      ),
    };
  return {
    filename: `caido-wstg-flow-findings-${safeTimestamp}.csv`,
    mediaType: "text/csv;charset=utf-8",
    content: findingCSV(data.findings),
  };
}

function exportableReport(data: ReportData, generatedAt: string) {
  return {
    generatedAt,
    generator: "Caido WSTG Flow 1.2.0",
    notice:
      "Candidates are review leads, not vulnerability verdicts. Raw HTTP and request identifiers are excluded.",
    summary: {
      tests: data.tests.length,
      tested: data.tests.filter((test) => test.status !== "NOT_TESTED").length,
      candidates: data.candidates.length,
      confirmedFindings: data.findings.length,
      assets: data.assets.length,
    },
    checklist: data.tests.map((test) => ({
      id: test.id,
      category: test.category,
      name: test.name,
      status: test.status,
      notes: redact(test.notes),
      candidateCount: test.candidateCount,
    })),
    findings: data.findings.map((finding) => ({
      title: redact(finding.title),
      severity: finding.severity,
      confidence: finding.confidence,
      url: redact(finding.url),
      method: finding.method,
      statusCode: finding.statusCode,
      wstgId: finding.wstgId,
      comment: redact(finding.comment),
      evidence: redact(finding.evidence),
      published: finding.published,
    })),
    candidates: data.candidates.map((candidate) => ({
      title: redact(candidate.title),
      ruleId: candidate.ruleId,
      category: candidate.category,
      severity: candidate.severity,
      confidence: candidate.confidence,
      url: redact(candidate.url),
      method: candidate.method,
      statusCode: candidate.statusCode,
      wstgId: candidate.wstgId,
      parameter: candidate.parameter,
      location: candidate.location,
      evidence: redact(candidate.evidence),
      explanation: redact(candidate.explanation),
      status: candidate.status,
      decisionNotes: redact(candidate.decisionNotes),
      occurrenceCount: candidate.occurrenceCount,
      comparison:
        candidate.comparison?.summary !== undefined &&
        candidate.comparison.summary !== ""
          ? redact(candidate.comparison.summary)
          : undefined,
    })),
    assets: data.assets.map((asset) => ({
      kind: asset.kind,
      url: redact(asset.url),
      sourceUrl: redact(asset.sourceUrl),
      discoveredAt: asset.discoveredAt,
    })),
  };
}

export function redact(value: string): string {
  return value
    .replace(
      /^(Authorization|Cookie|Set-Cookie|Proxy-Authorization):.*$/gim,
      "$1: [REDACTED]",
    )
    .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(
      new RegExp(
        `(${SENSITIVE_KEY})(=|%3d|:\\s*|"\\s*:\\s*")[^&\\s,}"]{3,}`,
        "gi",
      ),
      "$1$2[REDACTED]",
    )
    .replace(
      /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
      "[REDACTED_JWT]",
    );
}

function htmlReport(data: ReportData, generatedAt: string): string {
  const report = exportableReport(data, generatedAt);
  const checklist = report.checklist
    .map(
      (test) =>
        `<tr><td>${escapeHTML(test.id)}</td><td>${escapeHTML(test.category)}</td><td>${escapeHTML(test.name)}</td><td>${escapeHTML(test.status)}</td><td>${escapeHTML(test.notes)}</td></tr>`,
    )
    .join("");
  const findings = report.findings
    .map(
      (finding) =>
        `<tr><td>${escapeHTML(finding.severity)}</td><td>${escapeHTML(finding.title)}</td><td>${escapeHTML(finding.wstgId)}</td><td>${escapeHTML(`${finding.method} ${finding.url}`)}</td><td>${escapeHTML(`${finding.comment}\n${finding.evidence}`)}</td></tr>`,
    )
    .join("");
  const candidates = report.candidates
    .map(
      (candidate) =>
        `<tr><td>${escapeHTML(candidate.status)}</td><td>${escapeHTML(candidate.severity)}</td><td>${escapeHTML(candidate.title)}</td><td>${escapeHTML(`${candidate.method} ${candidate.url}`)}</td><td>${escapeHTML(candidate.wstgId)}</td><td>${escapeHTML(candidate.decisionNotes)}</td></tr>`,
    )
    .join("");
  const assets = report.assets
    .map(
      (asset) =>
        `<tr><td>${escapeHTML(asset.kind)}</td><td>${escapeHTML(asset.url)}</td><td>${escapeHTML(asset.sourceUrl)}</td></tr>`,
    )
    .join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Caido WSTG Flow Report</title><style>body{font:14px system-ui;margin:32px;color:#17202a}h1{color:#c2410c}table{border-collapse:collapse;width:100%;margin:16px 0 32px}th,td{border:1px solid #ccd1d1;padding:7px;text-align:left;vertical-align:top;white-space:pre-wrap}th{background:#273746;color:white}.notice{padding:12px;background:#fff7ed;border:1px solid #fdba74}</style></head><body><h1>Caido WSTG Flow Report</h1><p>Generated ${escapeHTML(generatedAt)} by Caido WSTG Flow 1.2.0.</p><p class="notice">Candidates are review leads, not vulnerability verdicts. Raw HTTP, request identifiers, credentials, and common sensitive values are excluded.</p><h2>Summary</h2><p>${report.summary.tested}/${report.summary.tests} tests reviewed · ${report.summary.candidates} candidates · ${report.summary.confirmedFindings} confirmed findings · ${report.summary.assets} assets</p><h2>Checklist</h2><table><thead><tr><th>ID</th><th>Category</th><th>Test</th><th>Status</th><th>Notes</th></tr></thead><tbody>${checklist}</tbody></table><h2>Confirmed findings</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>WSTG</th><th>Endpoint</th><th>Evidence</th></tr></thead><tbody>${findings}</tbody></table><h2>Candidate decisions</h2><table><thead><tr><th>Status</th><th>Severity</th><th>Candidate</th><th>Endpoint</th><th>WSTG</th><th>Decision notes</th></tr></thead><tbody>${candidates}</tbody></table><h2>Discovered assets</h2><table><thead><tr><th>Kind</th><th>URL</th><th>Source</th></tr></thead><tbody>${assets}</tbody></table></body></html>`;
}

function findingCSV(findings: FindingDTO[]): string {
  const header = [
    "Severity",
    "Title",
    "URL",
    "Method",
    "Status",
    "WSTG",
    "Confidence",
    "Comment",
    "Evidence",
  ];
  const rows = findings.map((finding) => [
    finding.severity,
    redact(finding.title),
    redact(finding.url),
    finding.method,
    finding.statusCode,
    finding.wstgId,
    finding.confidence,
    redact(finding.comment),
    redact(finding.evidence),
  ]);
  return `${header.map(csv).join(",")}\n${rows
    .map((row) => row.map(csv).join(","))
    .join("\n")}`;
}

function csv(value: unknown): string {
  let text: string;
  if (value === undefined || value === null) text = "";
  else if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    typeof value === "bigint"
  )
    text = String(value);
  else text = JSON.stringify(value);
  if (/^[=+@-]/.test(text.trimStart())) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function escapeHTML(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

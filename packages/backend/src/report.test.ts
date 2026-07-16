import { describe, expect, it } from "vitest";

import { buildReport, redact, type ReportData } from "./report";

describe("redacted reports", () => {
  it("redacts authentication headers, URL credentials, secrets, and JWTs", () => {
    const value = redact(
      "Authorization: Bearer abc\nCookie: sid=secret\nhttps://alice:password@example.test/?token=abcdefghi eyJabcdefgh.eyJabcdefgh.abcdefgh",
    );
    expect(value).not.toContain("Bearer abc");
    expect(value).not.toContain("alice:password");
    expect(value).not.toContain("abcdefghi");
    expect(value).toContain("[REDACTED_JWT]");
  });

  it("escapes HTML and includes every report section", () => {
    const file = buildReport("html", data(), "2026-07-15T10:00:00.000Z");
    expect(file.filename).toContain("2026-07-15T10-00-00-000Z");
    expect(file.content).toContain("Checklist");
    expect(file.content).toContain("Candidate decisions");
    expect(file.content).toContain("Discovered assets");
    expect(file.content).toContain("&lt;script&gt;");
    expect(file.content).not.toContain("<script>alert");
    expect(file.content).not.toContain("request-1");
  });

  it("exports structured JSON without internal identifiers", () => {
    const file = buildReport("json", data(), "2026-07-15T10:00:00.000Z");
    const parsed = JSON.parse(file.content) as Record<string, unknown>;
    expect(parsed.generator).toBe("Caido WSTG Flow 1.2.0");
    expect(file.content).not.toContain("request-1");
    expect(file.content).not.toContain("fingerprint-1");
  });

  it("guards CSV cells against spreadsheet formulas", () => {
    const value = data();
    value.findings[0]!.title = '=HYPERLINK("https://evil.test")';
    const file = buildReport("csv", value, "2026-07-15T10:00:00.000Z");
    expect(file.content).toContain("'=HYPERLINK");
  });
});

function data(): ReportData {
  return {
    tests: [
      {
        id: "WSTG-TEST-01",
        category: "Test",
        name: "Example",
        commonName: "Example",
        reference: "https://owasp.org/",
        objectives: "Objective",
        status: "FAIL",
        notes: "<script>alert(1)</script>",
        candidateCount: 1,
      },
    ],
    candidates: [candidate()],
    findings: [
      {
        projectId: "project-1",
        id: "finding-1",
        candidateId: "candidate-1",
        createdAt: "2026-07-15T10:00:00.000Z",
        title: "Example finding",
        severity: "High",
        confidence: "Confirmed",
        url: "https://example.test/?token=abcdefghi",
        method: "GET",
        statusCode: 200,
        wstgId: "WSTG-TEST-01",
        comment: "Validated",
        evidence: "Authorization: Bearer abc",
        remediation: "",
        requestId: "request-1",
        published: true,
      },
    ],
    assets: [
      {
        projectId: "project-1",
        id: "asset-1",
        url: "https://example.test/app.js",
        sourceUrl: "https://example.test/",
        kind: "Absolute URL",
        discoveredAt: "2026-07-15T10:00:00.000Z",
      },
    ],
  };
}

function candidate(): ReportData["candidates"][number] {
  return {
    projectId: "project-1",
    id: "candidate-1",
    fingerprint: "fingerprint-1",
    requestId: "request-1",
    responseId: "response-1",
    createdAt: "2026-07-15T10:00:00.000Z",
    lastSeen: "2026-07-15T10:00:00.000Z",
    occurrenceCount: 1,
    ruleId: "param.object_reference",
    title: "Example candidate",
    category: "Authorization",
    severity: "Medium",
    confidence: "Tentative",
    url: "https://example.test/orders/1",
    method: "GET",
    statusCode: 200,
    wstgId: "WSTG-TEST-01",
    parameter: "id",
    location: "QUERY",
    evidence: "id=[REDACTED]",
    explanation: "Review manually",
    recommendedTest: "Use two accounts",
    payloads: ["2"],
    status: "REVIEWING",
    decisionNotes: "No password=abcdefgh",
    published: false,
  };
}

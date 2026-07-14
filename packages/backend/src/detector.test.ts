import { describe, expect, it } from "vitest";

import { analyze, parseParameters } from "./detector";
import type { AnalyzerInput } from "./types";

describe("WSTG passive detector", () => {
  it("discovers object references and renders payload suggestions", () => {
    const result = analyze(input({ query: "user_id=42" }));
    const candidate = result.candidates.find(
      (value) => value.ruleId === "param.object_reference",
    );
    expect(candidate?.wstgId).toBe("WSTG-ATHZ-04");
    expect(candidate?.payloads.length).toBeGreaterThan(0);
    expect(candidate?.url).toContain("[REDACTED]");
  });

  it("requires an observed external redirect", () => {
    const result = analyze(
      input({
        query: "next=https%3A%2F%2Fevil.test%2F",
        statusCode: 302,
        responseHeaders: { Location: ["https://evil.test/"] },
      }),
    );
    expect(
      result.candidates.some((value) => value.ruleId === "param.redirect"),
    ).toBe(true);
  });

  it("extracts JavaScript endpoints without fetching them", () => {
    const result = analyze(
      input({
        path: "/app.js",
        responseContentType: "application/javascript",
        responseBody: 'fetch("/api/users"); //# sourceMappingURL=app.js.map',
      }),
    );
    expect(
      result.assets.some((asset) => asset.kind === "JavaScript endpoint"),
    ).toBe(true);
    expect(result.assets.some((asset) => asset.kind === "Source map")).toBe(
      true,
    );
  });

  it("parses bounded JSON parameters", () => {
    const values = parseParameters(
      "",
      '{"role":"admin"}',
      "application/json",
      [],
    );
    expect(values).toContainEqual({
      name: "role",
      value: "admin",
      location: "JSON",
    });
  });
});

function input(overrides: Partial<AnalyzerInput> = {}): AnalyzerInput {
  const query = overrides.query ?? "";
  const requestBody = overrides.requestBody ?? "";
  const requestContentType = overrides.requestContentType ?? "";
  return {
    requestId: "request-1",
    responseId: "response-1",
    method: "GET",
    url: `https://example.test/api/users${query === "" ? "" : `?${query}`}`,
    host: "example.test",
    path: "/api/users",
    query,
    headers: {},
    parameters: parseParameters(query, requestBody, requestContentType, []),
    requestRaw: "GET /api/users HTTP/1.1\r\nHost: example.test\r\n\r\n",
    requestBody,
    requestContentType,
    statusCode: 200,
    responseHeaders: { "Content-Type": ["application/json"] },
    responseRaw: "HTTP/1.1 200 OK\r\n\r\n{}",
    responseBody: "{}",
    responseContentType: "application/json",
    ...overrides,
  };
}

import { describe, expect, it } from "vitest";

import { formatDate, safeMessage, splitList, statusLabel } from "./utils";

describe("frontend utilities", () => {
  it("formats status labels", () => {
    expect(statusLabel("POSSIBLE_AUTHORIZATION_BYPASS")).toBe(
      "possible authorization bypass",
    );
  });

  it("normalizes and deduplicates host lists", () => {
    expect(splitList("EXAMPLE.test\nexample.test, cdn.test")).toEqual([
      "example.test",
      "cdn.test",
    ]);
  });

  it("extracts safe error messages", () => {
    expect(safeMessage(new Error("failed"))).toBe("failed");
    expect(safeMessage("failed")).toBe("failed");
  });

  it("formats valid timestamps for the current locale", () => {
    expect(formatDate("2026-07-15T10:00:00.000Z")).not.toBe("");
  });
});

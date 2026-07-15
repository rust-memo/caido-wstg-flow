/// <reference types="node" />

import { DatabaseSync } from "node:sqlite";

import type { SDK } from "caido:plugin";
import type { Database, Parameter } from "sqlite";
import { describe, expect, it } from "vitest";

import {
  normalizeAssetQuery,
  normalizeCandidateQuery,
  normalizePageQuery,
  WstgStore,
} from "./store";
import type { DetectedCandidate } from "./types";

describe("bounded list queries", () => {
  it("normalizes candidate filters and page limits", () => {
    expect(
      normalizeCandidateQuery({
        search: "  ADMIN  ",
        status: "NEW",
        severity: "High",
        offset: -20,
        limit: 500,
      }),
    ).toEqual({
      search: "admin",
      status: "NEW",
      severity: "High",
      offset: 0,
      limit: 100,
    });
  });

  it("bounds asset and generic page requests", () => {
    expect(
      normalizeAssetQuery({ search: "  APP.JS ", offset: 12.6, limit: 0 }),
    ).toEqual({ search: "app.js", offset: 13, limit: 1 });
    expect(normalizePageQuery({ offset: 2_000_000, limit: 50 })).toEqual({
      offset: 1_000_000,
      limit: 50,
    });
  });

  it("migrates existing data and serves bounded filtered pages", async () => {
    const raw = new DatabaseSync(":memory:");
    const database = asyncDatabase(raw);
    const store = new WstgStore();
    await store.initialize(sdk(database));

    await store.addAnalysis(
      "project-1",
      [
        candidate("one", "High", "https://example.test/admin?id=1"),
        candidate("two", "Medium", "https://example.test/users?id=2"),
      ],
      [
        {
          url: "https://example.test/app.js",
          sourceUrl: "https://example.test/",
          kind: "Absolute URL",
        },
      ],
      10,
    );
    await store.addAnalysis(
      "project-1",
      [candidate("one", "High", "https://example.test/admin?id=1")],
      [],
      10,
    );

    const firstPage = await store.listCandidates("project-1", {
      search: "admin",
      status: "ALL",
      severity: "High",
      offset: 0,
      limit: 1,
    });
    expect(firstPage.total).toBe(1);
    expect(firstPage.items[0]?.occurrenceCount).toBe(2);

    const assets = await store.listAssets("project-1", {
      search: "app.js",
      offset: 0,
      limit: 50,
    });
    expect(assets.total).toBe(1);

    await store.updateCandidate(
      "project-1",
      firstPage.items[0]!.id,
      "REVIEWING",
      "WSTG-ATHZ-04",
      "reviewed",
    );
    await store.updateTest(
      "project-1",
      "WSTG-ATHZ-04",
      "IN_PROGRESS",
      "testing",
    );
    const overview = await store.overview("project-1");
    expect(overview.summary).toMatchObject({
      candidateTotal: 2,
      newCandidateCount: 1,
      assetTotal: 1,
      testedCount: 1,
    });

    const reloaded = new WstgStore();
    await reloaded.initialize(sdk(database));
    expect(await reloaded.candidates("project-1")).toHaveLength(2);
    expect(
      raw
        .prepare("SELECT version FROM wstg_schema WHERE key = ?")
        .get("wstg-flow"),
    ).toMatchObject({ version: 2 });
    raw.close();
  });

  it("persists normalized settings and completes a confirmed finding", async () => {
    const raw = new DatabaseSync(":memory:");
    const database = asyncDatabase(raw);
    const store = new WstgStore();
    await store.initialize(sdk(database));
    const settings = await store.saveSettings({
      analysisEnabled: true,
      scopeOnly: true,
      autoHistory: false,
      maxHistoryEntries: 1,
      maxCandidates: 99_999,
      maxRequestBytes: 1,
      maxResponseBytes: Number.NaN,
      ignoredHosts: [" EXAMPLE.TEST ", "example.test"],
    });
    expect(settings).toMatchObject({
      maxHistoryEntries: 100,
      maxCandidates: 20_000,
      maxRequestBytes: 16_384,
      maxResponseBytes: 16_384,
      ignoredHosts: ["example.test"],
    });
    expect(await store.getSettings()).toEqual(settings);

    await store.addAnalysis(
      "project-1",
      [candidate("one", "High", "https://example.test/admin?id=1")],
      [],
      10,
    );
    const source = (await store.candidates("project-1"))[0]!;
    await store.attachEvidence(
      "project-1",
      source.id,
      "request-a",
      "BASELINE",
      undefined,
    );
    await store.clearEvidence("project-1", source.id);
    const draft = await store.prepareFinding("project-1", source);
    await store.completePublishedFinding("project-1", source, draft);
    const findings = await store.listFindings("project-1", {
      offset: 0,
      limit: 50,
    });
    expect(findings.items[0]).toMatchObject({
      id: draft.id,
      confidence: "Confirmed",
      published: true,
    });
    expect((await store.getCandidate("project-1", source.id))?.status).toBe(
      "CONFIRMED",
    );
    raw.close();
  });

  it("keeps the project candidate limit across concurrent analysis", async () => {
    const raw = new DatabaseSync(":memory:");
    const store = new WstgStore();
    await store.initialize(sdk(asyncDatabase(raw)));

    await Promise.all([
      store.addAnalysis(
        "project-1",
        [candidate("one", "High", "https://example.test/one?id=1")],
        [],
        1,
      ),
      store.addAnalysis(
        "project-1",
        [candidate("two", "High", "https://example.test/two?id=2")],
        [],
        1,
      ),
    ]);

    expect(await store.candidates("project-1")).toHaveLength(1);
    raw.close();
  });
});

function candidate(
  suffix: string,
  severity: DetectedCandidate["severity"],
  url: string,
): DetectedCandidate {
  return {
    requestId: `request-${suffix}`,
    responseId: `response-${suffix}`,
    ruleId: `rule.${suffix}`,
    title: `Candidate ${suffix}`,
    category: "Authorization",
    severity,
    confidence: "Tentative",
    url,
    method: "GET",
    statusCode: 200,
    wstgId: "WSTG-ATHZ-04",
    parameter: "id",
    location: "QUERY",
    evidence: "id=[REDACTED]",
    explanation: "Review manually",
    recommendedTest: "Use two accounts",
    payloads: ["2"],
  };
}

function sdk(database: Database): SDK {
  return {
    meta: { db: () => Promise.resolve(database) },
  } as unknown as SDK;
}

function asyncDatabase(raw: DatabaseSync): Database {
  return {
    exec: (sql: string) => Promise.resolve(raw.exec(sql)),
    prepare: (sql: string) => {
      const statement = raw.prepare(sql);
      return Promise.resolve({
        all: <T extends object = object>(...parameters: Parameter[]) =>
          Promise.resolve(statement.all(...parameters) as T[]),
        get: <T extends object = object>(...parameters: Parameter[]) =>
          Promise.resolve(statement.get(...parameters) as T | undefined),
        run: (...parameters: Parameter[]) => {
          const result = statement.run(...parameters);
          return Promise.resolve({
            changes: Number(result.changes),
            lastInsertRowid: Number(result.lastInsertRowid),
          });
        },
      });
    },
  };
}

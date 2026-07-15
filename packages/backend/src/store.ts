import { createHash } from "crypto";

import type { SDK } from "caido:plugin";
import type { Database, Parameter } from "sqlite";

import { validWstgId, WSTG_CATALOG } from "./catalog";
import type {
  AssetDTO,
  AssetQuery,
  CandidateDTO,
  CandidateQuery,
  CandidateStatus,
  CheckStatus,
  ComparisonDTO,
  Confidence,
  DetectedCandidate,
  FindingDTO,
  FindingQuery,
  Page,
  ParameterLocation,
  ProjectSummary,
  Severity,
  WstgSettings,
  WstgTestDTO,
} from "./types";

const DEFAULT_SETTINGS: WstgSettings = {
  analysisEnabled: true,
  scopeOnly: true,
  autoHistory: true,
  maxHistoryEntries: 5_000,
  maxCandidates: 3_000,
  maxRequestBytes: 1024 * 1024,
  maxResponseBytes: 5 * 1024 * 1024,
  ignoredHosts: [],
};

type CandidateRow = {
  project_id: string;
  id: string;
  fingerprint: string;
  request_id: string;
  response_id: string;
  created_at: string;
  last_seen: string;
  occurrence_count: number;
  rule_id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  url: string;
  method: string;
  status_code: number;
  wstg_id: string;
  parameter_name: string;
  parameter_location: ParameterLocation;
  evidence: string;
  explanation: string;
  recommended_test: string;
  payloads_json: string;
  status: CandidateStatus;
  decision_notes: string;
  confirmed_finding_id?: string;
  baseline_request_id?: string;
  variant_request_id?: string;
  comparison_json: string;
  published: number;
};

type FindingRow = {
  project_id: string;
  id: string;
  candidate_id?: string;
  created_at: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  url: string;
  method: string;
  status_code: number;
  wstg_id: string;
  comment: string;
  evidence: string;
  remediation: string;
  request_id?: string;
  published: number;
};

type AssetRow = {
  project_id: string;
  id: string;
  url: string;
  source_url: string;
  kind: string;
  discovered_at: string;
};

type ProgressRow = {
  wstg_id: string;
  status: CheckStatus;
  notes: string;
};

export class WstgStore {
  private database?: Database;

  async initialize(sdk: SDK): Promise<void> {
    if (this.database !== undefined) return;
    this.database = await sdk.meta.db();
    await this.database.exec(`
      CREATE TABLE IF NOT EXISTS wstg_candidates (
        project_id TEXT NOT NULL,
        id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        request_id TEXT NOT NULL,
        response_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        occurrence_count INTEGER NOT NULL DEFAULT 1,
        rule_id TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        url TEXT NOT NULL,
        method TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        wstg_id TEXT NOT NULL,
        parameter_name TEXT NOT NULL,
        parameter_location TEXT NOT NULL,
        evidence TEXT NOT NULL,
        explanation TEXT NOT NULL,
        recommended_test TEXT NOT NULL,
        payloads_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'NEW',
        decision_notes TEXT NOT NULL DEFAULT '',
        confirmed_finding_id TEXT,
        baseline_request_id TEXT,
        variant_request_id TEXT,
        comparison_json TEXT NOT NULL DEFAULT '',
        published INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(project_id, id),
        UNIQUE(project_id, fingerprint)
      );
      CREATE INDEX IF NOT EXISTS wstg_candidates_status ON wstg_candidates(project_id, status, last_seen);
      CREATE TABLE IF NOT EXISTS wstg_findings (
        project_id TEXT NOT NULL,
        id TEXT NOT NULL,
        candidate_id TEXT,
        created_at TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        url TEXT NOT NULL,
        method TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        wstg_id TEXT NOT NULL,
        comment TEXT NOT NULL,
        evidence TEXT NOT NULL,
        remediation TEXT NOT NULL,
        request_id TEXT,
        published INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(project_id, id)
      );
      CREATE INDEX IF NOT EXISTS wstg_findings_created ON wstg_findings(project_id, created_at);
      CREATE TABLE IF NOT EXISTS wstg_assets (
        project_id TEXT NOT NULL,
        id TEXT NOT NULL,
        url TEXT NOT NULL,
        source_url TEXT NOT NULL,
        kind TEXT NOT NULL,
        discovered_at TEXT NOT NULL,
        PRIMARY KEY(project_id, id)
      );
      CREATE TABLE IF NOT EXISTS wstg_progress (
        project_id TEXT NOT NULL,
        wstg_id TEXT NOT NULL,
        status TEXT NOT NULL,
        notes TEXT NOT NULL,
        PRIMARY KEY(project_id, wstg_id)
      );
      CREATE TABLE IF NOT EXISTS wstg_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS wstg_schema (
        key TEXT PRIMARY KEY,
        version INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS wstg_candidates_filter
        ON wstg_candidates(project_id, status, severity, last_seen DESC);
      CREATE INDEX IF NOT EXISTS wstg_assets_discovered
        ON wstg_assets(project_id, discovered_at DESC);
      INSERT OR IGNORE INTO wstg_schema(key, version) VALUES('wstg-flow', 2);
      UPDATE wstg_schema SET version = 2 WHERE key = 'wstg-flow' AND version < 2;
    `);
  }

  async getSettings(): Promise<WstgSettings> {
    const row = await this.requireDatabase()
      .prepare("SELECT value FROM wstg_settings WHERE key = ?")
      .then((statement) => statement.get<{ value: string }>("wstg-flow"));
    if (row === undefined) return cloneSettings(DEFAULT_SETTINGS);
    try {
      return normalizeSettings({
        ...DEFAULT_SETTINGS,
        ...(JSON.parse(row.value) as Partial<WstgSettings>),
      });
    } catch {
      return cloneSettings(DEFAULT_SETTINGS);
    }
  }

  async saveSettings(value: WstgSettings): Promise<WstgSettings> {
    const settings = normalizeSettings(value);
    const statement = await this.requireDatabase().prepare(
      "INSERT INTO wstg_settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    );
    await statement.run("wstg-flow", JSON.stringify(settings));
    return settings;
  }

  async tests(projectId: string): Promise<WstgTestDTO[]> {
    const progress = await this.requireDatabase()
      .prepare("SELECT * FROM wstg_progress WHERE project_id = ?")
      .then((statement) => statement.all<ProgressRow>(projectId));
    const progressById = new Map(
      progress.map((value) => [value.wstg_id, value]),
    );
    const counts = await this.requireDatabase()
      .prepare(
        "SELECT wstg_id, COUNT(*) AS count FROM wstg_candidates WHERE project_id = ? AND status != 'REJECTED' GROUP BY wstg_id",
      )
      .then((statement) =>
        statement.all<{ wstg_id: string; count: number }>(projectId),
      );
    const countById = new Map(
      counts.map((value) => [value.wstg_id, value.count]),
    );
    return WSTG_CATALOG.map((test) => ({
      ...test,
      status: progressById.get(test.id)?.status ?? "NOT_TESTED",
      notes: progressById.get(test.id)?.notes ?? "",
      candidateCount: countById.get(test.id) ?? 0,
    }));
  }

  async candidates(projectId: string): Promise<CandidateDTO[]> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM wstg_candidates WHERE project_id = ? ORDER BY last_seen DESC",
    );
    return (await statement.all<CandidateRow>(projectId)).map(toCandidate);
  }

  async overview(projectId: string): Promise<{
    tests: WstgTestDTO[];
    recentCandidates: CandidateDTO[];
    summary: ProjectSummary;
  }> {
    const database = this.requireDatabase();
    const [tests, recentRows, candidateCounts, findingCount, assetCount] =
      await Promise.all([
        this.tests(projectId),
        database
          .prepare(
            "SELECT * FROM wstg_candidates WHERE project_id = ? ORDER BY last_seen DESC LIMIT 12",
          )
          .then((statement) => statement.all<CandidateRow>(projectId)),
        database
          .prepare(
            `
            SELECT COUNT(*) AS total,
              COALESCE(SUM(CASE WHEN status = 'NEW' THEN 1 ELSE 0 END), 0) AS new_count
            FROM wstg_candidates WHERE project_id = ?
          `,
          )
          .then((statement) =>
            statement.get<{ total: number; new_count: number }>(projectId),
          ),
        database
          .prepare(
            "SELECT COUNT(*) AS count FROM wstg_findings WHERE project_id = ?",
          )
          .then((statement) => statement.get<{ count: number }>(projectId)),
        database
          .prepare(
            "SELECT COUNT(*) AS count FROM wstg_assets WHERE project_id = ?",
          )
          .then((statement) => statement.get<{ count: number }>(projectId)),
      ]);
    return {
      tests,
      recentCandidates: recentRows.map(toCandidate),
      summary: {
        candidateTotal: candidateCounts?.total ?? 0,
        newCandidateCount: candidateCounts?.new_count ?? 0,
        findingTotal: findingCount?.count ?? 0,
        assetTotal: assetCount?.count ?? 0,
        testedCount: tests.filter((test) => test.status !== "NOT_TESTED")
          .length,
        passCount: tests.filter((test) => test.status === "PASS").length,
        failCount: tests.filter((test) => test.status === "FAIL").length,
      },
    };
  }

  async listCandidates(
    projectId: string,
    value: CandidateQuery,
  ): Promise<Page<CandidateDTO>> {
    const query = normalizeCandidateQuery(value);
    const where = ["project_id = ?"];
    const parameters: Parameter[] = [projectId];
    if (query.status !== "ALL") {
      where.push("status = ?");
      parameters.push(query.status);
    }
    if (query.severity !== "ALL") {
      where.push("severity = ?");
      parameters.push(query.severity);
    }
    if (query.search !== "") {
      where.push(`instr(lower(
        title || ' ' || rule_id || ' ' || url || ' ' || parameter_name || ' ' || category || ' ' || wstg_id
      ), ?) > 0`);
      parameters.push(query.search);
    }
    const clause = where.join(" AND ");
    const database = this.requireDatabase();
    const [rows, count] = await Promise.all([
      database
        .prepare(
          `SELECT * FROM wstg_candidates WHERE ${clause} ORDER BY last_seen DESC LIMIT ? OFFSET ?`,
        )
        .then((statement) =>
          statement.all<CandidateRow>(...parameters, query.limit, query.offset),
        ),
      database
        .prepare(
          `SELECT COUNT(*) AS count FROM wstg_candidates WHERE ${clause}`,
        )
        .then((statement) => statement.get<{ count: number }>(...parameters)),
    ]);
    return {
      items: rows.map(toCandidate),
      total: count?.count ?? 0,
      offset: query.offset,
      limit: query.limit,
    };
  }

  async listAssets(
    projectId: string,
    value: AssetQuery,
  ): Promise<Page<AssetDTO>> {
    const query = normalizeAssetQuery(value);
    const searchClause =
      query.search === ""
        ? ""
        : " AND instr(lower(kind || ' ' || url || ' ' || source_url), ?) > 0";
    const parameters: Parameter[] =
      query.search === "" ? [projectId] : [projectId, query.search];
    const database = this.requireDatabase();
    const [rows, count] = await Promise.all([
      database
        .prepare(
          `SELECT * FROM wstg_assets WHERE project_id = ?${searchClause} ORDER BY discovered_at DESC LIMIT ? OFFSET ?`,
        )
        .then((statement) =>
          statement.all<AssetRow>(...parameters, query.limit, query.offset),
        ),
      database
        .prepare(
          `SELECT COUNT(*) AS count FROM wstg_assets WHERE project_id = ?${searchClause}`,
        )
        .then((statement) => statement.get<{ count: number }>(...parameters)),
    ]);
    return {
      items: rows.map(toAsset),
      total: count?.count ?? 0,
      offset: query.offset,
      limit: query.limit,
    };
  }

  async listFindings(
    projectId: string,
    value: FindingQuery,
  ): Promise<Page<FindingDTO>> {
    const query = normalizePageQuery(value);
    const database = this.requireDatabase();
    const [rows, count] = await Promise.all([
      database
        .prepare(
          "SELECT * FROM wstg_findings WHERE project_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )
        .then((statement) =>
          statement.all<FindingRow>(projectId, query.limit, query.offset),
        ),
      database
        .prepare(
          "SELECT COUNT(*) AS count FROM wstg_findings WHERE project_id = ?",
        )
        .then((statement) => statement.get<{ count: number }>(projectId)),
    ]);
    return {
      items: rows.map(toFinding),
      total: count?.count ?? 0,
      offset: query.offset,
      limit: query.limit,
    };
  }

  async findings(projectId: string): Promise<FindingDTO[]> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM wstg_findings WHERE project_id = ? ORDER BY created_at DESC",
    );
    return (await statement.all<FindingRow>(projectId)).map(toFinding);
  }

  async assets(projectId: string): Promise<AssetDTO[]> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM wstg_assets WHERE project_id = ? ORDER BY discovered_at DESC",
    );
    return (await statement.all<AssetRow>(projectId)).map(toAsset);
  }

  async getCandidate(
    projectId: string,
    id: string,
  ): Promise<CandidateDTO | undefined> {
    const row = await this.requireDatabase()
      .prepare("SELECT * FROM wstg_candidates WHERE project_id = ? AND id = ?")
      .then((statement) => statement.get<CandidateRow>(projectId, id));
    return row === undefined ? undefined : toCandidate(row);
  }

  async addAnalysis(
    projectId: string,
    candidates: DetectedCandidate[],
    assets: Array<{ url: string; sourceUrl: string; kind: string }>,
    maximumCandidates: number,
  ): Promise<number> {
    let added = 0;
    const database = this.requireDatabase();
    const existingStatement = await database.prepare(
      "SELECT id FROM wstg_candidates WHERE project_id = ? AND fingerprint = ?",
    );
    const insert = await database.prepare(`
      INSERT OR IGNORE INTO wstg_candidates(
        project_id, id, fingerprint, request_id, response_id, created_at, last_seen,
        rule_id, title, category, severity, confidence, url, method, status_code,
        wstg_id, parameter_name, parameter_location, evidence, explanation,
        recommended_test, payloads_json
      ) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE (
          SELECT COUNT(*) FROM wstg_candidates WHERE project_id = ?
        ) < ?
    `);
    const update = await database.prepare(`
      UPDATE wstg_candidates SET request_id = ?, response_id = ?, last_seen = ?,
        occurrence_count = occurrence_count + 1, status_code = ?, evidence = ?
      WHERE project_id = ? AND fingerprint = ?
    `);
    for (const candidate of candidates) {
      const fingerprint = candidateFingerprint(candidate);
      const existing = await existingStatement.get<{ id: string }>(
        projectId,
        fingerprint,
      );
      const now = new Date().toISOString();
      if (existing === undefined) {
        const id = sha256(`${projectId}\n${fingerprint}`).slice(0, 24);
        const result = await insert.run(
          projectId,
          id,
          fingerprint,
          candidate.requestId,
          candidate.responseId,
          now,
          now,
          candidate.ruleId,
          candidate.title,
          candidate.category,
          candidate.severity,
          candidate.confidence,
          candidate.url,
          candidate.method,
          candidate.statusCode,
          candidate.wstgId,
          candidate.parameter,
          candidate.location,
          candidate.evidence,
          candidate.explanation,
          candidate.recommendedTest,
          JSON.stringify(candidate.payloads),
          projectId,
          maximumCandidates,
        );
        if (result.changes === 0) {
          await update.run(
            candidate.requestId,
            candidate.responseId,
            now,
            candidate.statusCode,
            candidate.evidence,
            projectId,
            fingerprint,
          );
        } else {
          added += 1;
        }
      } else {
        await update.run(
          candidate.requestId,
          candidate.responseId,
          now,
          candidate.statusCode,
          candidate.evidence,
          projectId,
          fingerprint,
        );
      }
    }
    const assetStatement = await database.prepare(`
      INSERT OR IGNORE INTO wstg_assets(project_id, id, url, source_url, kind, discovered_at)
      VALUES(?, ?, ?, ?, ?, ?)
    `);
    for (const asset of assets) {
      const id = sha256(`${asset.kind}\n${asset.url}`).slice(0, 24);
      await assetStatement.run(
        projectId,
        id,
        clip(asset.url, 4_000),
        clip(asset.sourceUrl, 4_000),
        clip(asset.kind, 100),
        new Date().toISOString(),
      );
    }
    return added;
  }

  async updateCandidate(
    projectId: string,
    id: string,
    status: CandidateStatus,
    wstgId: string,
    notes: string,
  ): Promise<void> {
    if (!validWstgId(wstgId)) throw new Error("Unknown WSTG test ID");
    if (status === "CONFIRMED")
      throw new Error("Use Confirm finding to create a confirmed result");
    const statement = await this.requireDatabase().prepare(`
      UPDATE wstg_candidates SET status = ?, wstg_id = ?, decision_notes = ?
      WHERE project_id = ? AND id = ?
    `);
    await statement.run(
      status,
      wstgId,
      clip(notes.trim(), 8_000),
      projectId,
      id,
    );
  }

  async attachEvidence(
    projectId: string,
    candidateId: string,
    requestId: string,
    slot: "BASELINE" | "VARIANT",
    comparison: ComparisonDTO | undefined,
  ): Promise<void> {
    const column =
      slot === "BASELINE" ? "baseline_request_id" : "variant_request_id";
    const statement = await this.requireDatabase().prepare(`
      UPDATE wstg_candidates SET ${column} = ?, comparison_json = ?,
        status = CASE WHEN status = 'NEW' THEN 'REVIEWING' ELSE status END
      WHERE project_id = ? AND id = ?
    `);
    await statement.run(
      requestId,
      comparison === undefined ? "" : JSON.stringify(comparison),
      projectId,
      candidateId,
    );
  }

  async clearEvidence(projectId: string, candidateId: string): Promise<void> {
    const statement = await this.requireDatabase().prepare(`
      UPDATE wstg_candidates SET baseline_request_id = '', variant_request_id = '', comparison_json = ''
      WHERE project_id = ? AND id = ?
    `);
    await statement.run(projectId, candidateId);
  }

  async updateTest(
    projectId: string,
    wstgId: string,
    status: CheckStatus,
    notes: string,
  ): Promise<void> {
    if (!validWstgId(wstgId) || wstgId === "")
      throw new Error("Unknown WSTG test ID");
    const statement = await this.requireDatabase().prepare(`
      INSERT INTO wstg_progress(project_id, wstg_id, status, notes) VALUES(?, ?, ?, ?)
      ON CONFLICT(project_id, wstg_id) DO UPDATE SET status = excluded.status, notes = excluded.notes
    `);
    await statement.run(projectId, wstgId, status, clip(notes.trim(), 10_000));
  }

  async prepareFinding(
    projectId: string,
    candidate: CandidateDTO,
  ): Promise<FindingDTO> {
    if (
      candidate.status === "CONFIRMED" &&
      candidate.confirmedFindingId !== undefined
    ) {
      const findingId = candidate.confirmedFindingId;
      const existing = await this.requireDatabase()
        .prepare("SELECT * FROM wstg_findings WHERE project_id = ? AND id = ?")
        .then((statement) => statement.get<FindingRow>(projectId, findingId));
      if (existing !== undefined) return toFinding(existing);
    }
    const id = sha256(`${projectId}\n${candidate.id}\nconfirmed`).slice(0, 24);
    const comparison = candidate.comparison?.summary ?? "";
    const finding: FindingDTO = {
      projectId,
      id,
      candidateId: candidate.id,
      createdAt: new Date().toISOString(),
      title: candidate.title,
      severity: candidate.severity,
      confidence: "Confirmed",
      url: candidate.url,
      method: candidate.method,
      statusCode: candidate.statusCode,
      wstgId: candidate.wstgId,
      comment: `${candidate.explanation}${candidate.decisionNotes === "" ? "" : `\n\nReviewer: ${candidate.decisionNotes}`}`,
      evidence: `${candidate.evidence}${comparison === "" ? "" : `\n\nVerification comparison:\n${comparison}`}`,
      remediation: "",
      requestId: candidate.variantRequestId ?? candidate.requestId,
      published: false,
    };
    return finding;
  }

  async completePublishedFinding(
    projectId: string,
    candidate: CandidateDTO,
    finding: FindingDTO,
  ): Promise<void> {
    const insert = await this.requireDatabase().prepare(`
      INSERT OR REPLACE INTO wstg_findings(
        project_id, id, candidate_id, created_at, title, severity, confidence, url,
        method, status_code, wstg_id, comment, evidence, remediation, request_id, published
      ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    await insert.run(
      finding.projectId,
      finding.id,
      finding.candidateId ?? "",
      finding.createdAt,
      finding.title,
      finding.severity,
      finding.confidence,
      finding.url,
      finding.method,
      finding.statusCode,
      finding.wstgId,
      finding.comment,
      finding.evidence,
      finding.remediation,
      finding.requestId ?? "",
      1,
    );
    await this.requireDatabase()
      .prepare(
        "UPDATE wstg_candidates SET status = 'CONFIRMED', confirmed_finding_id = ?, published = 1 WHERE project_id = ? AND id = ?",
      )
      .then((statement) => statement.run(finding.id, projectId, candidate.id));
    if (candidate.wstgId !== "")
      await this.updateTest(
        projectId,
        candidate.wstgId,
        "FAIL",
        "Confirmed finding recorded by WSTG Flow.",
      );
  }

  async clearUnconfirmed(projectId: string): Promise<void> {
    await this.requireDatabase()
      .prepare(
        "DELETE FROM wstg_candidates WHERE project_id = ? AND status != 'CONFIRMED'",
      )
      .then((statement) => statement.run(projectId));
  }

  private requireDatabase(): Database {
    if (this.database === undefined)
      throw new Error("WSTG Flow database is not initialized");
    return this.database;
  }
}

function toCandidate(row: CandidateRow): CandidateDTO {
  return {
    projectId: row.project_id,
    id: row.id,
    fingerprint: row.fingerprint,
    requestId: row.request_id,
    responseId: row.response_id,
    createdAt: row.created_at,
    lastSeen: row.last_seen,
    occurrenceCount: row.occurrence_count,
    ruleId: row.rule_id,
    title: row.title,
    category: row.category,
    severity: row.severity,
    confidence: row.confidence,
    url: row.url,
    method: row.method,
    statusCode: row.status_code,
    wstgId: row.wstg_id,
    parameter: row.parameter_name,
    location: row.parameter_location,
    evidence: row.evidence,
    explanation: row.explanation,
    recommendedTest: row.recommended_test,
    payloads: parseStringArray(row.payloads_json),
    status: row.status,
    decisionNotes: row.decision_notes,
    confirmedFindingId: present(row.confirmed_finding_id),
    baselineRequestId: present(row.baseline_request_id),
    variantRequestId: present(row.variant_request_id),
    comparison: parseComparison(row.comparison_json),
    published: row.published === 1,
  };
}

function toFinding(row: FindingRow): FindingDTO {
  return {
    projectId: row.project_id,
    id: row.id,
    candidateId: present(row.candidate_id),
    createdAt: row.created_at,
    title: row.title,
    severity: row.severity,
    confidence: row.confidence,
    url: row.url,
    method: row.method,
    statusCode: row.status_code,
    wstgId: row.wstg_id,
    comment: row.comment,
    evidence: row.evidence,
    remediation: row.remediation,
    requestId: present(row.request_id),
    published: row.published === 1,
  };
}

function toAsset(row: AssetRow): AssetDTO {
  return {
    projectId: row.project_id,
    id: row.id,
    url: row.url,
    sourceUrl: row.source_url,
    kind: row.kind,
    discoveredAt: row.discovered_at,
  };
}

function candidateFingerprint(candidate: DetectedCandidate): string {
  const url = candidate.url.replace(/[?#].*$/, "");
  const hostScoped =
    candidate.ruleId.startsWith("header.") ||
    candidate.ruleId.startsWith("cookie.");
  return sha256(
    [
      candidate.ruleId,
      hostScoped ? "" : candidate.method,
      hostScoped ? origin(url) : url,
      candidate.parameter.toLowerCase(),
      candidate.location,
    ].join("|"),
  );
}

function origin(value: string): string {
  try {
    return new URL(value).origin;
  } catch {
    return value;
  }
}

function normalizeSettings(value: WstgSettings): WstgSettings {
  return {
    analysisEnabled: value.analysisEnabled === true,
    scopeOnly: value.scopeOnly === true,
    autoHistory: value.autoHistory === true,
    maxHistoryEntries: bounded(value.maxHistoryEntries, 100, 50_000),
    maxCandidates: bounded(value.maxCandidates, 100, 20_000),
    maxRequestBytes: bounded(value.maxRequestBytes, 16_384, 10 * 1024 * 1024),
    maxResponseBytes: bounded(value.maxResponseBytes, 16_384, 20 * 1024 * 1024),
    ignoredHosts: [
      ...new Set(
        value.ignoredHosts
          .map((host) => host.trim().toLowerCase())
          .filter(Boolean),
      ),
    ].slice(0, 500),
  };
}

function cloneSettings(value: WstgSettings): WstgSettings {
  return { ...value, ignoredHosts: [...value.ignoredHosts] };
}

function bounded(value: number, minimum: number, maximum: number): number {
  return Number.isFinite(value)
    ? Math.max(minimum, Math.min(Math.round(value), maximum))
    : minimum;
}

export function normalizeCandidateQuery(value: CandidateQuery): CandidateQuery {
  return {
    search: clip(value.search.trim().toLowerCase(), 200),
    status: isCandidateStatus(value.status) ? value.status : "ALL",
    severity: isSeverity(value.severity) ? value.severity : "ALL",
    ...normalizePageQuery(value),
  };
}

export function normalizeAssetQuery(value: AssetQuery): AssetQuery {
  return {
    search: clip(value.search.trim().toLowerCase(), 200),
    ...normalizePageQuery(value),
  };
}

export function normalizePageQuery(value: { offset: number; limit: number }): {
  offset: number;
  limit: number;
} {
  return {
    offset: bounded(value.offset, 0, 1_000_000),
    limit: bounded(value.limit, 1, 100),
  };
}

function isCandidateStatus(
  value: CandidateQuery["status"],
): value is CandidateQuery["status"] {
  return ["ALL", "NEW", "REVIEWING", "CONFIRMED", "REJECTED"].includes(value);
}

function isSeverity(
  value: CandidateQuery["severity"],
): value is CandidateQuery["severity"] {
  return ["ALL", "Critical", "High", "Medium", "Low", "Information"].includes(
    value,
  );
}

function parseStringArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed)
      ? parsed.filter((item): item is string => typeof item === "string")
      : [];
  } catch {
    return [];
  }
}

function parseComparison(value: string): ComparisonDTO | undefined {
  if (value === "") return undefined;
  try {
    return JSON.parse(value) as ComparisonDTO;
  } catch {
    return undefined;
  }
}

function present(value: string | undefined): string | undefined {
  return value === undefined || value === "" ? undefined : value;
}

function clip(value: string, maximum: number): string {
  return value.length <= maximum ? value : `${value.slice(0, maximum)}…`;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

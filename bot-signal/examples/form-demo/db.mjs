import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const file = process.env.DB_FILE ?? join(here, "submissions.db");

const db = new DatabaseSync(file);

db.exec(`
  CREATE TABLE IF NOT EXISTS submissions (
    id TEXT PRIMARY KEY,
    received_at TEXT NOT NULL,
    verdict TEXT NOT NULL,
    score REAL NOT NULL,
    automation_kind TEXT,
    name TEXT,
    email TEXT,
    company TEXT,
    message TEXT,
    ip TEXT,
    country TEXT,
    user_agent TEXT,
    timezone TEXT,
    instant_score REAL,
    behavioral_score REAL,
    server_score REAL,
    record TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS submissions_received_at ON submissions (received_at DESC);
`);

const insertStatement = db.prepare(`
  INSERT INTO submissions (
    id, received_at, verdict, score, automation_kind,
    name, email, company, message,
    ip, country, user_agent, timezone,
    instant_score, behavioral_score, server_score, record
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const listStatement = db.prepare(
  "SELECT record FROM submissions ORDER BY received_at DESC, rowid DESC LIMIT ?",
);

const statsStatement = db.prepare(
  "SELECT verdict, COUNT(*) AS count FROM submissions GROUP BY verdict",
);

export function insertSubmission(record) {
  insertStatement.run(
    record.id,
    record.receivedAt,
    record.verdict,
    record.score,
    record.automationKind,
    record.form.name,
    record.form.email,
    record.form.company,
    record.form.message,
    record.ip,
    record.country,
    record.userAgent,
    record.timezone,
    record.layers.instant?.score ?? null,
    record.layers.behavioral?.score ?? null,
    record.layers.server.score,
    JSON.stringify(record),
  );
}

export function listSubmissions(limit = 200) {
  return listStatement.all(limit).map((row) => JSON.parse(row.record));
}

export function countByVerdict() {
  const counts = { human: 0, agent: 0 };
  for (const row of statsStatement.all()) counts[row.verdict] = Number(row.count);
  return { total: counts.human + counts.agent, humans: counts.human, agents: counts.agent };
}

export function clearSubmissions() {
  db.exec("DELETE FROM submissions");
}

export const dbFile = file;

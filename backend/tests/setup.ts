import { beforeEach, afterEach } from 'vitest';
import { getDb, runMigrations, destroyDb } from '../src/db/index.js';

/**
 * Global test lifecycle: ensure schema is migrated and clear all rows before
 * each test so tests are isolated and repeatable against PostgreSQL.
 */
beforeEach(async () => {
  await runMigrations();
});

afterEach(async () => {
  const db = getDb();
  for (const table of [
    'scan_artifacts',
    'findings',
    'scans',
    'scan_schedules',
    'targets',
    'projects',
    'audit_logs',
    'cve_cache',
    'users',
  ]) {
    await db(table).del().catch(() => undefined);
  }
});

afterEach(async () => {
  await destroyDb();
});

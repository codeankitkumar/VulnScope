import path from 'node:path';
import { fileURLToPath } from 'node:url';
import knex, { type Knex } from 'knex';
import { config } from '../config/env.js';

let db: Knex | null = null;
const HERE = path.dirname(fileURLToPath(import.meta.url)); // .../db (src or dist)

function buildKnex(): Knex {
  return knex({
    client: 'pg',
    connection: {
      host: config.database.host,
      port: config.database.port,
      database: config.database.database,
      user: config.database.user,
      password: config.database.password,
      ssl: false,
    },
    pool: { min: 0, max: 10 },
  });
}

export function getDb(): Knex {
  if (!db) db = buildKnex();
  return db;
}

/** Run schema migrations. Path resolves relative to this module so it works
 * both under tsx (src) and the compiled dist output. */
export async function runMigrations(): Promise<void> {
  const migrationsDir = path.join(HERE, 'migrations');
  await getDb().migrate.latest({ directory: migrationsDir });
}

export async function destroyDb(): Promise<void> {
  if (db) {
    await db.destroy();
    db = null;
  }
}
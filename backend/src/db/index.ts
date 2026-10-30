import knex, { type Knex } from 'knex';
import { config } from '../config/env.js';

let db: Knex | null = null;

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

export async function runMigrations(migrationsDir = './src/db/migrations'): Promise<void> {
  await getDb().migrate.latest({ directory: migrationsDir });
}

export async function destroyDb(): Promise<void> {
  if (db) {
    await db.destroy();
    db = null;
  }
}

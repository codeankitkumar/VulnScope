import { runMigrations, destroyDb } from '../db/index.js';

async function main(): Promise<void> {
  try {
    await runMigrations();
    console.log('Migrations applied');
  } catch (err) {
    console.error('Migration failed:', err);
    process.exitCode = 1;
  } finally {
    await destroyDb();
  }
}

void main();
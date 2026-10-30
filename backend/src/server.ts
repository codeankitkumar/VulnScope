import { createApp } from './app.js';
import { config } from './config/env.js';
import { runMigrations, destroyDb } from './db/index.js';
import { startScheduler } from './services/scheduler.js';

async function bootstrap(): Promise<void> {
  try {
    await runMigrations();
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  }

  const app = createApp();
  const server = app.listen(config.port, () => {
    console.log(`VulnScope backend listening on http://localhost:${config.port} (${config.env})`);
    console.log(`API docs: http://localhost:${config.port}/api/docs`);
  });

  if (config.env !== 'test') {
    startScheduler();
  }

  const shutdown = async (signal: string): Promise<void> => {
    console.log(`Received ${signal}, shutting down...`);
    server.close(async () => {
      await destroyDb();
      process.exit(0);
    });
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

void bootstrap();

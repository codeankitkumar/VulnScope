import { config } from './src/config/env.js';
import type { Knex } from 'knex';

const k: Knex.Config = {
  client: 'pg',
  connection: {
    host: config.database.host,
    port: config.database.port,
    database: config.database.database,
    user: config.database.user,
    password: config.database.password,
  },
  pool: { min: 0, max: 10 },
  migrations: { directory: './src/db/migrations', extension: 'ts' },
  seeds: { directory: './src/db/seeds', extension: 'ts' },
};

const knexfile: Record<string, Knex.Config> = {
  development: k,
  test: k,
  production: { ...k, migrations: { directory: './dist/db/migrations', extension: 'js' } },
  default: k,
};

export default knexfile;

import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

function num(value: string | undefined, fallback: number): number {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function bool(value: string | undefined, fallback = false): boolean {
  if (value === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}

export const config = {
  env: process.env.NODE_ENV ?? 'development',
  port: num(process.env.PORT, 4000),
  appOrigin: process.env.APP_ORIGIN ?? 'http://localhost:5173',
  logLevel: process.env.LOG_LEVEL ?? 'info',

  jwtSecret: process.env.JWT_SECRET ?? 'insecure-dev-secret',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN ?? '1d',
  bcryptRounds: num(process.env.BCRYPT_ROUNDS, 10),

  rateLimitWindowMs: num(process.env.RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
  rateLimitMax: num(process.env.RATE_LIMIT_MAX, 300),

  database: {
    host: process.env.PGHOST ?? '127.0.0.1',
    port: num(process.env.PGPORT, 5432),
    database: process.env.PGDATABASE ?? 'vulnscope',
    user: process.env.PGUSER ?? 'vulnscope',
    password: process.env.PGPASSWORD ?? 'vulnscope',
  },

  nvd: {
    apiKey: process.env.NVD_API_KEY,
    apiUrl: process.env.NVD_API_URL ?? 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    requestDelayMs: num(process.env.NVD_REQUEST_DELAY_MS, 1000),
  },

  zap: {
    baseUrl: process.env.ZAP_BASE_URL ?? 'http://zap:8090',
    apiKey: process.env.ZAP_API_KEY,
  },

  ai: {
    useExternalLLM: bool(process.env.USE_EXTERNAL_LLM, false),
    provider: process.env.LLM_PROVIDER ?? 'openai',
    openaiApiKey: process.env.OPENAI_API_KEY,
    openaiModel: process.env.OPENAI_MODEL ?? 'gpt-4o-mini',
  },

  isTest: process.env.NODE_ENV === 'test',
} as const;


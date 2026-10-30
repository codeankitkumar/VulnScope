import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    testTimeout: 30000,
    hookTimeout: 30000,
    fileParallelism: false,
    setupFiles: ['./tests/setup.ts'],
    env: {
      NODE_ENV: 'test',
      PGHOST: 'localhost',
      PGPORT: '5432',
      PGDATABASE: 'vulnscope_test',
      PGUSER: 'vulnscope',
      PGPASSWORD: 'vulnscope',
      JWT_SECRET: 'test-secret-do-not-use',
    },
  },
});

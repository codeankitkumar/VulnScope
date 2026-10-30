import express, { type Express } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { pinoHttp } from 'pino-http';
import { config } from './config/env.js';
import { globalLimiter } from './middleware/rateLimit.js';
import { notFound, errorHandler } from './middleware/errorHandler.js';
import authRoutes from './routes/auth.routes.js';
import usersRoutes from './routes/users.routes.js';
import projectsRoutes from './routes/projects.routes.js';
import targetsRoutes from './routes/targets.routes.js';
import scansRoutes from './routes/scans.routes.js';
import cveRoutes from './routes/cve.routes.js';
import aiRoutes from './routes/ai.routes.js';
import dashboardRoutes from './routes/dashboard.routes.js';
import reportsRoutes from './routes/reports.routes.js';
import auditRoutes from './routes/audit.routes.js';

const logger = pinoHttp({ enabled: config.env !== 'test', level: config.logLevel });

export function createApp(): Express {
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(
    cors({
      origin: config.appOrigin,
      credentials: true,
    }),
  );
  app.use(express.json({ limit: '1mb' }));
  app.use(logger);
  app.use('/api', globalLimiter);

  // Health + documentation
  app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'vulnscope-backend', time: new Date().toISOString() }));
  app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(buildSwagger()));

  // Feature routes
  app.use('/api/auth', authRoutes);
  app.use('/api/users', usersRoutes);
  app.use('/api/projects', projectsRoutes);
  app.use('/api/targets', targetsRoutes);
  app.use('/api/scans', scansRoutes);
  app.use('/api/cve', cveRoutes);
  app.use('/api/ai', aiRoutes);
  app.use('/api/dashboard', dashboardRoutes);
  app.use('/api/reports', reportsRoutes);
  app.use('/api/audit', auditRoutes);

  app.use(notFound);
  app.use(errorHandler);
  return app;
}

function buildSwagger() {
  const options = {
    definition: {
      openapi: '3.0.0',
      info: {
        title: 'VulnScope API',
        version: '0.1.0',
        description: 'AI-assisted vulnerability assessment platform. See docs/API.md for full reference.',
      },
      servers: [{ url: '/api' }],
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        },
      },
    },
    apis: ['./src/routes/*.ts'],
  };
  return swaggerJsdoc(options);
}

export default createApp;

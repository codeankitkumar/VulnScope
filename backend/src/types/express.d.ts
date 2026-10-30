import type { PublicUser, Role } from './index.js';

declare global {
  namespace Express {
    interface Request {
      user?: PublicUser;
    }
  }
}

declare module 'swagger-jsdoc';
declare module 'node-cron';

export {};

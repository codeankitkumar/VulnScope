import type { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { AppError } from '../utils/http.js';

export function notFound(_req: Request, res: Response): void {
  res.status(404).json({ error: 'Route not found' });
}

export function errorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  _next: NextFunction,
): void {
  if (err instanceof AppError) {
    res.status(err.status).json({ error: err.message, details: err.details });
    return;
  }
  if (err instanceof ZodError) {
    const details = err.issues.map((i) => ({ path: i.path.join('.'), message: i.message }));
    res.status(400).json({ error: 'Validation failed', details });
    return;
  }
  const message = err instanceof Error ? err.message : 'Internal server error';
  // Log server errors, but return a generic message in production.
  const safe = message;
  res.status(500).json({ error: 'Internal server error', message: safe });
}
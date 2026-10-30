import { randomUUID } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';

/** Create a NotFound/ApiError with an HTTP status code. */
export class AppError extends Error {
  status: number;
  details?: unknown;
  constructor(status: number, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

/** Wrap async route handlers so thrown errors reach the error middleware. */
export const asyncHandler =
  (fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>) =>
  (req: Request, res: Response, next: NextFunction): void => {
    fn(req, res, next).catch(next);
  };

/** Deterministic-looking, unique identifiers for all entities. */
export function newId(): string {
  return randomUUID();
}
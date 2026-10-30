import type { Request, Response, NextFunction } from 'express';
import { ZodTypeAny } from 'zod';
import { AppError } from '../utils/http.js';

type Source = 'body' | 'query' | 'params';

/** Validate a request section against a zod schema. */
export function validate(schema: ZodTypeAny, source: Source = 'body') {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const data = req[source];
    const result = schema.safeParse(data ?? {});
    if (!result.success) {
      const details = result.error.issues.map((i) => ({
        path: i.path.join('.'),
        message: i.message,
      }));
      throw new AppError(400, 'Validation failed', details);
    }
    // options.params is read-only; replace when needed
    if (source === 'params') {
      (req.params as Record<string, string>) = result.data as Record<string, string>;
    } else if (source === 'query') {
      (req.query as Record<string, unknown>) = result.data as Record<string, unknown>;
    } else {
      req.body = result.data;
    }
    next();
  };
}
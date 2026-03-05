import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';

export const securityMiddleware = [
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        scriptSrc: ["'none'"],
        styleSrc: ["'none'"],
        imgSrc: ["'none'"],
        connectSrc: ["'self'"],
        fontSrc: ["'none'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'none'"],
        frameSrc: ["'none'"]
      }
    },
    crossOriginEmbedderPolicy: false
  }),
  cors({
    origin: false,
    methods: ['POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false,
    maxAge: 86400
  })
];

export function rateLimiter(req: Request, res: Response, next: NextFunction): void {
  const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
  const currentTime = Date.now();
  
  if (!req.rateLimitStore) {
    req.rateLimitStore = new Map();
  }
  
  const store = req.rateLimitStore as Map<string, { count: number; resetTime: number }>;
  const record = store.get(clientIP);
  
  if (!record || currentTime > record.resetTime) {
    store.set(clientIP, { count: 1, resetTime: currentTime + 60000 });
    next();
    return;
  }
  
  if (record.count >= 10) {
    res.status(429).json({ error: 'Rate limit exceeded' });
    return;
  }
  
  record.count++;
  next();
}

declare global {
  namespace Express {
    interface Request {
      rateLimitStore?: Map<string, { count: number; resetTime: number }>;
    }
  }
}

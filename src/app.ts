import express from 'express';
import { securityMiddleware, rateLimiter } from './middleware/security';
import { handleDetection } from './routes/detect';
import { handleSimpleDetection } from './routes/simple';

const app = express();

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(securityMiddleware);
app.use(rateLimiter);

app.post('/dusk/archive/url=', handleDetection);
app.post('/check', handleSimpleDetection);

app.use((req: express.Request, res: express.Response) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

export default app;

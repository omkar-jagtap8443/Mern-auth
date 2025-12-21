import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import authRouter from '../Routes/authRoutes.js';
import { notFound, errorHandler } from './middlewares/error.js';

const app = express();

app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());
app.use(helmet());

const parseOrigins = () => {
  const raw = process.env.CORS_ORIGIN || '';
  const origins = raw.split(',').map((o) => o.trim()).filter(Boolean);
  return origins.length ? origins : true; // allow any during local dev
};

app.use(
  cors({
    origin: parseOrigins(),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-refresh-token']
  })
);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

app.get('/', (req, res) => res.send('API Working okay'));
app.use('/api/auth', authLimiter, authRouter);

app.use(notFound);
app.use(errorHandler);

export default app;

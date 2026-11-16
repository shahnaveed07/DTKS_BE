import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import workerApp from './backend/src/index.js';
import { createNodeWorkerEnv } from './backend/src/database/d1Adapter.js';
import { ensureDatabaseSeeded } from './backend/src/database/seed.js';

const PORT = Number(process.env.PORT || 3000);

async function startServer() {
  const app = express();
  app.disable('x-powered-by');

  const workerEnv = createNodeWorkerEnv({
    dbPath: path.resolve(process.cwd(), process.env.SQLITE_DB_PATH || 'data/dtks.sqlite'),
    r2Dir: path.resolve(process.cwd(), process.env.R2_STORAGE_DIR || 'data/r2-storage'),
    migrationsDir: path.resolve(process.cwd(), 'backend/migrations'),
  });

  // Ensure initial database schema & non-destructive catalog seed data are ready on startup
  await ensureDatabaseSeeded(workerEnv);

  // Root status endpoint for standalone backend service
  app.get('/', (_req, res) => {
    res.status(200).json({
      success: true,
      message: 'DTKS_BE — DreamTech Kashmir Solutions Standalone Backend API',
      data: {
        service: 'dtks-be',
        version: '1.0.0',
        apiBasePath: '/api/v1',
        healthEndpoint: '/api/v1/health',
        readinessEndpoint: '/api/v1/ready',
        bootstrapEndpoint: '/api/v1/bootstrap',
        frontendRepository: 'https://github.com/shahnaveed07/DTKS.git',
        productionWebsite: 'https://dreamtechkashmirsolutions.studio/',
      },
    });
  });

  // Mount Cloudflare Worker API router for all /api/* routes
  app.use(express.raw({ type: '*/*', limit: '6mb' }), async (req, res) => {
    try {
      const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
      const host = req.headers.host || `localhost:${PORT}`;
      const fullUrl = `${protocol}://${host}${req.originalUrl}`;

      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers)) {
        if (Array.isArray(value)) {
          headers.set(key, value.join(', '));
        } else if (typeof value === 'string') {
          headers.set(key, value);
        }
      }

      const method = req.method.toUpperCase();
      const hasBody = !['GET', 'HEAD', 'OPTIONS'].includes(method);
      const rawBody =
        hasBody && Buffer.isBuffer(req.body) && req.body.length > 0
          ? new Uint8Array(req.body)
          : undefined;

      const webRequest = new Request(fullUrl, {
        method,
        headers,
        body: rawBody,
      });

      const workerResponse = await workerApp.fetch(webRequest, workerEnv, {});

      res.status(workerResponse.status);
      const setCookies =
        typeof workerResponse.headers.getSetCookie === 'function'
          ? workerResponse.headers.getSetCookie()
          : [];
      workerResponse.headers.forEach((val, key) => {
        if (key.toLowerCase() !== 'set-cookie') {
          res.setHeader(key, val);
        }
      });
      if (setCookies.length > 0) {
        res.setHeader('Set-Cookie', setCookies);
      }

      const arrayBuffer = await workerResponse.arrayBuffer();
      res.send(Buffer.from(arrayBuffer));
    } catch (err) {
      console.error('[Server API Proxy Error]:', err);
      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Internal server error processing API request.',
        },
      });
    }
  });

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`DTKS_BE Standalone Backend Server (Cloudflare Worker + D1/R2 Adapter) running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start DTKS_BE server:', err);
  process.exit(1);
});

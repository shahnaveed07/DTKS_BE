import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import workerApp from './backend/src/index.js';
import { createNodeWorkerEnv } from './backend/src/database/d1Adapter.js';
import { ensureDatabaseSeeded } from './backend/src/database/seed.js';

const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';

async function startServer() {
  const app = express();
  app.disable('x-powered-by');

  const workerEnv = createNodeWorkerEnv({
    dbPath: path.resolve(process.cwd(), process.env.SQLITE_DB_PATH || 'data/dtks.sqlite'),
    r2Dir: path.resolve(process.cwd(), process.env.R2_STORAGE_DIR || 'data/r2-storage'),
    migrationsDir: path.resolve(process.cwd(), 'backend/migrations'),
  });

  // Ensure initial database schema & seed data are ready on startup
  await ensureDatabaseSeeded(workerEnv);

  // Mount Cloudflare Worker API router at /api/v1/*
  app.use('/api/v1', express.raw({ type: '*/*', limit: '6mb' }), async (req, res) => {
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
      workerResponse.headers.forEach((val, key) => {
        res.setHeader(key, val);
      });

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

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir, { index: false }));
    app.get('*', (req, res) => {
      const indexFile = path.join(distDir, 'index.html');
      if (fs.existsSync(indexFile)) {
        res.sendFile(indexFile);
      } else {
        res.status(404).send('Build output not found. Run npm run build first.');
      }
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`DTKS Full-Stack Server (Frontend + Worker D1/R2 API) running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start DTKS server:', err);
  process.exit(1);
});

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { createApiApp } from './src/server/apiRouter.js';
import { initPostgresSchema } from './src/lib/db.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = createApiApp();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  const isProduction = process.env.NODE_ENV === 'production';

  // Verify and initialize PostgreSQL database schema safely on boot
  initPostgresSchema().catch((err) => {
    console.warn('[DATABASE BOOTSTRAP NOTICE]:', err.message);
  });

  // Vite dev server or static dist serving
  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(
      `[IVENTUS SERVER] Rodando na porta ${PORT} (modo ${isProduction ? 'produção' : 'desenvolvimento'})`
    );
  });
}

startServer().catch((err) => {
  console.warn('[FATAL SERVER START ERROR]:', err);
});

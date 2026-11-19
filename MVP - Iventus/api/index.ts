import { createApiApp } from '../src/server/apiRouter.js';

const app = createApiApp();

export default function handler(req: any, res: any) {
  // Restore original /api/<route> path when routed via vercel.json rewrite (?__path=...)
  const rawUrl = String(req.url || '/api/health');
  const urlObj = new URL(rawUrl, 'http://localhost');
  const rewrittenPath = urlObj.searchParams.get('__path');

  if (rewrittenPath !== null) {
    urlObj.searchParams.delete('__path');
    if (req.query && typeof req.query === 'object') {
      delete req.query.__path;
    }
    const cleanSubpath = rewrittenPath.replace(/^\/+/, '');
    const remainingSearch = urlObj.searchParams.toString();
    req.url = `/api/${cleanSubpath}${remainingSearch ? `?${remainingSearch}` : ''}`;
  } else if (!rawUrl.startsWith('/api')) {
    req.url = `/api${rawUrl.startsWith('/') ? rawUrl : `/${rawUrl}`}`;
  }

  return app(req, res);
}

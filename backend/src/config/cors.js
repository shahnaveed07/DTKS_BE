/**
 * Strict CORS Configuration & Origin Allowlist
 */

const DEFAULT_ALLOWED_ORIGINS = [
  'https://dreamtechkashmirsolutions.studio',
  'https://www.dreamtechkashmirsolutions.studio',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:5173',
];

export function getAllowedOrigins(env = {}) {
  const custom = env.CORS_ALLOWED_ORIGINS
    ? String(env.CORS_ALLOWED_ORIGINS)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : [];
  const appUrl = env.APP_URL ? [String(env.APP_URL).trim().replace(/\/+$/, '')] : [];
  return Array.from(new Set([...DEFAULT_ALLOWED_ORIGINS, ...custom, ...appUrl]));
}

export function isOriginAllowed(origin, env = {}) {
  if (!origin) return true; // Same-origin or server-to-server request
  const normalized = String(origin).trim().replace(/\/+$/, '');
  const allowlist = getAllowedOrigins(env);
  if (allowlist.includes(normalized)) return true;
  // Also allow *.run.app preview origins in AI Studio preview container
  if (/^https:\/\/[a-z0-9-]+\.run\.app$/i.test(normalized)) return true;
  return false;
}

export function buildCorsHeaders(request, env = {}) {
  const origin = request.headers.get('Origin');
  const headers = {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers':
      'Content-Type, Authorization, X-CSRF-Token, X-Requested-With, Accept',
    'Access-Control-Expose-Headers':
      'X-Request-Id, X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };

  if (origin && isOriginAllowed(origin, env)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Credentials'] = 'true';
  } else if (!origin) {
    headers['Access-Control-Allow-Origin'] = 'https://dreamtechkashmirsolutions.studio';
  }

  return headers;
}

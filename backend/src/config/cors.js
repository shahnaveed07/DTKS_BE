/**
 * Strict CORS Configuration & Origin Allowlist
 */

const PRODUCTION_ALLOWED_ORIGINS = [
  'https://dreamtechkashmirsolutions.studio',
  'https://www.dreamtechkashmirsolutions.studio',
];

const DEV_ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:8787',
];

export function isProductionEnv(env = {}) {
  return (
    String(env?.ENVIRONMENT || '').toLowerCase() === 'production' ||
    (typeof process !== 'undefined' &&
      String(process.env?.NODE_ENV || '').toLowerCase() === 'production' &&
      !env?.ENVIRONMENT)
  );
}

function isDevOrPreviewOrigin(origin = '') {
  return (
    /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i.test(origin) ||
    /^https:\/\/[a-z0-9-]+\.run\.app$/i.test(origin)
  );
}

export function getAllowedOrigins(env = {}) {
  const custom = env.CORS_ALLOWED_ORIGINS
    ? String(env.CORS_ALLOWED_ORIGINS)
        .split(',')
        .map((s) => s.trim().replace(/\/+$/, ''))
        .filter(Boolean)
    : [];
  const appUrl = env.APP_URL ? [String(env.APP_URL).trim().replace(/\/+$/, '')] : [];
  const inProd = isProductionEnv(env);

  const baseOrigins = inProd
    ? PRODUCTION_ALLOWED_ORIGINS
    : [...PRODUCTION_ALLOWED_ORIGINS, ...DEV_ALLOWED_ORIGINS];

  const combined = Array.from(new Set([...baseOrigins, ...custom, ...appUrl]));
  if (inProd) {
    return combined.filter((origin) => !isDevOrPreviewOrigin(origin));
  }
  return combined;
}

export function isOriginAllowed(origin, env = {}) {
  if (!origin) return true; // Same-origin or server-to-server request
  const normalized = String(origin).trim().replace(/\/+$/, '');
  const allowlist = getAllowedOrigins(env);
  if (allowlist.includes(normalized)) return true;
  // Allow *.run.app preview origins strictly outside production
  if (!isProductionEnv(env) && /^https:\/\/[a-z0-9-]+\.run\.app$/i.test(normalized)) {
    return true;
  }
  return false;
}

export function buildCorsHeaders(request, env = {}) {
  const origin = request.headers.get('Origin');
  const headers = {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers':
      'Content-Type, Authorization, X-CSRF-Token, X-Auth-Mode, X-Requested-With, Accept',
    'Access-Control-Expose-Headers':
      'X-Request-Id, X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };

  if (origin && isOriginAllowed(origin, env)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Credentials'] = 'true';
  }

  return headers;
}


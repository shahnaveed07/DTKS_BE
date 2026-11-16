import { buildCorsHeaders, isProductionEnv } from '../config/cors.js';

/**
 * Applies production security headers and CORS allowlist headers to every API response.
 */
export function applySecurityAndCorsHeaders(response, request, env = {}) {
  const headers = new Headers(response.headers);
  const corsHeaders = buildCorsHeaders(request, env);

  for (const [key, value] of Object.entries(corsHeaders)) {
    headers.set(key, value);
  }

  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');

  if (!headers.has('Cross-Origin-Resource-Policy')) {
    headers.set('Cross-Origin-Resource-Policy', 'same-site');
  }

  if (!headers.has('Cache-Control')) {
    headers.set('Cache-Control', 'no-store');
  }

  if (!headers.has('Content-Security-Policy')) {
    headers.set(
      'Content-Security-Policy',
      "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    );
  }

  let isHttps = false;
  try {
    const url = new URL(request.url);
    isHttps =
      url.protocol === 'https:' ||
      String(request.headers.get('X-Forwarded-Proto') || '').toLowerCase() === 'https';
  } catch {
    isHttps = false;
  }

  if (isProductionEnv(env) && isHttps) {
    headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}


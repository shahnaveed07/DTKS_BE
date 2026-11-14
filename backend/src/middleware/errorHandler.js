import { generateRandomId } from '../utils/crypto.js';
import { errorResponse } from '../utils/response.js';

/**
 * Resolves or generates a correlation request ID (prefers Cloudflare CF-Ray or X-Request-Id).
 */
export function resolveRequestId(request = null) {
  if (request && typeof request.headers?.get === 'function') {
    const cfRay = request.headers.get('cf-ray') || request.headers.get('CF-Ray');
    if (cfRay) return cfRay;
    const headerId = request.headers.get('x-request-id') || request.headers.get('X-Request-Id');
    if (headerId) return headerId;
  }
  return generateRandomId('req');
}

/**
 * Emits a structured JSON diagnostic log entry to server-side logs only.
 * Never exposes stack traces or sensitive SQL details to HTTP clients.
 */
export function logServerError(err, request = null, extraContext = {}) {
  const requestId = resolveRequestId(request);
  let pathname = '/';
  let method = 'UNKNOWN';

  if (request) {
    method = (request.method || 'GET').toUpperCase();
    try {
      pathname = new URL(request.url).pathname;
    } catch {
      pathname = String(request.url || '/');
    }
  }

  const logEntry = {
    level: 'error',
    service: 'dtks-be',
    timestamp: new Date().toISOString(),
    requestId,
    method,
    pathname,
    errorName: err?.name || 'Error',
    errorCode: err?.code || 'INTERNAL_SERVER_ERROR',
    errorMessage: err?.message || String(err),
    stack: err?.stack || null,
    ...extraContext,
  };

  console.error('[DTKS Backend Error]:', JSON.stringify(logEntry));
  return requestId;
}

/**
 * Centralized exception handler that logs full diagnostics server-side while
 * returning a sanitized, consistent JSON error response to the client.
 */
export function handleException(err, request = null) {
  const requestId = logServerError(err, request);
  const rawMessage = String(err?.message || '');

  // Classify uninitialized database schema or missing D1 tables as 503 Service Unavailable
  if (
    err?.code === 'DATABASE_SCHEMA_MISSING' ||
    err?.code === 'DATABASE_UNAVAILABLE' ||
    /no such table/i.test(rawMessage)
  ) {
    return errorResponse(
      'Database service or schema is not ready. Ensure D1 migrations have been applied.',
      503,
      err?.code === 'DATABASE_UNAVAILABLE' ? 'DATABASE_UNAVAILABLE' : 'DATABASE_SCHEMA_MISSING',
      { requestId },
      { 'X-Request-Id': requestId }
    );
  }

  // Classify general SQLite / D1 query execution failures safely without leaking SQL
  if (
    err?.code === 'DATABASE_QUERY_ERROR' ||
    /D1_ERROR|SQLITE_ERROR|SQLITE_CONSTRAINT|database is locked/i.test(rawMessage)
  ) {
    return errorResponse(
      'A database error occurred while processing your request.',
      500,
      'DATABASE_ERROR',
      { requestId },
      { 'X-Request-Id': requestId }
    );
  }

  const status = typeof err?.status === 'number' ? err.status : 500;
  const code = err?.code || (status === 500 ? 'INTERNAL_SERVER_ERROR' : 'REQUEST_ERROR');

  if (status >= 500) {
    return errorResponse(
      'An unexpected server error occurred while processing your request.',
      status,
      code,
      { requestId },
      { 'X-Request-Id': requestId }
    );
  }

  return errorResponse(
    err?.message || 'Invalid request.',
    status,
    code,
    err?.details || { requestId },
    { 'X-Request-Id': requestId }
  );
}

import { errorResponse } from '../utils/response.js';

/**
 * Centralized error handler that prevents internal stack traces, SQL errors,
 * or credentials from leaking in API responses.
 */
export function handleException(err) {
  const status = typeof err?.status === 'number' ? err.status : 500;
  const code = err?.code || (status === 500 ? 'INTERNAL_SERVER_ERROR' : 'REQUEST_ERROR');

  if (status >= 500) {
    console.error('[DTKS Backend Error]:', err?.message || err);
    return errorResponse(
      'An unexpected server error occurred while processing your request.',
      500,
      'INTERNAL_SERVER_ERROR'
    );
  }

  return errorResponse(
    err?.message || 'Invalid request.',
    status,
    code,
    err?.details || null
  );
}

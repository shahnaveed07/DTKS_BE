import { verifyJwt } from '../utils/crypto.js';
import { errorResponse } from '../utils/response.js';

export function getJwtSecret(env = {}) {
  return (
    env.JWT_SECRET ||
    (typeof process !== 'undefined' && process.env?.JWT_SECRET) ||
    'dtks-production-grade-fallback-hmac-secret-2026-kashmir'
  );
}

function parseCookies(cookieHeader = '') {
  const out = {};
  for (const pair of String(cookieHeader).split(';')) {
    const idx = pair.indexOf('=');
    if (idx > 0) {
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      out[k] = decodeURIComponent(v);
    }
  }
  return out;
}

/**
 * Extracts and verifies the JWT token (via Authorization Bearer header or HttpOnly cookie
 * with CSRF token verification for state-changing requests), then verifies the Admin
 * account is active in D1 (`admins` table) and satisfies role-based access control.
 */
export async function authenticateAdmin(
  request,
  env,
  allowedRoles = ['super_admin', 'admin', 'editor']
) {
  const authHeader = request.headers.get('Authorization') || '';
  let token = '';
  let usedCookieAuth = false;

  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.slice('Bearer '.length).trim();
  } else {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    if (cookies.dtks_access_token) {
      token = cookies.dtks_access_token;
      usedCookieAuth = true;
    }
  }

  if (!token) {
    return {
      authenticated: false,
      response: errorResponse(
        'Authentication required. Please sign in as an administrator.',
        401,
        'UNAUTHORIZED'
      ),
    };
  }

  // CSRF protection when cookie-based authentication is used on state-changing requests
  const method = (request.method || 'GET').toUpperCase();
  if (usedCookieAuth && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const csrfHeader = request.headers.get('X-CSRF-Token') || '';
    if (!csrfHeader || !cookies.dtks_csrf_token || csrfHeader !== cookies.dtks_csrf_token) {
      return {
        authenticated: false,
        response: errorResponse(
          'CSRF token validation failed for cookie-authenticated request.',
          403,
          'CSRF_VALIDATION_FAILED'
        ),
      };
    }
  }

  let decoded;
  try {
    decoded = await verifyJwt(token, getJwtSecret(env));
  } catch (err) {
    const code = err.code === 'TOKEN_EXPIRED' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN';
    return {
      authenticated: false,
      response: errorResponse(
        err.code === 'TOKEN_EXPIRED'
          ? 'Your session has expired. Please refresh or sign in again.'
          : 'Invalid authentication token.',
        401,
        code
      ),
    };
  }

  if (decoded.type && decoded.type !== 'access') {
    return {
      authenticated: false,
      response: errorResponse('Invalid token type for API access.', 401, 'INVALID_TOKEN_TYPE'),
    };
  }

  const adminRow = await env.DB.prepare(
    'SELECT id, name, email, role, is_active, created_at, updated_at, last_login_at FROM admins WHERE id = ?'
  )
    .bind(decoded.sub)
    .first();

  if (!adminRow) {
    return {
      authenticated: false,
      response: errorResponse('Administrator account not found.', 401, 'ADMIN_NOT_FOUND'),
    };
  }

  if (!adminRow.is_active) {
    return {
      authenticated: false,
      response: errorResponse(
        'This administrator account has been deactivated.',
        403,
        'ACCOUNT_DEACTIVATED'
      ),
    };
  }

  if (allowedRoles.length > 0 && !allowedRoles.includes(adminRow.role)) {
    return {
      authenticated: false,
      response: errorResponse(
        'Insufficient role permissions for this operation.',
        403,
        'FORBIDDEN'
      ),
    };
  }

  return {
    authenticated: true,
    admin: {
      id: adminRow.id,
      name: adminRow.name,
      email: adminRow.email,
      role: adminRow.role,
      is_active: Boolean(adminRow.is_active),
      isActive: Boolean(adminRow.is_active),
      created_at: adminRow.created_at,
      createdAt: adminRow.created_at,
      updated_at: adminRow.updated_at,
      updatedAt: adminRow.updated_at,
      last_login_at: adminRow.last_login_at,
      lastLoginAt: adminRow.last_login_at,
    },
  };
}

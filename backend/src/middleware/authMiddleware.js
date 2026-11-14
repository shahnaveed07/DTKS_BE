import { verifyJwt } from '../utils/crypto.js';
import { errorResponse } from '../utils/response.js';

/**
 * Retrieves the configured JWT signing secret.
 * In production (`ENVIRONMENT === "production"`), a strong secret (>= 32 characters)
 * MUST be explicitly configured via Cloudflare secrets (`JWT_SECRET`).
 */
export function getJwtSecret(env = {}) {
  const configured =
    env.JWT_SECRET || (typeof process !== 'undefined' && process.env?.JWT_SECRET) || '';
  const isProd =
    env.ENVIRONMENT === 'production' ||
    (typeof process !== 'undefined' && process.env?.NODE_ENV === 'production');

  if (isProd) {
    if (
      !configured ||
      configured.length < 32 ||
      configured.includes('replace-with') ||
      configured.includes('fallback')
    ) {
      const err = new Error(
        'CRITICAL SECURITY ERROR: Production JWT_SECRET must be explicitly configured and at least 32 characters.'
      );
      err.status = 500;
      err.code = 'SERVER_MISCONFIGURED';
      throw err;
    }
    return configured;
  }

  return configured || 'dtks-local-dev-only-ephemeral-hmac-secret-key-2026';
}

export function parseCookies(cookieHeader = '') {
  const out = {};
  for (const pair of String(cookieHeader).split(';')) {
    const idx = pair.indexOf('=');
    if (idx > 0) {
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      try {
        out[k] = decodeURIComponent(v);
      } catch {
        out[k] = v;
      }
    }
  }
  return out;
}

function validateCookieCsrf(request, cookies, csrfCookieName) {
  const method = (request.method || 'GET').toUpperCase();
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    return true;
  }
  const csrfHeader = request.headers.get('X-CSRF-Token') || '';
  const csrfCookie = cookies[csrfCookieName] || '';
  return Boolean(csrfHeader && csrfCookie && csrfHeader === csrfCookie);
}

/**
 * Extracts and verifies the Admin JWT token (via Authorization Bearer header or HttpOnly cookie
 * with CSRF token verification for state-changing requests), verifies `accountType !== 'client'`,
 * validates `token_version` for immediate session revocation, checks `admins.is_active`, and
 * enforces role-based access control.
 */
export async function authenticateAdmin(
  request,
  env,
  allowedRoles = ['super_admin', 'admin', 'editor']
) {
  const authHeader = request.headers.get('Authorization') || '';
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  let token = '';
  let usedCookieAuth = false;

  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.slice('Bearer '.length).trim();
  } else if (cookies.dtks_access_token) {
    token = cookies.dtks_access_token;
    usedCookieAuth = true;
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

  if (usedCookieAuth && !validateCookieCsrf(request, cookies, 'dtks_csrf_token')) {
    return {
      authenticated: false,
      response: errorResponse(
        'CSRF token validation failed for cookie-authenticated request.',
        403,
        'CSRF_VALIDATION_FAILED'
      ),
    };
  }

  let decoded;
  try {
    decoded = await verifyJwt(token, getJwtSecret(env));
  } catch (err) {
    if (err.code === 'SERVER_MISCONFIGURED') {
      throw err;
    }
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

  if (decoded.accountType && decoded.accountType !== 'admin') {
    return {
      authenticated: false,
      response: errorResponse(
        'Client authentication tokens cannot access administrator endpoints.',
        401,
        'INVALID_TOKEN_TYPE'
      ),
    };
  }

  const adminRow = await env.DB.prepare(
    `SELECT id, name, email, role, is_active, token_version, invited_by_admin_id,
            invite_accepted_at, deactivated_at, created_at, updated_at, last_login_at
     FROM admins WHERE id = ?`
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

  const dbTokenVersion = Number(adminRow.token_version ?? 1);
  if (
    (decoded.tv !== undefined && Number(decoded.tv) !== dbTokenVersion) ||
    (decoded.tv === undefined && dbTokenVersion > 1)
  ) {
    return {
      authenticated: false,
      response: errorResponse(
        'Your session has been revoked. Please sign in again.',
        401,
        'SESSION_REVOKED'
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
      invited_by_admin_id: adminRow.invited_by_admin_id || null,
      invitedByAdminId: adminRow.invited_by_admin_id || null,
      invite_accepted_at: adminRow.invite_accepted_at || null,
      inviteAcceptedAt: adminRow.invite_accepted_at || null,
      deactivated_at: adminRow.deactivated_at || null,
      deactivatedAt: adminRow.deactivated_at || null,
      created_at: adminRow.created_at,
      createdAt: adminRow.created_at,
      updated_at: adminRow.updated_at,
      updatedAt: adminRow.updated_at,
      last_login_at: adminRow.last_login_at,
      lastLoginAt: adminRow.last_login_at,
    },
  };
}

/**
 * Dedicated Client Authentication Middleware (`authenticateClient`).
 * Strictly isolated from `authenticateAdmin`:
 *   - Requires `decoded.accountType === 'client'` and `decoded.type === 'access'`.
 *   - Rejects all Admin JWTs.
 *   - Verifies account existence, active status, email verification status, and `token_version`.
 */
export async function authenticateClient(
  request,
  env,
  { requireVerified = true } = {}
) {
  const authHeader = request.headers.get('Authorization') || '';
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  let token = '';
  let usedCookieAuth = false;

  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.slice('Bearer '.length).trim();
  } else if (cookies.dtks_client_access_token) {
    token = cookies.dtks_client_access_token;
    usedCookieAuth = true;
  }

  if (!token) {
    return {
      authenticated: false,
      response: errorResponse(
        'Authentication required. Please sign in to your client account.',
        401,
        'UNAUTHORIZED'
      ),
    };
  }

  if (usedCookieAuth && !validateCookieCsrf(request, cookies, 'dtks_client_csrf_token')) {
    return {
      authenticated: false,
      response: errorResponse(
        'CSRF token validation failed for cookie-authenticated request.',
        403,
        'CSRF_VALIDATION_FAILED'
      ),
    };
  }

  let decoded;
  try {
    decoded = await verifyJwt(token, getJwtSecret(env));
  } catch (err) {
    if (err.code === 'SERVER_MISCONFIGURED') {
      throw err;
    }
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

  if (decoded.type !== 'access' || decoded.accountType !== 'client') {
    return {
      authenticated: false,
      response: errorResponse(
        'Invalid token type for client portal access.',
        401,
        'INVALID_TOKEN_TYPE'
      ),
    };
  }

  const accountRow = await env.DB.prepare(
    `SELECT id, customer_id, full_name, email, phone, city, business_name,
            is_email_verified, email_verified_at, is_active, deactivated_at,
            terms_accepted, terms_accepted_at, terms_version,
            privacy_accepted, privacy_accepted_at, privacy_version,
            token_version, last_login_at, created_at, updated_at
     FROM customer_accounts WHERE id = ?`
  )
    .bind(decoded.sub)
    .first();

  if (!accountRow) {
    return {
      authenticated: false,
      response: errorResponse('Client account not found.', 401, 'CLIENT_NOT_FOUND'),
    };
  }

  if (!accountRow.is_active) {
    return {
      authenticated: false,
      response: errorResponse(
        'This client account has been deactivated.',
        403,
        'ACCOUNT_DEACTIVATED'
      ),
    };
  }

  if (requireVerified && !accountRow.is_email_verified) {
    return {
      authenticated: false,
      response: errorResponse(
        'Please verify your email address before accessing your client account.',
        403,
        'EMAIL_NOT_VERIFIED'
      ),
    };
  }

  const dbTokenVersion = Number(accountRow.token_version ?? 1);
  if (typeof decoded.tv !== 'number' || Number(decoded.tv) !== dbTokenVersion) {
    return {
      authenticated: false,
      response: errorResponse(
        'Your session has been revoked. Please sign in again.',
        401,
        'SESSION_REVOKED'
      ),
    };
  }

  return {
    authenticated: true,
    client: {
      id: accountRow.id,
      customer_id: accountRow.customer_id || null,
      customerId: accountRow.customer_id || null,
      full_name: accountRow.full_name,
      fullName: accountRow.full_name,
      email: accountRow.email,
      phone: accountRow.phone,
      city: accountRow.city || '',
      business_name: accountRow.business_name || '',
      businessName: accountRow.business_name || '',
      is_email_verified: Boolean(accountRow.is_email_verified),
      isEmailVerified: Boolean(accountRow.is_email_verified),
      email_verified_at: accountRow.email_verified_at || null,
      emailVerifiedAt: accountRow.email_verified_at || null,
      is_active: Boolean(accountRow.is_active),
      isActive: Boolean(accountRow.is_active),
      deactivated_at: accountRow.deactivated_at || null,
      deactivatedAt: accountRow.deactivated_at || null,
      terms_accepted: Boolean(accountRow.terms_accepted),
      termsAccepted: Boolean(accountRow.terms_accepted),
      terms_accepted_at: accountRow.terms_accepted_at || null,
      termsAcceptedAt: accountRow.terms_accepted_at || null,
      terms_version: accountRow.terms_version || '',
      termsVersion: accountRow.terms_version || '',
      privacy_accepted: Boolean(accountRow.privacy_accepted),
      privacyAccepted: Boolean(accountRow.privacy_accepted),
      privacy_accepted_at: accountRow.privacy_accepted_at || null,
      privacyAcceptedAt: accountRow.privacy_accepted_at || null,
      privacy_version: accountRow.privacy_version || '',
      privacyVersion: accountRow.privacy_version || '',
      last_login_at: accountRow.last_login_at || null,
      lastLoginAt: accountRow.last_login_at || null,
      created_at: accountRow.created_at,
      createdAt: accountRow.created_at,
      updated_at: accountRow.updated_at,
      updatedAt: accountRow.updated_at,
    },
  };
}

/**
 * Optional client session resolver for endpoints supporting both guests and logged-in clients
 * (e.g., `POST /api/v1/orders`). Never throws or blocks unauthenticated guests.
 */
export async function getOptionalAuthenticatedClient(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  if (!authHeader.startsWith('Bearer ') && !cookies.dtks_client_access_token) {
    return null;
  }
  const result = await authenticateClient(request, env, { requireVerified: true });
  return result.authenticated ? result.client : null;
}

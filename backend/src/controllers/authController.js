import {
  verifyPassword,
  hashPassword,
  signJwt,
  generateRandomId,
  generateRandomToken,
  sha256Hex,
} from '../utils/crypto.js';
import { successResponse, errorResponse, parseJsonBody } from '../utils/response.js';
import { validateLoginInput, validateChangePasswordInput } from '../validators/schemas.js';
import { getJwtSecret } from '../middleware/authMiddleware.js';
import { getClientIp } from '../middleware/rateLimiter.js';
import { logAdminActivity } from '../services/auditService.js';

function getAccessExpiresSeconds(env) {
  return Number.parseInt(env.JWT_ACCESS_EXPIRES_IN || '900', 10) || 900;
}

function getRefreshExpiresSeconds(env) {
  return Number.parseInt(env.JWT_REFRESH_EXPIRES_IN || '604800', 10) || 604800;
}

function mapAdminResponse(row, lastLoginOverride = null) {
  if (!row) return null;
  const lastLogin = lastLoginOverride || row.last_login_at || null;
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    is_active: Boolean(row.is_active),
    isActive: Boolean(row.is_active),
    created_at: row.created_at,
    createdAt: row.created_at,
    updated_at: row.updated_at,
    updatedAt: row.updated_at,
    last_login_at: lastLogin,
    lastLoginAt: lastLogin,
  };
}

export async function loginAdmin(request, env) {
  const body = await parseJsonBody(request);
  const validation = validateLoginInput(body);
  if (!validation.isValid) {
    return errorResponse('Invalid login credentials.', 400, 'VALIDATION_ERROR', validation.errors);
  }

  const { email, password } = validation.data;
  const admin = await env.DB.prepare(
    'SELECT id, name, email, password_hash, role, is_active, created_at, updated_at, last_login_at FROM admins WHERE lower(email) = lower(?)'
  )
    .bind(email)
    .first();

  if (!admin) {
    return errorResponse('Invalid email or password.', 401, 'INVALID_CREDENTIALS');
  }

  if (!admin.is_active) {
    return errorResponse(
      'This administrator account has been deactivated.',
      403,
      'ACCOUNT_DEACTIVATED'
    );
  }

  const passwordValid = await verifyPassword(password, admin.password_hash);
  if (!passwordValid) {
    await logAdminActivity(env, {
      adminId: admin.id,
      action: 'LOGIN_FAILED',
      entityType: 'Admin',
      entityId: admin.id,
      details: 'Invalid password attempt',
      request,
    });
    return errorResponse('Invalid email or password.', 401, 'INVALID_CREDENTIALS');
  }

  const now = new Date().toISOString();
  const accessExp = getAccessExpiresSeconds(env);
  const refreshExp = getRefreshExpiresSeconds(env);

  const accessToken = await signJwt(
    {
      sub: admin.id,
      email: admin.email,
      role: admin.role,
      type: 'access',
    },
    getJwtSecret(env),
    accessExp
  );

  const rawRefreshToken = generateRandomToken(32);
  const refreshTokenHash = await sha256Hex(rawRefreshToken);
  const sessionId = generateRandomId('sess');
  const expiresAt = new Date(Date.now() + refreshExp * 1000).toISOString();

  await env.DB.prepare(
    `INSERT INTO refresh_sessions (id, admin_id, refresh_token_hash, user_agent, ip_address, expires_at, revoked_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`
  )
    .bind(
      sessionId,
      admin.id,
      refreshTokenHash,
      (request.headers.get('User-Agent') || '').slice(0, 255),
      getClientIp(request),
      expiresAt,
      now
    )
    .run();

  await env.DB.prepare('UPDATE admins SET last_login_at = ?, updated_at = ? WHERE id = ?')
    .bind(now, now, admin.id)
    .run();

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'LOGIN_SUCCESS',
    entityType: 'Admin',
    entityId: admin.id,
    details: 'Administrator signed in',
    request,
  });

  return successResponse(
    {
      accessToken,
      access_token: accessToken,
      refreshToken: rawRefreshToken,
      refresh_token: rawRefreshToken,
      expiresIn: accessExp,
      expires_in: accessExp,
      admin: mapAdminResponse(admin, now),
    },
    'Authenticated successfully.'
  );
}

export async function logoutAdmin(request, env, currentAdmin) {
  const body = await parseJsonBody(request).catch(() => ({}));
  const rawToken = body.refreshToken || body.refresh_token;
  const now = new Date().toISOString();

  if (rawToken) {
    const hash = await sha256Hex(rawToken);
    await env.DB.prepare(
      'UPDATE refresh_sessions SET revoked_at = ? WHERE refresh_token_hash = ?'
    )
      .bind(now, hash)
      .run();
  } else if (currentAdmin?.id) {
    await env.DB.prepare('UPDATE refresh_sessions SET revoked_at = ? WHERE admin_id = ?')
      .bind(now, currentAdmin.id)
      .run();
  }

  if (currentAdmin?.id) {
    await logAdminActivity(env, {
      adminId: currentAdmin.id,
      action: 'LOGOUT',
      entityType: 'Admin',
      entityId: currentAdmin.id,
      details: 'Administrator signed out',
      request,
    });
  }

  return successResponse({ loggedOut: true }, 'Logged out successfully.');
}

export async function refreshAdminToken(request, env) {
  const body = await parseJsonBody(request);
  const rawToken =
    typeof (body.refreshToken || body.refresh_token) === 'string'
      ? (body.refreshToken || body.refresh_token).trim()
      : '';
  if (!rawToken) {
    return errorResponse('Refresh token is required.', 400, 'MISSING_REFRESH_TOKEN');
  }

  const tokenHash = await sha256Hex(rawToken);
  const session = await env.DB.prepare(
    'SELECT id, admin_id, expires_at, revoked_at FROM refresh_sessions WHERE refresh_token_hash = ?'
  )
    .bind(tokenHash)
    .first();

  if (!session || session.revoked_at) {
    return errorResponse('Invalid or revoked refresh token.', 401, 'INVALID_REFRESH_TOKEN');
  }

  if (new Date(session.expires_at).getTime() <= Date.now()) {
    await env.DB.prepare('DELETE FROM refresh_sessions WHERE id = ?').bind(session.id).run();
    return errorResponse(
      'Refresh token has expired. Please sign in again.',
      401,
      'REFRESH_TOKEN_EXPIRED'
    );
  }

  const admin = await env.DB.prepare(
    'SELECT id, name, email, role, is_active, created_at, updated_at, last_login_at FROM admins WHERE id = ?'
  )
    .bind(session.admin_id)
    .first();

  if (!admin || !admin.is_active) {
    await env.DB.prepare('DELETE FROM refresh_sessions WHERE id = ?').bind(session.id).run();
    return errorResponse('Administrator account is not active.', 403, 'ACCOUNT_DEACTIVATED');
  }

  // Rotate refresh token: revoke old session and issue a new one
  const now = new Date().toISOString();
  await env.DB.prepare('UPDATE refresh_sessions SET revoked_at = ? WHERE id = ?')
    .bind(now, session.id)
    .run();

  const accessExp = getAccessExpiresSeconds(env);
  const refreshExp = getRefreshExpiresSeconds(env);

  const newAccessToken = await signJwt(
    {
      sub: admin.id,
      email: admin.email,
      role: admin.role,
      type: 'access',
    },
    getJwtSecret(env),
    accessExp
  );

  const newRawRefreshToken = generateRandomToken(32);
  const newRefreshTokenHash = await sha256Hex(newRawRefreshToken);
  const newSessionId = generateRandomId('sess');
  const newExpiresAt = new Date(Date.now() + refreshExp * 1000).toISOString();

  await env.DB.prepare(
    `INSERT INTO refresh_sessions (id, admin_id, refresh_token_hash, user_agent, ip_address, expires_at, revoked_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`
  )
    .bind(
      newSessionId,
      admin.id,
      newRefreshTokenHash,
      (request.headers.get('User-Agent') || '').slice(0, 255),
      getClientIp(request),
      newExpiresAt,
      now
    )
    .run();

  return successResponse(
    {
      accessToken: newAccessToken,
      access_token: newAccessToken,
      refreshToken: newRawRefreshToken,
      refresh_token: newRawRefreshToken,
      expiresIn: accessExp,
      expires_in: accessExp,
      admin: mapAdminResponse(admin),
    },
    'Session token refreshed.'
  );
}

export async function getAuthenticatedAdmin(request, env, admin) {
  return successResponse({ admin }, 'Authenticated administrator profile.');
}

export async function changeAdminPassword(request, env, admin) {
  const body = await parseJsonBody(request);
  const validation = validateChangePasswordInput({
    currentPassword: body.currentPassword ?? body.current_password,
    newPassword: body.newPassword ?? body.new_password,
  });
  if (!validation.isValid) {
    return errorResponse('Password validation failed.', 400, 'VALIDATION_ERROR', validation.errors);
  }

  const { currentPassword, newPassword } = validation.data;
  const row = await env.DB.prepare('SELECT id, password_hash FROM admins WHERE id = ?')
    .bind(admin.id)
    .first();

  if (!row) {
    return errorResponse('Administrator account not found.', 404, 'NOT_FOUND');
  }

  const matches = await verifyPassword(currentPassword, row.password_hash);
  if (!matches) {
    return errorResponse('Current password is incorrect.', 401, 'INVALID_CURRENT_PASSWORD');
  }

  const newHash = await hashPassword(newPassword);
  const now = new Date().toISOString();

  await env.DB.prepare('UPDATE admins SET password_hash = ?, updated_at = ? WHERE id = ?')
    .bind(newHash, now, admin.id)
    .run();

  // Revoke existing refresh sessions on password change
  await env.DB.prepare('UPDATE refresh_sessions SET revoked_at = ? WHERE admin_id = ?')
    .bind(now, admin.id)
    .run();

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'PASSWORD_CHANGED',
    entityType: 'Admin',
    entityId: admin.id,
    details: 'Administrator updated account password',
    request,
  });

  return successResponse({ updated: true }, 'Password changed successfully.');
}

export async function updateAdminProfile(request, env, admin) {
  const body = await parseJsonBody(request);
  const name = typeof body.name === 'string' ? body.name.trim() : admin.name;
  if (!name || name.length < 2) {
    return errorResponse('Administrator name must be at least 2 characters.', 400, 'VALIDATION_ERROR');
  }
  const now = new Date().toISOString();
  await env.DB.prepare('UPDATE admins SET name = ?, updated_at = ? WHERE id = ?')
    .bind(name, now, admin.id)
    .run();

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'UPDATE_PROFILE',
    entityType: 'Admin',
    entityId: admin.id,
    details: `Updated profile name to ${name}`,
    request,
  });

  return successResponse(
    {
      admin: {
        ...admin,
        name,
        updated_at: now,
        updatedAt: now,
      },
    },
    'Admin profile updated.'
  );
}

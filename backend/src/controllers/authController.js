import {
  verifyPassword,
  verifyPasswordWithMigration,
  hashPassword,
  signJwt,
  generateRandomId,
  generateRandomToken,
  sha256Hex,
} from '../utils/crypto.js';
import {
  ADMIN_PASSWORD_RESET_EXPIRY_SECONDS,
  PENDING_INVITE_PASSWORD_SENTINEL,
} from '../config/constants.js';
import { successResponse, errorResponse, parseJsonBody } from '../utils/response.js';
import {
  validateLoginInput,
  validateChangePasswordInput,
  validateForgotPasswordInput,
  validateResetPasswordInput,
} from '../validators/schemas.js';
import { getJwtSecret } from '../middleware/authMiddleware.js';
import { getClientIp } from '../middleware/rateLimiter.js';
import { logAdminActivity } from '../services/auditService.js';
import {
  isEmailProviderConfigured,
  sendAdminPasswordResetEmail,
  sendAdminSecurityNotificationEmail,
} from '../services/emailService.js';

function getAccessExpiresSeconds(env) {
  return (
    Number.parseInt(
      env.JWT_ACCESS_EXPIRES_IN || env.JWT_ACCESS_EXPIRY_SECONDS || '900',
      10
    ) || 900
  );
}

function getRefreshExpiresSeconds(env) {
  return (
    Number.parseInt(
      env.JWT_REFRESH_EXPIRES_IN || env.JWT_REFRESH_EXPIRY_SECONDS || '604800',
      10
    ) || 604800
  );
}

function getAdminResetExpirySeconds(env = {}) {
  const configured = Number.parseInt(String(env?.ADMIN_PASSWORD_RESET_EXPIRY_SECONDS || ''), 10);
  return Number.isFinite(configured) && configured > 0
    ? configured
    : ADMIN_PASSWORD_RESET_EXPIRY_SECONDS;
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
    invited_by_admin_id: row.invited_by_admin_id || null,
    invitedByAdminId: row.invited_by_admin_id || null,
    invite_accepted_at: row.invite_accepted_at || null,
    inviteAcceptedAt: row.invite_accepted_at || null,
    deactivated_at: row.deactivated_at || null,
    deactivatedAt: row.deactivated_at || null,
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
    `SELECT id, name, email, password_hash, role, is_active, token_version,
            invited_by_admin_id, invite_accepted_at, deactivated_at,
            created_at, updated_at, last_login_at
     FROM admins WHERE lower(email) = lower(?)`
  )
    .bind(email)
    .first();

  if (!admin) {
    return errorResponse('Invalid email or password.', 401, 'INVALID_CREDENTIALS');
  }

  if (admin.password_hash === PENDING_INVITE_PASSWORD_SENTINEL) {
    return errorResponse(
      'Administrator invitation is pending password setup. Please accept your invitation link first.',
      403,
      'INVITE_PENDING'
    );
  }

  if (!admin.is_active) {
    return errorResponse(
      'This administrator account has been deactivated.',
      403,
      'ACCOUNT_DEACTIVATED'
    );
  }

  const verification = await verifyPasswordWithMigration(password, admin.password_hash);
  if (!verification.valid) {
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

  // Transparently migrate legacy password hashes to canonical $pbkdf2-sha512$v=1$i=100000$...
  if (verification.needsRehash) {
    const upgradedHash = await hashPassword(password);
    await env.DB.prepare(
      'UPDATE admins SET password_hash = ?, last_login_at = ?, updated_at = ? WHERE id = ?'
    )
      .bind(upgradedHash, now, now, admin.id)
      .run();
    await logAdminActivity(env, {
      adminId: admin.id,
      action: 'PASSWORD_HASH_MIGRATED',
      entityType: 'Admin',
      entityId: admin.id,
      details: 'Migrated password hash to canonical PBKDF2-SHA512 format',
      request,
    });
  } else {
    await env.DB.prepare('UPDATE admins SET last_login_at = ?, updated_at = ? WHERE id = ?')
      .bind(now, now, admin.id)
      .run();
  }

  const accessExp = getAccessExpiresSeconds(env);
  const refreshExp = getRefreshExpiresSeconds(env);
  const tokenVersion = Number(admin.token_version ?? 1);

  const accessToken = await signJwt(
    {
      sub: admin.id,
      email: admin.email,
      role: admin.role,
      accountType: 'admin',
      type: 'access',
      tv: tokenVersion,
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
      getClientIp(request, env),
      expiresAt,
      now
    )
    .run();

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'LOGIN_SUCCESS',
    entityType: 'Admin',
    entityId: admin.id,
    details: 'Administrator signed in',
    request,
  });

  const csrfToken = generateRandomToken(16);

  return successResponse(
    {
      accessToken,
      access_token: accessToken,
      refreshToken: rawRefreshToken,
      refresh_token: rawRefreshToken,
      csrfToken,
      csrf_token: csrfToken,
      expiresIn: accessExp,
      expires_in: accessExp,
      admin: mapAdminResponse(admin, now),
    },
    'Authenticated successfully.'
  );
}

export async function logoutAdmin(request, env, currentAdmin) {
  const body = await parseJsonBody(request);
  const rawAllDevices =
    body.allDevices !== undefined ? body.allDevices : body.all_devices;

  if (rawAllDevices !== undefined && typeof rawAllDevices !== 'boolean') {
    return errorResponse('Invalid logout options.', 400, 'VALIDATION_ERROR', {
      allDevices: 'allDevices must be a boolean.',
    });
  }

  const allDevices = rawAllDevices === true;
  const rawToken =
    typeof (body.refreshToken || body.refresh_token) === 'string'
      ? (body.refreshToken || body.refresh_token).trim()
      : '';

  if (allDevices && !currentAdmin?.id) {
    return errorResponse(
      'Authenticated session is required to log out from all devices.',
      401,
      'UNAUTHORIZED'
    );
  }

  if (!rawToken && !currentAdmin?.id) {
    return errorResponse(
      'Authentication or refresh token is required to log out.',
      401,
      'UNAUTHORIZED'
    );
  }

  const now = new Date().toISOString();
  let sessionsRevoked = 0;
  let scope = 'single_device';

  if (allDevices || (!rawToken && currentAdmin?.id)) {
    scope = 'all_devices';
    const [revokeRes] = await env.DB.batch([
      env.DB.prepare(
        'UPDATE refresh_sessions SET revoked_at = ? WHERE admin_id = ? AND revoked_at IS NULL'
      ).bind(now, currentAdmin.id),
      env.DB.prepare(
        'UPDATE admins SET token_version = COALESCE(token_version, 1) + 1, updated_at = ? WHERE id = ?'
      ).bind(now, currentAdmin.id),
    ]);
    sessionsRevoked = Number(revokeRes?.meta?.changes || 0);
  } else if (rawToken) {
    const hash = await sha256Hex(rawToken);
    const revokeRes = currentAdmin?.id
      ? await env.DB.prepare(
          'UPDATE refresh_sessions SET revoked_at = ? WHERE refresh_token_hash = ? AND admin_id = ? AND revoked_at IS NULL'
        )
          .bind(now, hash, currentAdmin.id)
          .run()
      : await env.DB.prepare(
          'UPDATE refresh_sessions SET revoked_at = ? WHERE refresh_token_hash = ? AND revoked_at IS NULL'
        )
          .bind(now, hash)
          .run();
    sessionsRevoked = Number(revokeRes?.meta?.changes || 0);
  }

  if (currentAdmin?.id) {
    await logAdminActivity(env, {
      adminId: currentAdmin.id,
      action: scope === 'all_devices' ? 'LOGOUT_ALL_DEVICES' : 'LOGOUT',
      entityType: 'Admin',
      entityId: currentAdmin.id,
      details:
        scope === 'all_devices'
          ? 'Administrator signed out from all devices'
          : 'Administrator signed out',
      request,
    });
  }

  return successResponse(
    {
      loggedOut: true,
      allDevices: scope === 'all_devices',
      scope,
      sessionsRevoked,
    },
    scope === 'all_devices'
      ? 'Logged out from all devices successfully.'
      : 'Logged out successfully.'
  );
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
    `SELECT id, name, email, password_hash, role, is_active, token_version,
            invited_by_admin_id, invite_accepted_at, deactivated_at,
            created_at, updated_at, last_login_at
     FROM admins WHERE id = ?`
  )
    .bind(session.admin_id)
    .first();

  if (!admin || !admin.is_active || admin.password_hash === PENDING_INVITE_PASSWORD_SENTINEL) {
    await env.DB.prepare('DELETE FROM refresh_sessions WHERE id = ?').bind(session.id).run();
    return errorResponse('Administrator account is not active.', 403, 'ACCOUNT_DEACTIVATED');
  }

  // Rotate refresh token atomically: claim old session so concurrent replays fail
  const now = new Date().toISOString();
  const claimSession = await env.DB.prepare(
    'UPDATE refresh_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL'
  )
    .bind(now, session.id)
    .run();

  if (Number(claimSession?.meta?.changes || 0) !== 1) {
    return errorResponse('Invalid or revoked refresh token.', 401, 'INVALID_REFRESH_TOKEN');
  }

  const accessExp = getAccessExpiresSeconds(env);
  const refreshExp = getRefreshExpiresSeconds(env);
  const tokenVersion = Number(admin.token_version ?? 1);

  const newAccessToken = await signJwt(
    {
      sub: admin.id,
      email: admin.email,
      role: admin.role,
      accountType: 'admin',
      type: 'access',
      tv: tokenVersion,
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
      getClientIp(request, env),
      newExpiresAt,
      now
    )
    .run();

  const csrfToken = generateRandomToken(16);

  return successResponse(
    {
      accessToken: newAccessToken,
      access_token: newAccessToken,
      refreshToken: newRawRefreshToken,
      refresh_token: newRawRefreshToken,
      csrfToken,
      csrf_token: csrfToken,
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
    confirmPassword: body.confirmPassword ?? body.confirm_password,
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

  await env.DB.batch([
    env.DB.prepare(
      'UPDATE admins SET password_hash = ?, token_version = COALESCE(token_version, 1) + 1, updated_at = ? WHERE id = ?'
    ).bind(newHash, now, admin.id),
    env.DB.prepare(
      'UPDATE refresh_sessions SET revoked_at = ? WHERE admin_id = ? AND revoked_at IS NULL'
    ).bind(now, admin.id),
  ]);

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'PASSWORD_CHANGED',
    entityType: 'Admin',
    entityId: admin.id,
    details: 'Administrator updated account password and revoked active sessions',
    request,
  });

  return successResponse({ updated: true }, 'Password changed successfully.');
}

export async function updateAdminProfile(request, env, admin) {
  const body = await parseJsonBody(request);
  const forbiddenKeys = ['role', 'isActive', 'is_active', 'email', 'id', 'password', 'password_hash'];
  for (const key of forbiddenKeys) {
    if (Object.prototype.hasOwnProperty.call(body, key)) {
      return errorResponse(
        `Field "${key}" cannot be modified via profile update.`,
        400,
        'VALIDATION_ERROR',
        { [key]: 'Field is not editable on profile.' }
      );
    }
  }

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

export async function forgotAdminPassword(request, env) {
  const body = await parseJsonBody(request);
  const validation = validateForgotPasswordInput(body);
  if (!validation.isValid) {
    return errorResponse(
      'Please provide a valid email address.',
      400,
      'VALIDATION_ERROR',
      validation.errors
    );
  }

  // Verify email provider configuration BEFORE account lookup to prevent enumeration
  if (!isEmailProviderConfigured(env)) {
    return errorResponse(
      'Administrator password reset email delivery is currently unavailable.',
      503,
      'EMAIL_PROVIDER_UNCONFIGURED'
    );
  }

  const { email } = validation.data;
  const admin = await env.DB.prepare(
    `SELECT id, name, email, password_hash, is_active, invited_by_admin_id, invite_accepted_at, deactivated_at
     FROM admins WHERE lower(email) = lower(?)`
  )
    .bind(email)
    .first();

  const isEligibleAdmin = Boolean(
    admin &&
      admin.is_active &&
      !admin.deactivated_at &&
      admin.password_hash !== PENDING_INVITE_PASSWORD_SENTINEL &&
      (!admin.invited_by_admin_id || admin.invite_accepted_at)
  );

  if (isEligibleAdmin) {
    const now = new Date().toISOString();
    const tokenId = generateRandomId('atok');
    const rawResetToken = generateRandomToken(32);
    const resetTokenHash = await sha256Hex(rawResetToken);
    const resetExpirySeconds = getAdminResetExpirySeconds(env);
    const expiresAt = new Date(Date.now() + resetExpirySeconds * 1000).toISOString();

    await env.DB.prepare(
      `INSERT INTO admin_auth_tokens
       (id, admin_id, purpose, token_hash, expires_at, used_at, revoked_at, created_at)
       VALUES (?, ?, 'password_reset', ?, ?, NULL, NULL, ?)`
    )
      .bind(tokenId, admin.id, resetTokenHash, expiresAt, now)
      .run();

    let emailResult = {
      sent: false,
      status: 'failed',
      detailMessage: 'Unexpected error dispatching password reset email.',
    };
    try {
      emailResult = await sendAdminPasswordResetEmail(env, {
        adminId: admin.id,
        email: admin.email,
        name: admin.name,
        resetToken: rawResetToken,
        expiresMinutes: Math.max(1, Math.round(resetExpirySeconds / 60)),
      });
    } catch (err) {
      emailResult = {
        sent: false,
        status: 'failed',
        detailMessage: err?.message || 'Unexpected error dispatching password reset email.',
      };
    }

    if (emailResult.sent) {
      await env.DB.prepare(
        `UPDATE admin_auth_tokens
         SET revoked_at = ?
         WHERE admin_id = ? AND purpose = 'password_reset' AND id != ? AND used_at IS NULL AND revoked_at IS NULL`
      )
        .bind(now, admin.id, tokenId)
        .run();

      await logAdminActivity(env, {
        adminId: admin.id,
        action: 'ADMIN_PASSWORD_RESET_REQUESTED',
        entityType: 'Admin',
        entityId: admin.id,
        details: `Administrator password reset requested for ${admin.email}`,
        request,
      });
    } else {
      const revokedAt = new Date().toISOString();
      await env.DB.prepare(
        `UPDATE admin_auth_tokens
         SET revoked_at = ?
         WHERE id = ? AND purpose = 'password_reset' AND used_at IS NULL AND revoked_at IS NULL`
      )
        .bind(revokedAt, tokenId)
        .run();

      console.error(
        '[DTKS Security Event]: Admin password reset email delivery failed; token revoked.',
        JSON.stringify({
          adminId: admin.id,
          tokenId,
          deliveryStatus: emailResult.status,
          note: emailResult.detailMessage,
        })
      );

      await logAdminActivity(env, {
        adminId: admin.id,
        action: 'ADMIN_PASSWORD_RESET_DELIVERY_FAILED',
        entityType: 'Admin',
        entityId: admin.id,
        details: JSON.stringify({
          tokenId,
          deliveryStatus: emailResult.status,
          note: emailResult.detailMessage,
        }),
        request,
      });
    }
  }

  return successResponse(
    { requested: true },
    'If an eligible administrator account exists for that email address, a password reset email has been sent.'
  );
}

export async function resetAdminPassword(request, env) {
  const body = await parseJsonBody(request);
  const validation = validateResetPasswordInput(body);
  if (!validation.isValid) {
    return errorResponse(
      'Password reset validation failed.',
      400,
      'VALIDATION_ERROR',
      validation.errors
    );
  }

  const { token, password } = validation.data;
  const tokenHash = await sha256Hex(token);
  const tokenRow = await env.DB.prepare(
    `SELECT id, admin_id, expires_at, used_at, revoked_at
     FROM admin_auth_tokens
     WHERE token_hash = ? AND purpose = 'password_reset'`
  )
    .bind(tokenHash)
    .first();

  if (!tokenRow) {
    return errorResponse('Invalid password reset token.', 400, 'INVALID_RESET_TOKEN');
  }
  if (tokenRow.used_at || tokenRow.revoked_at) {
    return errorResponse(
      'This password reset token has already been used or revoked.',
      400,
      'RESET_TOKEN_USED'
    );
  }

  const expiresMs = new Date(tokenRow.expires_at).getTime();
  if (Number.isNaN(expiresMs) || expiresMs <= Date.now()) {
    return errorResponse(
      'This password reset token has expired. Please request a new password reset.',
      400,
      'RESET_TOKEN_EXPIRED'
    );
  }

  const admin = await env.DB.prepare(
    `SELECT id, name, email, password_hash, is_active, deactivated_at, invited_by_admin_id, invite_accepted_at
     FROM admins WHERE id = ?`
  )
    .bind(tokenRow.admin_id)
    .first();

  if (!admin) {
    return errorResponse('Administrator account not found.', 404, 'ADMIN_NOT_FOUND');
  }
  if (
    admin.password_hash === PENDING_INVITE_PASSWORD_SENTINEL ||
    (admin.invited_by_admin_id && !admin.invite_accepted_at)
  ) {
    return errorResponse(
      'Administrator invitation is pending password setup. Please accept your invitation link first.',
      403,
      'INVITE_PENDING'
    );
  }
  if (!admin.is_active || admin.deactivated_at) {
    return errorResponse(
      'This administrator account has been deactivated.',
      403,
      'ACCOUNT_DEACTIVATED'
    );
  }

  const newHash = await hashPassword(password);
  const now = new Date().toISOString();

  // Atomically claim the single-use, unrevoked, unexpired token inside the DB update itself
  const claimRes = await env.DB.prepare(
    `UPDATE admin_auth_tokens
     SET used_at = ?
     WHERE id = ?
       AND purpose = 'password_reset'
       AND used_at IS NULL
       AND revoked_at IS NULL
       AND julianday(expires_at) > julianday(?)`
  )
    .bind(now, tokenRow.id, now)
    .run();

  if (Number(claimRes?.meta?.changes || 0) !== 1) {
    const freshToken = await env.DB.prepare(
      'SELECT used_at, revoked_at, expires_at FROM admin_auth_tokens WHERE id = ?'
    )
      .bind(tokenRow.id)
      .first();

    if (freshToken && !freshToken.used_at && !freshToken.revoked_at) {
      return errorResponse(
        'This password reset token has expired. Please request a new password reset.',
        400,
        'RESET_TOKEN_EXPIRED'
      );
    }

    return errorResponse(
      'This password reset token has already been used or revoked.',
      400,
      'RESET_TOKEN_USED'
    );
  }

  try {
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE admin_auth_tokens
         SET revoked_at = ?
         WHERE admin_id = ? AND purpose = 'password_reset' AND id != ? AND used_at IS NULL AND revoked_at IS NULL`
      ).bind(now, admin.id, tokenRow.id),
      env.DB.prepare(
        `UPDATE admins
         SET password_hash = ?, token_version = COALESCE(token_version, 1) + 1, updated_at = ?
         WHERE id = ?`
      ).bind(newHash, now, admin.id),
      env.DB.prepare(
        'UPDATE refresh_sessions SET revoked_at = ? WHERE admin_id = ? AND revoked_at IS NULL'
      ).bind(now, admin.id),
    ]);
  } catch (err) {
    await env.DB.prepare('UPDATE admin_auth_tokens SET used_at = NULL WHERE id = ?')
      .bind(tokenRow.id)
      .run()
      .catch(() => {});
    throw err;
  }

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'ADMIN_PASSWORD_RESET_COMPLETED',
    entityType: 'Admin',
    entityId: admin.id,
    details: `Administrator password reset completed for ${admin.email} and all active sessions revoked`,
    request,
  });

  // Security alert notification must not cause a completed password reset to fail
  try {
    await sendAdminSecurityNotificationEmail(env, {
      adminId: admin.id,
      email: admin.email,
      name: admin.name,
      eventTitle: 'Your DTKS administrator password was reset',
      eventDescription:
        'Your DreamTech Kashmir Solutions (DTKS) administrator account password was reset using a one-time reset token and all active administrator sessions have been revoked.',
    });
  } catch {
    // Non-blocking security notification
  }

  return successResponse(
    { reset: true },
    'Administrator password has been reset successfully. You can now sign in with your new password.'
  );
}

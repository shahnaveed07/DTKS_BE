import {
  ADMIN_INVITE_EXPIRY_SECONDS,
  DEFAULT_ADMIN_ACCOUNTS_LIMIT,
  DEFAULT_ADMIN_ACCOUNTS_PAGE,
  MAX_ADMIN_ACCOUNTS_LIMIT,
  PENDING_INVITE_PASSWORD_SENTINEL,
} from '../config/constants.js';
import {
  generateRandomId,
  generateRandomToken,
  hashPassword,
  sha256Hex,
} from '../utils/crypto.js';
import { successResponse, errorResponse, parseJsonBody } from '../utils/response.js';
import {
  validateAdminAccountCreate,
  validateAdminAccountUpdate,
  validateAdminStatusUpdate,
  validateAcceptInviteInput,
} from '../validators/schemas.js';
import { logAdminActivity } from '../services/auditService.js';
import { sendAdminInvitationEmail } from '../services/emailService.js';

function getAdminInviteExpirySeconds(env = {}) {
  const configured = Number.parseInt(String(env?.ADMIN_INVITE_EXPIRY_SECONDS || ''), 10);
  return Number.isFinite(configured) && configured > 0 ? configured : ADMIN_INVITE_EXPIRY_SECONDS;
}

function mapAdminAccountRow(row, extra = {}) {
  if (!row) return null;
  const invitePending = row.password_hash === PENDING_INVITE_PASSWORD_SENTINEL;
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    is_active: Boolean(row.is_active),
    isActive: Boolean(row.is_active),
    invite_pending: invitePending,
    invitePending,
    invited_by_admin_id: row.invited_by_admin_id || null,
    invitedByAdminId: row.invited_by_admin_id || null,
    invite_accepted_at: row.invite_accepted_at || null,
    inviteAcceptedAt: row.invite_accepted_at || null,
    deactivated_at: row.deactivated_at || null,
    deactivatedAt: row.deactivated_at || null,
    last_login_at: row.last_login_at || null,
    lastLoginAt: row.last_login_at || null,
    created_at: row.created_at,
    createdAt: row.created_at,
    updated_at: row.updated_at,
    updatedAt: row.updated_at,
    ...extra,
  };
}

export async function listAdminAccounts(request, env) {
  const url = new URL(request.url);
  const role = (url.searchParams.get('role') || '').trim().toLowerCase();
  const rawStatus = (url.searchParams.get('status') || '').trim().toLowerCase();
  const status = ['all', 'active', 'inactive', 'pending', 'expired'].includes(rawStatus)
    ? rawStatus
    : '';
  const isActiveParam = url.searchParams.get('is_active') ?? url.searchParams.get('isActive');
  const search = (url.searchParams.get('search') || url.searchParams.get('q') || '').trim();

  const parsedPage = Number.parseInt(url.searchParams.get('page') || '', 10);
  const page =
    Number.isFinite(parsedPage) && parsedPage >= 1 ? parsedPage : DEFAULT_ADMIN_ACCOUNTS_PAGE;
  const parsedLimit = Number.parseInt(url.searchParams.get('limit') || '', 10);
  const limit =
    Number.isFinite(parsedLimit) && parsedLimit >= 1
      ? Math.min(MAX_ADMIN_ACCOUNTS_LIMIT, parsedLimit)
      : DEFAULT_ADMIN_ACCOUNTS_LIMIT;
  const offset = (page - 1) * limit;

  const nowIso = new Date().toISOString();
  const conditions = [];
  const params = [];

  if (role && role !== 'all') {
    conditions.push('a.role = ?');
    params.push(role);
  }

  if (status === 'active') {
    conditions.push('a.is_active = 1');
  } else if (status === 'inactive') {
    conditions.push('a.is_active = 0');
  } else if (status === 'pending') {
    conditions.push('a.password_hash = ?');
    params.push(PENDING_INVITE_PASSWORD_SENTINEL);
  } else if (status === 'expired') {
    conditions.push(
      `a.password_hash = ? AND COALESCE(
        (SELECT ai.expires_at FROM admin_invitations ai
         WHERE ai.admin_id = a.id AND ai.used_at IS NULL
         ORDER BY ai.created_at DESC LIMIT 1),
        ''
      ) <= ?`
    );
    params.push(PENDING_INVITE_PASSWORD_SENTINEL, nowIso);
  } else if (isActiveParam === 'true' || isActiveParam === '1') {
    conditions.push('a.is_active = 1');
  } else if (isActiveParam === 'false' || isActiveParam === '0') {
    conditions.push('a.is_active = 0');
  }

  if (search) {
    conditions.push('(a.name LIKE ? OR a.email LIKE ?)');
    const pattern = `%${search}%`;
    params.push(pattern, pattern);
  }

  const whereClause = conditions.length > 0 ? ` WHERE ${conditions.join(' AND ')}` : '';

  const countRow = await env.DB.prepare(`SELECT COUNT(*) AS total FROM admins a${whereClause}`)
    .bind(...params)
    .first();
  const total = Number(countRow?.total || 0);
  const totalPages = Math.max(1, Math.ceil(total / limit));

  const sql = `
    SELECT a.id, a.name, a.email, a.password_hash, a.role, a.is_active,
           a.invited_by_admin_id, a.invite_accepted_at, a.deactivated_at,
           a.last_login_at, a.created_at, a.updated_at,
           (SELECT COUNT(*) FROM refresh_sessions rs
            WHERE rs.admin_id = a.id AND rs.revoked_at IS NULL AND rs.expires_at > ?) AS activeSessionCount,
           (SELECT ai.expires_at FROM admin_invitations ai
            WHERE ai.admin_id = a.id AND ai.used_at IS NULL AND ai.revoked_at IS NULL
            ORDER BY ai.created_at DESC LIMIT 1) AS latestInviteExpiresAt
    FROM admins a${whereClause}
    ORDER BY a.created_at ASC
    LIMIT ? OFFSET ?`;

  const result = await env.DB.prepare(sql)
    .bind(nowIso, ...params, limit, offset)
    .all();

  const nowMs = Date.now();
  const accounts = (result.results || []).map((row) => {
    const activeSessions = Number(row.activeSessionCount || 0);
    const invitePending = row.password_hash === PENDING_INVITE_PASSWORD_SENTINEL;
    const inviteExpiresAt = invitePending ? row.latestInviteExpiresAt || null : null;
    const inviteExpired = Boolean(
      invitePending &&
        inviteExpiresAt &&
        !Number.isNaN(new Date(inviteExpiresAt).getTime()) &&
        new Date(inviteExpiresAt).getTime() <= nowMs
    );
    return mapAdminAccountRow(row, {
      activeSessionCount: activeSessions,
      activeSessions,
      inviteExpiresAt,
      invite_expires_at: inviteExpiresAt,
      inviteExpired,
      invite_expired: inviteExpired,
    });
  });

  return successResponse(
    {
      accounts,
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    },
    'Administrator accounts retrieved.'
  );
}

export async function getAdminAccountById(request, env, id) {
  const row = await env.DB.prepare(
    `SELECT id, name, email, password_hash, role, is_active,
            invited_by_admin_id, invite_accepted_at, deactivated_at,
            last_login_at, created_at, updated_at
     FROM admins WHERE id = ?`
  )
    .bind(id)
    .first();

  if (!row) {
    return errorResponse('Administrator account not found.', 404, 'NOT_FOUND');
  }

  const sessionsRes = await env.DB.prepare(
    `SELECT id, user_agent, ip_address, expires_at, revoked_at, created_at
     FROM refresh_sessions
     WHERE admin_id = ?
     ORDER BY created_at DESC
     LIMIT 20`
  )
    .bind(id)
    .all();

  const latestInvite = await env.DB.prepare(
    `SELECT id, expires_at, used_at, revoked_at, created_at
     FROM admin_invitations
     WHERE admin_id = ?
     ORDER BY created_at DESC
     LIMIT 1`
  )
    .bind(id)
    .first();

  const sessions = (sessionsRes.results || []).map((s) => ({
    id: s.id,
    userAgent: s.user_agent || '',
    ipAddress: s.ip_address || '',
    expiresAt: s.expires_at,
    revokedAt: s.revoked_at || null,
    isActive: !s.revoked_at && new Date(s.expires_at).getTime() > Date.now(),
    createdAt: s.created_at,
  }));

  const activeCount = sessions.filter((s) => s.isActive).length;
  const invitePending = row.password_hash === PENDING_INVITE_PASSWORD_SENTINEL;
  const inviteExpiresAt = invitePending && latestInvite ? latestInvite.expires_at : null;
  const inviteExpired = Boolean(
    invitePending &&
      inviteExpiresAt &&
      !Number.isNaN(new Date(inviteExpiresAt).getTime()) &&
      new Date(inviteExpiresAt).getTime() <= Date.now()
  );

  return successResponse(
    {
      account: mapAdminAccountRow(row, {
        activeSessionCount: activeCount,
        activeSessions: activeCount,
        inviteExpiresAt,
        invite_expires_at: inviteExpiresAt,
        inviteExpired,
        invite_expired: inviteExpired,
        sessions,
        latestInvitation: latestInvite
          ? {
              id: latestInvite.id,
              expiresAt: latestInvite.expires_at,
              usedAt: latestInvite.used_at || null,
              revokedAt: latestInvite.revoked_at || null,
              createdAt: latestInvite.created_at,
            }
          : null,
      }),
    },
    'Administrator account details retrieved.'
  );
}

export async function createAdminAccount(request, env, currentAdmin) {
  const body = await parseJsonBody(request);
  const validation = validateAdminAccountCreate(body);
  if (!validation.isValid) {
    return errorResponse(
      'Administrator account validation failed.',
      400,
      'VALIDATION_ERROR',
      validation.errors
    );
  }

  const { name, email, role } = validation.data;
  const existing = await env.DB.prepare(
    'SELECT id FROM admins WHERE lower(email) = lower(?)'
  )
    .bind(email)
    .first();

  if (existing) {
    return errorResponse(
      'An administrator account with this email address already exists.',
      409,
      'ADMIN_EMAIL_EXISTS'
    );
  }

  const now = new Date().toISOString();
  const adminId = generateRandomId('adm');
  const inviteId = generateRandomId('inv');
  const rawInviteToken = generateRandomToken(32);
  const inviteTokenHash = await sha256Hex(rawInviteToken);
  const inviteExpirySeconds = getAdminInviteExpirySeconds(env);
  const inviteExpiresAt = new Date(Date.now() + inviteExpirySeconds * 1000).toISOString();

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO admins
         (id, name, email, password_hash, role, is_active, token_version, invited_by_admin_id, created_at, updated_at, last_login_at)
         VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?, ?, NULL)`
      ).bind(
        adminId,
        name,
        email,
        PENDING_INVITE_PASSWORD_SENTINEL,
        role,
        currentAdmin.id,
        now,
        now
      ),
      env.DB.prepare(
        `INSERT INTO admin_invitations
         (id, admin_id, email, token_hash, invited_by_admin_id, expires_at, used_at, revoked_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)`
      ).bind(inviteId, adminId, email, inviteTokenHash, currentAdmin.id, inviteExpiresAt, now),
    ]);
  } catch (err) {
    if (/UNIQUE constraint failed/i.test(String(err?.message || ''))) {
      return errorResponse(
        'An administrator account with this email address already exists.',
        409,
        'ADMIN_EMAIL_EXISTS'
      );
    }
    throw err;
  }

  await logAdminActivity(env, {
    adminId: currentAdmin.id,
    action: 'ADMIN_ACCOUNT_CREATED',
    entityType: 'Admin',
    entityId: adminId,
    details: `Created pending administrator account (${email}) with role "${role}"`,
    request,
  });

  const emailResult = await sendAdminInvitationEmail(env, {
    adminId,
    email,
    name,
    role,
    inviteToken: rawInviteToken,
    expiresHours: Math.max(1, Math.round(inviteExpirySeconds / 3600)),
    invitedByName: currentAdmin.name,
  });

  const createdRow = await env.DB.prepare(
    `SELECT id, name, email, password_hash, role, is_active,
            invited_by_admin_id, invite_accepted_at, deactivated_at,
            last_login_at, created_at, updated_at
     FROM admins WHERE id = ?`
  )
    .bind(adminId)
    .first();

  if (!emailResult.sent) {
    return errorResponse(
      'Administrator account created in pending state, but invitation email delivery failed.',
      503,
      emailResult.status === 'skipped_unconfigured'
        ? 'EMAIL_PROVIDER_UNCONFIGURED'
        : 'EMAIL_DELIVERY_FAILED',
      {
        adminCreated: true,
        invitationEmailSent: false,
        inviteEmailSent: false,
        deliveryStatus: emailResult.status,
        account: mapAdminAccountRow(createdRow, {
          inviteExpiresAt,
          inviteExpired: false,
        }),
      }
    );
  }

  return successResponse(
    {
      account: mapAdminAccountRow(createdRow, {
        inviteExpiresAt,
        inviteExpired: false,
      }),
      invitationEmailSent: true,
      inviteEmailSent: true,
      invitationExpiresAt: inviteExpiresAt,
      inviteExpiresAt,
    },
    'Administrator account created and invitation email dispatched.',
    201
  );
}

export async function resendAdminInvitation(request, env, currentAdmin, id) {
  const target = await env.DB.prepare(
    `SELECT id, name, email, password_hash, role, is_active, deactivated_at
     FROM admins WHERE id = ?`
  )
    .bind(id)
    .first();

  if (!target) {
    return errorResponse('Administrator account not found.', 404, 'NOT_FOUND');
  }

  if (target.deactivated_at) {
    return errorResponse(
      'Cannot resend invitation for a deactivated administrator account.',
      403,
      'ACCOUNT_DEACTIVATED'
    );
  }

  if (target.password_hash !== PENDING_INVITE_PASSWORD_SENTINEL) {
    return errorResponse(
      'This administrator has already completed account activation.',
      400,
      'INVITE_ALREADY_ACCEPTED'
    );
  }

  const now = new Date().toISOString();
  const inviteId = generateRandomId('inv');
  const rawInviteToken = generateRandomToken(32);
  const inviteTokenHash = await sha256Hex(rawInviteToken);
  const inviteExpirySeconds = getAdminInviteExpirySeconds(env);
  const inviteExpiresAt = new Date(Date.now() + inviteExpirySeconds * 1000).toISOString();

  await env.DB.batch([
    env.DB.prepare(
      'UPDATE admin_invitations SET revoked_at = ? WHERE admin_id = ? AND used_at IS NULL AND revoked_at IS NULL'
    ).bind(now, target.id),
    env.DB.prepare(
      `INSERT INTO admin_invitations
       (id, admin_id, email, token_hash, invited_by_admin_id, expires_at, used_at, revoked_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)`
    ).bind(
      inviteId,
      target.id,
      target.email,
      inviteTokenHash,
      currentAdmin.id,
      inviteExpiresAt,
      now
    ),
  ]);

  await logAdminActivity(env, {
    adminId: currentAdmin.id,
    action: 'ADMIN_INVITE_RESENT',
    entityType: 'Admin',
    entityId: target.id,
    details: `Re-issued invitation token for ${target.email}`,
    request,
  });

  const emailResult = await sendAdminInvitationEmail(env, {
    adminId: target.id,
    email: target.email,
    name: target.name,
    role: target.role,
    inviteToken: rawInviteToken,
    expiresHours: Math.max(1, Math.round(inviteExpirySeconds / 3600)),
    invitedByName: currentAdmin.name,
  });

  if (!emailResult.sent) {
    return errorResponse(
      'Invitation token was regenerated, but invitation email could not be delivered.',
      503,
      emailResult.status === 'skipped_unconfigured'
        ? 'EMAIL_PROVIDER_UNCONFIGURED'
        : 'EMAIL_DELIVERY_FAILED',
      {
        adminId: target.id,
        invitationEmailSent: false,
        inviteEmailSent: false,
        deliveryStatus: emailResult.status,
      }
    );
  }

  return successResponse(
    {
      invitationEmailSent: true,
      inviteEmailSent: true,
      invitationExpiresAt: inviteExpiresAt,
      inviteExpiresAt,
    },
    'Administrator invitation email resent.'
  );
}

export async function acceptAdminInvite(request, env) {
  const body = await parseJsonBody(request);
  const validation = validateAcceptInviteInput(body);
  if (!validation.isValid) {
    return errorResponse(
      'Invitation acceptance validation failed.',
      400,
      'VALIDATION_ERROR',
      validation.errors
    );
  }

  const { token, password } = validation.data;
  const tokenHash = await sha256Hex(token);
  const invite = await env.DB.prepare(
    `SELECT id, admin_id, email, expires_at, used_at, revoked_at
     FROM admin_invitations WHERE token_hash = ?`
  )
    .bind(tokenHash)
    .first();

  if (!invite) {
    return errorResponse('Invalid invitation token.', 400, 'INVALID_INVITE_TOKEN');
  }
  if (invite.used_at || invite.revoked_at) {
    return errorResponse(
      'This invitation token has already been used or revoked.',
      400,
      'INVITE_TOKEN_ALREADY_USED'
    );
  }
  if (new Date(invite.expires_at).getTime() <= Date.now()) {
    return errorResponse(
      'This invitation token has expired. Ask a super administrator to resend an invitation.',
      400,
      'INVITE_TOKEN_EXPIRED'
    );
  }

  const targetAdmin = await env.DB.prepare(
    `SELECT id, email, password_hash, is_active, deactivated_at
     FROM admins WHERE id = ?`
  )
    .bind(invite.admin_id)
    .first();

  if (!targetAdmin) {
    return errorResponse('Administrator account not found.', 404, 'NOT_FOUND');
  }
  if (targetAdmin.deactivated_at) {
    return errorResponse(
      'This administrator account has been deactivated.',
      403,
      'ACCOUNT_DEACTIVATED'
    );
  }
  if (targetAdmin.password_hash !== PENDING_INVITE_PASSWORD_SENTINEL) {
    return errorResponse(
      'This administrator account has already been activated.',
      400,
      'INVITE_ALREADY_ACCEPTED'
    );
  }

  const passwordHash = await hashPassword(password);
  const now = new Date().toISOString();

  // Atomically claim the single-use, unrevoked, unexpired invitation first
  const claimRes = await env.DB.prepare(
    `UPDATE admin_invitations
     SET used_at = ?
     WHERE id = ?
       AND used_at IS NULL
       AND revoked_at IS NULL
       AND julianday(expires_at) > julianday(?)`
  )
    .bind(now, invite.id, now)
    .run();

  if (Number(claimRes?.meta?.changes || 0) !== 1) {
    const freshInvite = await env.DB.prepare(
      'SELECT used_at, revoked_at FROM admin_invitations WHERE id = ?'
    )
      .bind(invite.id)
      .first();

    if (freshInvite && !freshInvite.used_at && !freshInvite.revoked_at) {
      return errorResponse(
        'This invitation token has expired. Ask a super administrator to resend an invitation.',
        400,
        'INVITE_TOKEN_EXPIRED'
      );
    }

    return errorResponse(
      'This invitation token has already been used or revoked.',
      400,
      'INVITE_TOKEN_ALREADY_USED'
    );
  }

  try {
    await env.DB.batch([
      env.DB.prepare(
        'UPDATE admin_invitations SET revoked_at = ? WHERE admin_id = ? AND id != ? AND used_at IS NULL AND revoked_at IS NULL'
      ).bind(now, invite.admin_id, invite.id),
      env.DB.prepare(
        `UPDATE admins
         SET password_hash = ?, is_active = 1, invite_accepted_at = ?, deactivated_at = NULL, updated_at = ?
         WHERE id = ? AND password_hash = ? AND deactivated_at IS NULL`
      ).bind(passwordHash, now, now, invite.admin_id, PENDING_INVITE_PASSWORD_SENTINEL),
    ]);
  } catch (err) {
    await env.DB.prepare('UPDATE admin_invitations SET used_at = NULL WHERE id = ?')
      .bind(invite.id)
      .run()
      .catch(() => {});
    throw err;
  }

  const updatedAdmin = await env.DB.prepare(
    `SELECT id, name, email, password_hash, role, is_active,
            invited_by_admin_id, invite_accepted_at, deactivated_at,
            last_login_at, created_at, updated_at
     FROM admins WHERE id = ?`
  )
    .bind(invite.admin_id)
    .first();

  await logAdminActivity(env, {
    adminId: invite.admin_id,
    action: 'ADMIN_INVITE_ACCEPTED',
    entityType: 'Admin',
    entityId: invite.admin_id,
    details: `Administrator ${invite.email} completed password setup and activated account`,
    request,
  });

  return successResponse(
    {
      activated: true,
      account: mapAdminAccountRow(updatedAdmin),
    },
    'Administrator account activated. You can now sign in.'
  );
}

export async function updateAdminAccount(request, env, currentAdmin, id) {
  const existing = await env.DB.prepare(
    `SELECT id, name, email, password_hash, role, is_active, token_version,
            invited_by_admin_id, invite_accepted_at, deactivated_at,
            last_login_at, created_at, updated_at
     FROM admins WHERE id = ?`
  )
    .bind(id)
    .first();

  if (!existing) {
    return errorResponse('Administrator account not found.', 404, 'NOT_FOUND');
  }

  const body = await parseJsonBody(request);
  const validation = validateAdminAccountUpdate(body);
  if (!validation.isValid) {
    return errorResponse(
      'Administrator account update validation failed.',
      400,
      'VALIDATION_ERROR',
      validation.errors
    );
  }

  const nextName = validation.data.name !== undefined ? validation.data.name : existing.name;
  const nextRole = validation.data.role !== undefined ? validation.data.role : existing.role;
  const roleChanged = nextRole !== existing.role;
  const now = new Date().toISOString();

  if (roleChanged) {
    // Atomic last-active-super-admin protection inside SQL WHERE clause
    const updateRes = await env.DB.prepare(
      `UPDATE admins
       SET name = ?, role = ?, token_version = COALESCE(token_version, 1) + 1, updated_at = ?
       WHERE id = ?
         AND (
           role != 'super_admin'
           OR is_active = 0
           OR ? = 'super_admin'
           OR (SELECT COUNT(*) FROM admins WHERE role = 'super_admin' AND is_active = 1 AND id != ?) >= 1
         )`
    )
      .bind(nextName, nextRole, now, existing.id, nextRole, existing.id)
      .run();

    if (Number(updateRes?.meta?.changes || 0) !== 1) {
      return errorResponse(
        'Cannot demote the last active super_admin account.',
        409,
        'LAST_SUPER_ADMIN_PROTECTED'
      );
    }

    await env.DB.prepare(
      "UPDATE refresh_sessions SET revoked_at = ?, revoke_reason = 'role_changed' WHERE admin_id = ? AND revoked_at IS NULL"
    )
      .bind(now, existing.id)
      .run();

    await logAdminActivity(env, {
      adminId: currentAdmin.id,
      action: 'ADMIN_ROLE_CHANGED',
      entityType: 'Admin',
      entityId: existing.id,
      details: `Changed role of ${existing.email} from "${existing.role}" to "${nextRole}" and revoked active sessions`,
      request,
    });
  } else {
    await env.DB.prepare('UPDATE admins SET name = ?, updated_at = ? WHERE id = ?')
      .bind(nextName, now, existing.id)
      .run();
    await logAdminActivity(env, {
      adminId: currentAdmin.id,
      action: 'ADMIN_ACCOUNT_UPDATED',
      entityType: 'Admin',
      entityId: existing.id,
      details: `Updated administrator profile name for ${existing.email}`,
      request,
    });
  }

  const updated = await env.DB.prepare(
    `SELECT id, name, email, password_hash, role, is_active,
            invited_by_admin_id, invite_accepted_at, deactivated_at,
            last_login_at, created_at, updated_at
     FROM admins WHERE id = ?`
  )
    .bind(existing.id)
    .first();

  return successResponse(
    { account: mapAdminAccountRow(updated) },
    'Administrator account updated.'
  );
}

export async function updateAdminAccountStatus(request, env, currentAdmin, id) {
  const existing = await env.DB.prepare(
    `SELECT id, name, email, password_hash, role, is_active, token_version,
            invited_by_admin_id, invite_accepted_at, deactivated_at,
            last_login_at, created_at, updated_at
     FROM admins WHERE id = ?`
  )
    .bind(id)
    .first();

  if (!existing) {
    return errorResponse('Administrator account not found.', 404, 'NOT_FOUND');
  }

  const body = await parseJsonBody(request);
  const validation = validateAdminStatusUpdate(body);
  if (!validation.isValid) {
    return errorResponse(
      'Administrator status validation failed.',
      400,
      'VALIDATION_ERROR',
      validation.errors
    );
  }

  const { isActive } = validation.data;
  const now = new Date().toISOString();

  if (isActive) {
    if (existing.password_hash === PENDING_INVITE_PASSWORD_SENTINEL) {
      return errorResponse(
        'Cannot activate an administrator account before they complete invitation password setup.',
        400,
        'INVITE_PENDING'
      );
    }

    await env.DB.prepare(
      'UPDATE admins SET is_active = 1, deactivated_at = NULL, updated_at = ? WHERE id = ?'
    )
      .bind(now, existing.id)
      .run();

    await logAdminActivity(env, {
      adminId: currentAdmin.id,
      action: 'ADMIN_ACCOUNT_ACTIVATED',
      entityType: 'Admin',
      entityId: existing.id,
      details: `Activated administrator account ${existing.email}`,
      request,
    });
  } else {
    // Atomic last-active-super-admin protection inside SQL WHERE clause
    const deactivateRes = await env.DB.prepare(
      `UPDATE admins
       SET is_active = 0, deactivated_at = ?, token_version = COALESCE(token_version, 1) + 1, updated_at = ?
       WHERE id = ?
         AND (
           role != 'super_admin'
           OR is_active = 0
           OR (SELECT COUNT(*) FROM admins WHERE role = 'super_admin' AND is_active = 1 AND id != ?) >= 1
         )`
    )
      .bind(now, now, existing.id, existing.id)
      .run();

    if (Number(deactivateRes?.meta?.changes || 0) !== 1) {
      return errorResponse(
        'Cannot deactivate the last active super_admin account.',
        409,
        'LAST_SUPER_ADMIN_PROTECTED'
      );
    }

    await env.DB.prepare(
      "UPDATE refresh_sessions SET revoked_at = ?, revoke_reason = 'account_deactivated' WHERE admin_id = ? AND revoked_at IS NULL"
    )
      .bind(now, existing.id)
      .run();

    await logAdminActivity(env, {
      adminId: currentAdmin.id,
      action: 'ADMIN_ACCOUNT_DEACTIVATED',
      entityType: 'Admin',
      entityId: existing.id,
      details: `Deactivated administrator account ${existing.email} and revoked all sessions`,
      request,
    });
  }

  const updated = await env.DB.prepare(
    `SELECT id, name, email, password_hash, role, is_active,
            invited_by_admin_id, invite_accepted_at, deactivated_at,
            last_login_at, created_at, updated_at
     FROM admins WHERE id = ?`
  )
    .bind(existing.id)
    .first();

  return successResponse(
    { account: mapAdminAccountRow(updated) },
    isActive ? 'Administrator account activated.' : 'Administrator account deactivated.'
  );
}

export async function revokeAdminAccountSessions(request, env, currentAdmin, id) {
  const existing = await env.DB.prepare('SELECT id, email FROM admins WHERE id = ?')
    .bind(id)
    .first();

  if (!existing) {
    return errorResponse('Administrator account not found.', 404, 'NOT_FOUND');
  }

  const now = new Date().toISOString();
  const [revokeRes] = await env.DB.batch([
    env.DB.prepare(
      "UPDATE refresh_sessions SET revoked_at = ?, revoke_reason = 'admin_sessions_revoked' WHERE admin_id = ? AND revoked_at IS NULL"
    ).bind(now, existing.id),
    env.DB.prepare(
      'UPDATE admins SET token_version = COALESCE(token_version, 1) + 1, updated_at = ? WHERE id = ?'
    ).bind(now, existing.id),
  ]);

  await logAdminActivity(env, {
    adminId: currentAdmin.id,
    action: 'ADMIN_SESSIONS_REVOKED',
    entityType: 'Admin',
    entityId: existing.id,
    details: `Revoked all active sessions for ${existing.email}`,
    request,
  });

  return successResponse(
    {
      adminId: existing.id,
      revokedSessions: Number(revokeRes?.meta?.changes || 0),
      revokedAt: now,
    },
    'All administrator sessions revoked.'
  );
}

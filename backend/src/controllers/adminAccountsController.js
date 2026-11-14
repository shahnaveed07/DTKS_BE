import {
  ADMIN_INVITE_EXPIRY_SECONDS,
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
  const isActiveParam = url.searchParams.get('is_active') ?? url.searchParams.get('isActive');
  const search = (url.searchParams.get('search') || url.searchParams.get('q') || '').trim();

  const conditions = [];
  const params = [];

  if (role && role !== 'all') {
    conditions.push('a.role = ?');
    params.push(role);
  }
  if (isActiveParam === 'true' || isActiveParam === '1') {
    conditions.push('a.is_active = 1');
  } else if (isActiveParam === 'false' || isActiveParam === '0') {
    conditions.push('a.is_active = 0');
  }
  if (search) {
    conditions.push('(a.name LIKE ? OR a.email LIKE ?)');
    const pattern = `%${search}%`;
    params.push(pattern, pattern);
  }

  let sql = `
    SELECT a.id, a.name, a.email, a.password_hash, a.role, a.is_active,
           a.invited_by_admin_id, a.invite_accepted_at, a.deactivated_at,
           a.last_login_at, a.created_at, a.updated_at,
           (SELECT COUNT(*) FROM refresh_sessions rs
            WHERE rs.admin_id = a.id AND rs.revoked_at IS NULL AND rs.expires_at > ?) AS activeSessionCount
    FROM admins a`;
  const nowIso = new Date().toISOString();
  const bindParams = [nowIso, ...params];

  if (conditions.length > 0) {
    sql += ` WHERE ${conditions.join(' AND ')}`;
  }
  sql += ' ORDER BY a.created_at ASC';

  const result = await env.DB.prepare(sql)
    .bind(...bindParams)
    .all();

  const accounts = (result.results || []).map((row) =>
    mapAdminAccountRow(row, {
      activeSessionCount: Number(row.activeSessionCount || 0),
    })
  );

  return successResponse({ accounts }, 'Administrator accounts retrieved.');
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

  return successResponse(
    {
      account: mapAdminAccountRow(row, {
        activeSessionCount: sessions.filter((s) => s.isActive).length,
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
  const inviteExpiresAt = new Date(Date.now() + ADMIN_INVITE_EXPIRY_SECONDS * 1000).toISOString();

  await env.DB.prepare(
    `INSERT INTO admins
     (id, name, email, password_hash, role, is_active, token_version, invited_by_admin_id, created_at, updated_at, last_login_at)
     VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?, ?, NULL)`
  )
    .bind(adminId, name, email, PENDING_INVITE_PASSWORD_SENTINEL, role, currentAdmin.id, now, now)
    .run();

  await env.DB.prepare(
    `INSERT INTO admin_invitations
     (id, admin_id, email, token_hash, invited_by_admin_id, expires_at, used_at, revoked_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)`
  )
    .bind(inviteId, adminId, email, inviteTokenHash, currentAdmin.id, inviteExpiresAt, now)
    .run();

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
    expiresHours: Math.round(ADMIN_INVITE_EXPIRY_SECONDS / 3600),
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
        deliveryStatus: emailResult.status,
        account: mapAdminAccountRow(createdRow),
      }
    );
  }

  return successResponse(
    {
      account: mapAdminAccountRow(createdRow),
      invitationEmailSent: true,
      invitationExpiresAt: inviteExpiresAt,
    },
    'Administrator account created and invitation email dispatched.',
    201
  );
}

export async function resendAdminInvitation(request, env, currentAdmin, id) {
  const target = await env.DB.prepare(
    `SELECT id, name, email, password_hash, role, is_active
     FROM admins WHERE id = ?`
  )
    .bind(id)
    .first();

  if (!target) {
    return errorResponse('Administrator account not found.', 404, 'NOT_FOUND');
  }

  if (target.password_hash !== PENDING_INVITE_PASSWORD_SENTINEL) {
    return errorResponse(
      'This administrator has already completed account activation.',
      400,
      'INVITE_ALREADY_ACCEPTED'
    );
  }

  const now = new Date().toISOString();
  await env.DB.prepare(
    'UPDATE admin_invitations SET revoked_at = ? WHERE admin_id = ? AND used_at IS NULL AND revoked_at IS NULL'
  )
    .bind(now, target.id)
    .run();

  const inviteId = generateRandomId('inv');
  const rawInviteToken = generateRandomToken(32);
  const inviteTokenHash = await sha256Hex(rawInviteToken);
  const inviteExpiresAt = new Date(Date.now() + ADMIN_INVITE_EXPIRY_SECONDS * 1000).toISOString();

  await env.DB.prepare(
    `INSERT INTO admin_invitations
     (id, admin_id, email, token_hash, invited_by_admin_id, expires_at, used_at, revoked_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)`
  )
    .bind(
      inviteId,
      target.id,
      target.email,
      inviteTokenHash,
      currentAdmin.id,
      inviteExpiresAt,
      now
    )
    .run();

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
    expiresHours: Math.round(ADMIN_INVITE_EXPIRY_SECONDS / 3600),
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
        invitationEmailSent: false,
        deliveryStatus: emailResult.status,
      }
    );
  }

  return successResponse(
    {
      invitationEmailSent: true,
      invitationExpiresAt: inviteExpiresAt,
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

  const passwordHash = await hashPassword(password);
  const now = new Date().toISOString();

  await env.DB.prepare('UPDATE admin_invitations SET used_at = ? WHERE id = ?')
    .bind(now, invite.id)
    .run();
  await env.DB.prepare(
    'UPDATE admin_invitations SET revoked_at = ? WHERE admin_id = ? AND id != ? AND used_at IS NULL AND revoked_at IS NULL'
  )
    .bind(now, invite.admin_id, invite.id)
    .run();

  await env.DB.prepare(
    `UPDATE admins
     SET password_hash = ?, is_active = 1, invite_accepted_at = ?, deactivated_at = NULL, updated_at = ?
     WHERE id = ?`
  )
    .bind(passwordHash, now, now, invite.admin_id)
    .run();

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

  // Prevent demoting the last active super_admin
  if (existing.role === 'super_admin' && existing.is_active && nextRole !== 'super_admin') {
    const activeSuperAdmins = await env.DB.prepare(
      "SELECT COUNT(*) AS cnt FROM admins WHERE role = 'super_admin' AND is_active = 1"
    ).first();
    if (Number(activeSuperAdmins?.cnt || 0) <= 1) {
      return errorResponse(
        'Cannot demote the last active super_admin account.',
        409,
        'LAST_SUPER_ADMIN_PROTECTED'
      );
    }
  }

  const now = new Date().toISOString();
  if (roleChanged) {
    await env.DB.prepare(
      `UPDATE admins
       SET name = ?, role = ?, token_version = COALESCE(token_version, 1) + 1, updated_at = ?
       WHERE id = ?`
    )
      .bind(nextName, nextRole, now, existing.id)
      .run();
    await env.DB.prepare('UPDATE refresh_sessions SET revoked_at = ? WHERE admin_id = ?')
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
    if (existing.role === 'super_admin' && existing.is_active) {
      const activeSuperAdmins = await env.DB.prepare(
        "SELECT COUNT(*) AS cnt FROM admins WHERE role = 'super_admin' AND is_active = 1"
      ).first();
      if (Number(activeSuperAdmins?.cnt || 0) <= 1) {
        return errorResponse(
          'Cannot deactivate the last active super_admin account.',
          409,
          'LAST_SUPER_ADMIN_PROTECTED'
        );
      }
    }

    await env.DB.prepare(
      `UPDATE admins
       SET is_active = 0, deactivated_at = ?, token_version = COALESCE(token_version, 1) + 1, updated_at = ?
       WHERE id = ?`
    )
      .bind(now, now, existing.id)
      .run();

    await env.DB.prepare('UPDATE refresh_sessions SET revoked_at = ? WHERE admin_id = ?')
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
  const revokeRes = await env.DB.prepare(
    'UPDATE refresh_sessions SET revoked_at = ? WHERE admin_id = ? AND revoked_at IS NULL'
  )
    .bind(now, existing.id)
    .run();

  await env.DB.prepare(
    'UPDATE admins SET token_version = COALESCE(token_version, 1) + 1, updated_at = ? WHERE id = ?'
  )
    .bind(now, existing.id)
    .run();

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

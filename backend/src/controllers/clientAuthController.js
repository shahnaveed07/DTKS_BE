import {
  CLIENT_ACCESS_COOKIE_NAME,
  CLIENT_CSRF_COOKIE_NAME,
  CLIENT_EMAIL_VERIFICATION_EXPIRY_SECONDS,
  CLIENT_PASSWORD_RESET_EXPIRY_SECONDS,
  CLIENT_REFRESH_COOKIE_NAME,
  CURRENT_PRIVACY_VERSION,
  CURRENT_TERMS_VERSION,
} from '../config/constants.js';
import {
  generateRandomId,
  generateRandomToken,
  hashPassword,
  verifyPassword,
  verifyPasswordWithMigration,
  signJwt,
  sha256Hex,
} from '../utils/crypto.js';
import { successResponse, errorResponse, parseJsonBody } from '../utils/response.js';
import {
  validateClientRegisterInput,
  validateTokenInput,
  validateLoginInput,
  validateClientProfileUpdate,
  validateChangePasswordInput,
  validateForgotPasswordInput,
  validateResetPasswordInput,
} from '../validators/schemas.js';
import {
  appendCookiesToResponse,
  buildClientAuthCookies,
  clearClientAuthCookies,
  createCsrfToken,
  formatSetCookieHeader,
  getJwtSecret,
  isBearerModeRequested,
  isHttpsRequest,
  parseCookies,
  validateCookieCsrf,
} from '../middleware/authMiddleware.js';
import { isProductionEnv } from '../config/cors.js';
import { getClientIp } from '../middleware/rateLimiter.js';
import { logAdminActivity } from '../services/auditService.js';
import {
  isEmailProviderConfigured,
  sendClientVerificationEmail,
  sendClientPasswordResetEmail,
  sendClientSecurityNotificationEmail,
} from '../services/emailService.js';

function getAccessExpiresSeconds(env) {
  return (
    Number.parseInt(
      env?.JWT_ACCESS_EXPIRES_IN || env?.JWT_ACCESS_EXPIRY_SECONDS || '900',
      10
    ) || 900
  );
}

function getRefreshExpiresSeconds(env) {
  return (
    Number.parseInt(
      env?.JWT_REFRESH_EXPIRES_IN || env?.JWT_REFRESH_EXPIRY_SECONDS || '604800',
      10
    ) || 604800
  );
}

function getVerificationExpirySeconds(env) {
  const configured = Number.parseInt(
    String(env?.CLIENT_EMAIL_VERIFICATION_EXPIRY_SECONDS || ''),
    10
  );
  return Number.isFinite(configured) && configured > 0
    ? configured
    : CLIENT_EMAIL_VERIFICATION_EXPIRY_SECONDS;
}

function getResetExpirySeconds(env) {
  const configured = Number.parseInt(
    String(env?.CLIENT_PASSWORD_RESET_EXPIRY_SECONDS || ''),
    10
  );
  return Number.isFinite(configured) && configured > 0
    ? configured
    : CLIENT_PASSWORD_RESET_EXPIRY_SECONDS;
}

function mapClientResponse(row, lastLoginOverride = null) {
  if (!row) return null;
  const lastLogin = lastLoginOverride || row.last_login_at || null;
  return {
    id: row.id,
    customer_id: row.customer_id || null,
    customerId: row.customer_id || null,
    full_name: row.full_name,
    fullName: row.full_name,
    email: row.email,
    phone: row.phone,
    city: row.city || '',
    business_name: row.business_name || '',
    businessName: row.business_name || '',
    is_email_verified: Boolean(row.is_email_verified),
    isEmailVerified: Boolean(row.is_email_verified),
    email_verified_at: row.email_verified_at || null,
    emailVerifiedAt: row.email_verified_at || null,
    is_active: Boolean(row.is_active),
    isActive: Boolean(row.is_active),
    deactivated_at: row.deactivated_at || null,
    deactivatedAt: row.deactivated_at || null,
    terms_accepted: Boolean(row.terms_accepted),
    termsAccepted: Boolean(row.terms_accepted),
    terms_accepted_at: row.terms_accepted_at || null,
    termsAcceptedAt: row.terms_accepted_at || null,
    terms_version: row.terms_version || '',
    termsVersion: row.terms_version || '',
    privacy_accepted: Boolean(row.privacy_accepted),
    privacyAccepted: Boolean(row.privacy_accepted),
    privacy_accepted_at: row.privacy_accepted_at || null,
    privacyAcceptedAt: row.privacy_accepted_at || null,
    privacy_version: row.privacy_version || '',
    privacyVersion: row.privacy_version || '',
    last_login_at: lastLogin,
    lastLoginAt: lastLogin,
    created_at: row.created_at,
    createdAt: row.created_at,
    updated_at: row.updated_at,
    updatedAt: row.updated_at,
  };
}

export async function getClientCsrfToken(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const existing = cookies[CLIENT_CSRF_COOKIE_NAME];
  const csrfToken =
    typeof existing === 'string' && existing.length >= 32 ? existing : createCsrfToken();
  const refreshExp = getRefreshExpiresSeconds(env);
  const secure = isProductionEnv(env) || isHttpsRequest(request);
  const res = successResponse(
    {
      csrfToken,
      csrf_token: csrfToken,
    },
    'CSRF token issued.'
  );
  return appendCookiesToResponse(res, [
    formatSetCookieHeader(CLIENT_CSRF_COOKIE_NAME, csrfToken, {
      maxAge: refreshExp,
      path: '/api/v1',
      httpOnly: true,
      sameSite: 'Lax',
      secure,
    }),
  ]);
}

export async function registerClient(request, env) {
  const body = await parseJsonBody(request);
  const validation = validateClientRegisterInput(body);
  if (!validation.isValid) {
    return errorResponse(
      'Client registration validation failed.',
      400,
      'VALIDATION_ERROR',
      validation.errors
    );
  }

  const {
    fullName,
    email,
    phone,
    city,
    businessName,
    password,
    termsVersion: requestedTermsVersion,
    privacyVersion: requestedPrivacyVersion,
  } = validation.data;

  const existingAccount = await env.DB.prepare(
    'SELECT id FROM customer_accounts WHERE lower(email) = lower(?)'
  )
    .bind(email)
    .first();

  if (existingAccount) {
    return errorResponse(
      'Unable to complete registration with the provided email address. If you already have an account, please sign in or reset your password.',
      409,
      'REGISTRATION_CONFLICT'
    );
  }

  const passwordHash = await hashPassword(password);
  const now = new Date().toISOString();
  const accountId = generateRandomId('cacc');
  const termsVersion = requestedTermsVersion || env?.TERMS_VERSION || CURRENT_TERMS_VERSION;
  const privacyVersion = requestedPrivacyVersion || env?.PRIVACY_VERSION || CURRENT_PRIVACY_VERSION;
  const acceptedIp = getClientIp(request, env);

  const rawVerifyToken = generateRandomToken(32);
  const verifyTokenHash = await sha256Hex(rawVerifyToken);
  const tokenId = generateRandomId('ctok');
  const verifyExpirySeconds = getVerificationExpirySeconds(env);
  const expiresAt = new Date(Date.now() + verifyExpirySeconds * 1000).toISOString();

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO customer_accounts
         (id, customer_id, full_name, email, phone, city, business_name, password_hash,
          is_email_verified, email_verified_at, is_active, deactivated_at, token_version,
          terms_accepted, terms_accepted_at, terms_version,
          privacy_accepted, privacy_accepted_at, privacy_version, legal_accepted_ip,
          last_login_at, created_at, updated_at)
         VALUES (?, NULL, ?, ?, ?, ?, ?, ?, 0, NULL, 1, NULL, 1, 1, ?, ?, 1, ?, ?, ?, NULL, ?, ?)`
      ).bind(
        accountId,
        fullName,
        email,
        phone,
        city,
        businessName,
        passwordHash,
        now,
        termsVersion,
        now,
        privacyVersion,
        acceptedIp,
        now,
        now
      ),
      env.DB.prepare(
        `INSERT INTO customer_auth_tokens
         (id, customer_account_id, purpose, token_hash, expires_at, used_at, revoked_at, created_at)
         VALUES (?, ?, 'email_verification', ?, ?, NULL, NULL, ?)`
      ).bind(tokenId, accountId, verifyTokenHash, expiresAt, now),
    ]);
  } catch (err) {
    if (/UNIQUE constraint failed/i.test(String(err?.message || ''))) {
      return errorResponse(
        'Unable to complete registration with the provided email address. If you already have an account, please sign in or reset your password.',
        409,
        'REGISTRATION_CONFLICT'
      );
    }
    throw err;
  }

  await logAdminActivity(env, {
    adminId: null,
    action: 'CLIENT_REGISTERED',
    entityType: 'CustomerAccount',
    entityId: accountId,
    details: `New client account registered (${email}) pending email verification (terms v${termsVersion}, privacy v${privacyVersion})`,
    request,
  });

  const emailResult = await sendClientVerificationEmail(env, {
    accountId,
    email,
    fullName,
    verificationToken: rawVerifyToken,
    expiresHours: Math.max(1, Math.round(verifyExpirySeconds / 3600)),
  });

  const createdRow = await env.DB.prepare(
    `SELECT id, customer_id, full_name, email, phone, city, business_name,
            is_email_verified, email_verified_at, is_active, deactivated_at,
            terms_accepted, terms_accepted_at, terms_version,
            privacy_accepted, privacy_accepted_at, privacy_version,
            last_login_at, created_at, updated_at
     FROM customer_accounts WHERE id = ?`
  )
    .bind(accountId)
    .first();

  if (!emailResult.sent) {
    return errorResponse(
      'Your account was created and remains pending email verification, but the verification email could not be delivered right now.',
      503,
      emailResult.status === 'skipped_unconfigured'
        ? 'EMAIL_PROVIDER_UNCONFIGURED'
        : 'EMAIL_DELIVERY_FAILED',
      {
        accountCreated: true,
        accountPendingVerification: true,
        verificationEmailSent: false,
        requiresEmailVerification: true,
        canResendVerification: true,
        deliveryStatus: emailResult.status,
        account: mapClientResponse(createdRow),
      }
    );
  }

  return successResponse(
    {
      registered: true,
      verificationEmailSent: true,
      requiresEmailVerification: true,
      account: mapClientResponse(createdRow),
    },
    'Registration successful. Please check your email to verify your account.',
    201
  );
}

export async function resendClientVerification(request, env) {
  const body = await parseJsonBody(request);
  const validation = validateForgotPasswordInput(body);
  if (!validation.isValid) {
    return errorResponse('Please provide a valid email address.', 400, 'VALIDATION_ERROR', validation.errors);
  }

  if (!isEmailProviderConfigured(env)) {
    return errorResponse(
      'Email delivery service is currently unavailable.',
      503,
      'EMAIL_PROVIDER_UNCONFIGURED'
    );
  }

  const { email } = validation.data;
  const account = await env.DB.prepare(
    'SELECT id, full_name, email, is_email_verified, is_active FROM customer_accounts WHERE lower(email) = lower(?)'
  )
    .bind(email)
    .first();

  if (account && account.is_active && !account.is_email_verified) {
    const now = new Date().toISOString();
    const tokenId = generateRandomId('ctok');
    const rawVerifyToken = generateRandomToken(32);
    const verifyTokenHash = await sha256Hex(rawVerifyToken);
    const verifyExpirySeconds = getVerificationExpirySeconds(env);
    const expiresAt = new Date(Date.now() + verifyExpirySeconds * 1000).toISOString();

    // Insert new token first without revoking existing unused tokens until delivery succeeds
    await env.DB.prepare(
      `INSERT INTO customer_auth_tokens
       (id, customer_account_id, purpose, token_hash, expires_at, used_at, revoked_at, created_at)
       VALUES (?, ?, 'email_verification', ?, ?, NULL, NULL, ?)`
    )
      .bind(tokenId, account.id, verifyTokenHash, expiresAt, now)
      .run();

    let emailResult = {
      sent: false,
      status: 'failed',
      detailMessage: 'Unexpected error dispatching verification email.',
    };
    try {
      emailResult = await sendClientVerificationEmail(env, {
        accountId: account.id,
        email: account.email,
        fullName: account.full_name,
        verificationToken: rawVerifyToken,
        expiresHours: Math.max(1, Math.round(verifyExpirySeconds / 3600)),
      });
    } catch (err) {
      emailResult = {
        sent: false,
        status: 'failed',
        detailMessage: err?.message || 'Unexpected error dispatching verification email.',
      };
    }

    if (emailResult.sent) {
      await env.DB.prepare(
        `UPDATE customer_auth_tokens
         SET revoked_at = ?
         WHERE customer_account_id = ? AND purpose = 'email_verification' AND id != ? AND used_at IS NULL AND revoked_at IS NULL`
      )
        .bind(now, account.id, tokenId)
        .run();

      await logAdminActivity(env, {
        adminId: null,
        action: 'CLIENT_VERIFICATION_RESENT',
        entityType: 'CustomerAccount',
        entityId: account.id,
        details: `Verification email resent for ${account.email}`,
        request,
      });
    } else {
      const revokedAt = new Date().toISOString();
      await env.DB.prepare(
        `UPDATE customer_auth_tokens
         SET revoked_at = ?
         WHERE id = ? AND purpose = 'email_verification' AND used_at IS NULL AND revoked_at IS NULL`
      )
        .bind(revokedAt, tokenId)
        .run();

      await logAdminActivity(env, {
        adminId: null,
        action: 'CLIENT_VERIFICATION_DELIVERY_FAILED',
        entityType: 'CustomerAccount',
        entityId: account.id,
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
    'If an eligible unverified account exists for that email address, a verification email has been sent.'
  );
}

export async function verifyClientEmail(request, env) {
  const body = await parseJsonBody(request);
  const validation = validateTokenInput(body);
  if (!validation.isValid) {
    return errorResponse(
      'Invalid verification token.',
      400,
      'VALIDATION_ERROR',
      validation.errors
    );
  }

  const tokenHash = await sha256Hex(validation.data.token);
  const tokenRow = await env.DB.prepare(
    `SELECT id, customer_account_id, expires_at, used_at, revoked_at
     FROM customer_auth_tokens
     WHERE token_hash = ? AND purpose = 'email_verification'`
  )
    .bind(tokenHash)
    .first();

  if (!tokenRow) {
    return errorResponse('Invalid email verification token.', 400, 'INVALID_VERIFICATION_TOKEN');
  }
  if (tokenRow.used_at || tokenRow.revoked_at) {
    return errorResponse(
      'This email verification token has already been used or revoked.',
      400,
      'VERIFICATION_TOKEN_USED'
    );
  }
  if (new Date(tokenRow.expires_at).getTime() <= Date.now()) {
    return errorResponse(
      'This email verification token has expired. Please request a new verification email.',
      400,
      'VERIFICATION_TOKEN_EXPIRED'
    );
  }

  const account = await env.DB.prepare(
    `SELECT id, customer_id, full_name, email, phone, city, business_name,
            is_email_verified, is_active, created_at
     FROM customer_accounts WHERE id = ?`
  )
    .bind(tokenRow.customer_account_id)
    .first();

  if (!account) {
    return errorResponse('Client account not found.', 404, 'CLIENT_NOT_FOUND');
  }
  if (!account.is_active) {
    return errorResponse('This client account has been deactivated.', 403, 'ACCOUNT_DEACTIVATED');
  }

  const now = new Date().toISOString();

  // Atomically claim the single-use, unrevoked, unexpired token inside SQL
  const claimRes = await env.DB.prepare(
    `UPDATE customer_auth_tokens
     SET used_at = ?
     WHERE id = ?
       AND purpose = 'email_verification'
       AND used_at IS NULL
       AND revoked_at IS NULL
       AND julianday(expires_at) > julianday(?)`
  )
    .bind(now, tokenRow.id, now)
    .run();

  if (Number(claimRes?.meta?.changes || 0) !== 1) {
    const freshToken = await env.DB.prepare(
      'SELECT used_at, revoked_at FROM customer_auth_tokens WHERE id = ?'
    )
      .bind(tokenRow.id)
      .first();

    if (freshToken && !freshToken.used_at && !freshToken.revoked_at) {
      return errorResponse(
        'This email verification token has expired. Please request a new verification email.',
        400,
        'VERIFICATION_TOKEN_EXPIRED'
      );
    }

    return errorResponse(
      'This email verification token has already been used or revoked.',
      400,
      'VERIFICATION_TOKEN_USED'
    );
  }

  try {
    let linkedCustomerId = account.customer_id;
    const statements = [
      env.DB.prepare(
        `UPDATE customer_auth_tokens
         SET revoked_at = ?
         WHERE customer_account_id = ? AND purpose = 'email_verification' AND id != ? AND used_at IS NULL AND revoked_at IS NULL`
      ).bind(now, account.id, tokenRow.id),
    ];

    if (!linkedCustomerId) {
      const existingCustomer = await env.DB.prepare(
        'SELECT id FROM customers WHERE lower(email) = lower(?) LIMIT 1'
      )
        .bind(account.email)
        .first();

      if (existingCustomer) {
        linkedCustomerId = existingCustomer.id;
      } else {
        linkedCustomerId = generateRandomId('cust');
        statements.push(
          env.DB.prepare(
            `INSERT INTO customers (id, full_name, email, phone, city, business_name, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            linkedCustomerId,
            account.full_name,
            account.email,
            account.phone,
            account.city || '',
            account.business_name || '',
            now,
            now
          )
        );
      }

      // Link only pre-registration historical guest orders created before or at registration time
      statements.push(
        env.DB.prepare(
          `UPDATE orders
           SET customer_id = ?
           WHERE customer_id IS NULL
             AND lower(customer_email) = lower(?)
             AND julianday(created_at) <= julianday(?)`
        ).bind(linkedCustomerId, account.email, account.created_at)
      );
    }

    statements.push(
      env.DB.prepare(
        `UPDATE customer_accounts
         SET is_email_verified = 1,
             email_verified_at = COALESCE(email_verified_at, ?),
             customer_id = ?,
             updated_at = ?
         WHERE id = ?`
      ).bind(now, linkedCustomerId, now, account.id)
    );

    await env.DB.batch(statements);

    const updatedAccount = await env.DB.prepare(
      `SELECT id, customer_id, full_name, email, phone, city, business_name,
              is_email_verified, email_verified_at, is_active, deactivated_at,
              terms_accepted, terms_accepted_at, terms_version,
              privacy_accepted, privacy_accepted_at, privacy_version,
              last_login_at, created_at, updated_at
       FROM customer_accounts WHERE id = ?`
    )
      .bind(account.id)
      .first();

    await logAdminActivity(env, {
      adminId: null,
      action: 'CLIENT_EMAIL_VERIFIED',
      entityType: 'CustomerAccount',
      entityId: account.id,
      details: `Verified client email ${account.email} and linked customer record ${linkedCustomerId}`,
      request,
    });

    return successResponse(
      {
        verified: true,
        customerLinked: Boolean(linkedCustomerId),
        account: mapClientResponse(updatedAccount),
      },
      'Email verified successfully. You can now sign in to your client account.'
    );
  } catch (err) {
    await env.DB.prepare('UPDATE customer_auth_tokens SET used_at = NULL WHERE id = ?')
      .bind(tokenRow.id)
      .run()
      .catch(() => {});
    throw err;
  }
}

export async function loginClient(request, env) {
  const body = await parseJsonBody(request);
  const validation = validateLoginInput(body);
  if (!validation.isValid) {
    return errorResponse('Invalid login credentials.', 400, 'VALIDATION_ERROR', validation.errors);
  }

  const { email, password } = validation.data;
  const account = await env.DB.prepare(
    `SELECT id, customer_id, full_name, email, phone, city, business_name,
            password_hash, is_email_verified, email_verified_at, is_active,
            deactivated_at, token_version,
            terms_accepted, terms_accepted_at, terms_version,
            privacy_accepted, privacy_accepted_at, privacy_version,
            last_login_at, created_at, updated_at
     FROM customer_accounts WHERE lower(email) = lower(?)`
  )
    .bind(email)
    .first();

  if (!account) {
    return errorResponse('Invalid email or password.', 401, 'INVALID_CREDENTIALS');
  }

  const verification = await verifyPasswordWithMigration(password, account.password_hash);
  if (!verification.valid) {
    await logAdminActivity(env, {
      adminId: null,
      action: 'CLIENT_LOGIN_FAILED',
      entityType: 'CustomerAccount',
      entityId: account.id,
      details: 'Invalid client password attempt',
      request,
    });
    return errorResponse('Invalid email or password.', 401, 'INVALID_CREDENTIALS');
  }

  if (!account.is_active) {
    return errorResponse(
      'This client account has been deactivated.',
      403,
      'ACCOUNT_DEACTIVATED'
    );
  }

  if (!account.is_email_verified) {
    return errorResponse(
      'Please verify your email address before signing in.',
      403,
      'EMAIL_NOT_VERIFIED'
    );
  }

  const now = new Date().toISOString();
  const accessExp = getAccessExpiresSeconds(env);
  const refreshExp = getRefreshExpiresSeconds(env);
  const tokenVersion = Number(account.token_version ?? 1);

  const accessToken = await signJwt(
    {
      sub: account.id,
      customerId: account.customer_id || null,
      email: account.email,
      accountType: 'client',
      type: 'access',
      tv: tokenVersion,
    },
    getJwtSecret(env),
    accessExp
  );

  const rawRefreshToken = generateRandomToken(32);
  const refreshTokenHash = await sha256Hex(rawRefreshToken);
  const sessionId = generateRandomId('csess');
  const expiresAt = new Date(Date.now() + refreshExp * 1000).toISOString();

  const updateAccountStmt = verification.needsRehash
    ? env.DB.prepare(
        'UPDATE customer_accounts SET password_hash = ?, last_login_at = ?, updated_at = ? WHERE id = ?'
      ).bind(await hashPassword(password), now, now, account.id)
    : env.DB.prepare('UPDATE customer_accounts SET last_login_at = ?, updated_at = ? WHERE id = ?').bind(
        now,
        now,
        account.id
      );

  await env.DB.batch([
    updateAccountStmt,
    env.DB.prepare(
      `INSERT INTO customer_refresh_sessions
       (id, customer_account_id, refresh_token_hash, user_agent, ip_address, expires_at, revoked_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`
    ).bind(
      sessionId,
      account.id,
      refreshTokenHash,
      (request.headers.get('User-Agent') || '').slice(0, 255),
      getClientIp(request, env),
      expiresAt,
      now
    ),
  ]);

  await logAdminActivity(env, {
    adminId: null,
    action: 'CLIENT_LOGIN_SUCCESS',
    entityType: 'CustomerAccount',
    entityId: account.id,
    details: 'Client signed in',
    request,
  });

  const csrfToken = createCsrfToken();
  const bearerMode = isBearerModeRequested(request);

  if (bearerMode) {
    return successResponse(
      {
        authMode: 'bearer',
        accessToken,
        access_token: accessToken,
        refreshToken: rawRefreshToken,
        refresh_token: rawRefreshToken,
        csrfToken,
        csrf_token: csrfToken,
        expiresIn: accessExp,
        expires_in: accessExp,
        client: mapClientResponse(account, now),
      },
      'Authenticated successfully.'
    );
  }

  const res = successResponse(
    {
      authMode: 'cookie',
      csrfToken,
      csrf_token: csrfToken,
      expiresIn: accessExp,
      expires_in: accessExp,
      client: mapClientResponse(account, now),
    },
    'Authenticated successfully.'
  );

  return appendCookiesToResponse(
    res,
    buildClientAuthCookies(request, env, {
      accessToken,
      refreshToken: rawRefreshToken,
      csrfToken,
      accessMaxAge: accessExp,
      refreshMaxAge: refreshExp,
    })
  );
}

export async function refreshClientToken(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const body = await parseJsonBody(request);
  const rawBodyToken =
    typeof (body.refreshToken || body.refresh_token) === 'string'
      ? (body.refreshToken || body.refresh_token).trim()
      : '';
  const cookieToken = String(cookies[CLIENT_REFRESH_COOKIE_NAME] || '').trim();
  const usedCookieRefresh = !rawBodyToken && Boolean(cookieToken);

  if (usedCookieRefresh) {
    const csrfOk = await validateCookieCsrf(request, cookies, CLIENT_CSRF_COOKIE_NAME);
    if (!csrfOk) {
      return errorResponse(
        'CSRF token validation failed for cookie-authenticated request.',
        403,
        'CSRF_VALIDATION_FAILED'
      );
    }
  }

  const rawToken = rawBodyToken || cookieToken;
  if (!rawToken) {
    return errorResponse('Refresh token is required.', 400, 'MISSING_REFRESH_TOKEN');
  }

  const tokenHash = await sha256Hex(rawToken);
  const session = await env.DB.prepare(
    'SELECT id, customer_account_id, expires_at, revoked_at, revoke_reason FROM customer_refresh_sessions WHERE refresh_token_hash = ?'
  )
    .bind(tokenHash)
    .first();

  if (!session) {
    return errorResponse('Invalid or revoked refresh token.', 401, 'INVALID_REFRESH_TOKEN');
  }

  if (session.revoked_at) {
    if (session.revoke_reason === 'rotated') {
      const replayNow = new Date().toISOString();
      await env.DB.batch([
        env.DB.prepare(
          "UPDATE customer_refresh_sessions SET revoked_at = ?, revoke_reason = 'replay_detected' WHERE customer_account_id = ? AND revoked_at IS NULL"
        ).bind(replayNow, session.customer_account_id),
        env.DB.prepare(
          'UPDATE customer_accounts SET token_version = COALESCE(token_version, 1) + 1, updated_at = ? WHERE id = ?'
        ).bind(replayNow, session.customer_account_id),
      ]);
      await logAdminActivity(env, {
        adminId: null,
        action: 'CLIENT_REFRESH_REPLAY_DETECTED',
        entityType: 'CustomerAccount',
        entityId: session.customer_account_id,
        details: 'Detected reuse of rotated client refresh token; revoked all active client sessions.',
        request,
      });
      const replayRes = errorResponse(
        'Refresh token reuse detected. All client sessions have been revoked for security.',
        401,
        'REFRESH_TOKEN_REPLAY_DETECTED'
      );
      return appendCookiesToResponse(replayRes, clearClientAuthCookies(request, env));
    }

    return errorResponse('Invalid or revoked refresh token.', 401, 'INVALID_REFRESH_TOKEN');
  }

  if (new Date(session.expires_at).getTime() <= Date.now()) {
    await env.DB.prepare('DELETE FROM customer_refresh_sessions WHERE id = ?')
      .bind(session.id)
      .run();
    return errorResponse(
      'Refresh token has expired. Please sign in again.',
      401,
      'REFRESH_TOKEN_EXPIRED'
    );
  }

  const account = await env.DB.prepare(
    `SELECT id, customer_id, full_name, email, phone, city, business_name,
            is_email_verified, email_verified_at, is_active, deactivated_at,
            terms_accepted, terms_accepted_at, terms_version,
            privacy_accepted, privacy_accepted_at, privacy_version,
            token_version, last_login_at, created_at, updated_at
     FROM customer_accounts WHERE id = ?`
  )
    .bind(session.customer_account_id)
    .first();

  if (!account || !account.is_active) {
    await env.DB.prepare('DELETE FROM customer_refresh_sessions WHERE id = ?')
      .bind(session.id)
      .run();
    return errorResponse('Client account is not active.', 403, 'ACCOUNT_DEACTIVATED');
  }

  if (!account.is_email_verified) {
    return errorResponse('Client email is not verified.', 403, 'EMAIL_NOT_VERIFIED');
  }

  const now = new Date().toISOString();
  // Atomically claim the refresh token with revoke_reason = 'rotated' for replay detection
  const claimSession = await env.DB.prepare(
    "UPDATE customer_refresh_sessions SET revoked_at = ?, revoke_reason = 'rotated' WHERE id = ? AND revoked_at IS NULL"
  )
    .bind(now, session.id)
    .run();

  if (Number(claimSession?.meta?.changes || 0) !== 1) {
    await env.DB.batch([
      env.DB.prepare(
        "UPDATE customer_refresh_sessions SET revoked_at = ?, revoke_reason = 'replay_detected' WHERE customer_account_id = ? AND revoked_at IS NULL"
      ).bind(now, session.customer_account_id),
      env.DB.prepare(
        'UPDATE customer_accounts SET token_version = COALESCE(token_version, 1) + 1, updated_at = ? WHERE id = ?'
      ).bind(now, session.customer_account_id),
    ]);
    const replayRes = errorResponse(
      'Refresh token reuse detected. All client sessions have been revoked for security.',
      401,
      'REFRESH_TOKEN_REPLAY_DETECTED'
    );
    return appendCookiesToResponse(replayRes, clearClientAuthCookies(request, env));
  }

  const accessExp = getAccessExpiresSeconds(env);
  const refreshExp = getRefreshExpiresSeconds(env);
  const tokenVersion = Number(account.token_version ?? 1);

  const newAccessToken = await signJwt(
    {
      sub: account.id,
      customerId: account.customer_id || null,
      email: account.email,
      accountType: 'client',
      type: 'access',
      tv: tokenVersion,
    },
    getJwtSecret(env),
    accessExp
  );

  const newRawRefreshToken = generateRandomToken(32);
  const newRefreshTokenHash = await sha256Hex(newRawRefreshToken);
  const newSessionId = generateRandomId('csess');
  const newExpiresAt = new Date(Date.now() + refreshExp * 1000).toISOString();

  await env.DB.prepare(
    `INSERT INTO customer_refresh_sessions
     (id, customer_account_id, refresh_token_hash, user_agent, ip_address, expires_at, revoked_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`
  )
    .bind(
      newSessionId,
      account.id,
      newRefreshTokenHash,
      (request.headers.get('User-Agent') || '').slice(0, 255),
      getClientIp(request, env),
      newExpiresAt,
      now
    )
    .run();

  const csrfToken = createCsrfToken();
  const bearerMode = isBearerModeRequested(request);

  if (bearerMode) {
    return successResponse(
      {
        authMode: 'bearer',
        accessToken: newAccessToken,
        access_token: newAccessToken,
        refreshToken: newRawRefreshToken,
        refresh_token: newRawRefreshToken,
        csrfToken,
        csrf_token: csrfToken,
        expiresIn: accessExp,
        expires_in: accessExp,
        client: mapClientResponse(account),
      },
      'Session token refreshed.'
    );
  }

  const res = successResponse(
    {
      authMode: 'cookie',
      csrfToken,
      csrf_token: csrfToken,
      expiresIn: accessExp,
      expires_in: accessExp,
      client: mapClientResponse(account),
    },
    'Session token refreshed.'
  );

  return appendCookiesToResponse(
    res,
    buildClientAuthCookies(request, env, {
      accessToken: newAccessToken,
      refreshToken: newRawRefreshToken,
      csrfToken,
      accessMaxAge: accessExp,
      refreshMaxAge: refreshExp,
    })
  );
}

export async function logoutClient(request, env, currentClient) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const authHeader = request.headers.get('Authorization') || '';
  const hasBearer = authHeader.startsWith('Bearer ');
  const hasClientCookie = Boolean(
    cookies[CLIENT_ACCESS_COOKIE_NAME] || cookies[CLIENT_REFRESH_COOKIE_NAME]
  );

  if (!hasBearer && hasClientCookie) {
    const csrfOk = await validateCookieCsrf(request, cookies, CLIENT_CSRF_COOKIE_NAME);
    if (!csrfOk) {
      return errorResponse(
        'CSRF token validation failed for cookie-authenticated request.',
        403,
        'CSRF_VALIDATION_FAILED'
      );
    }
  }

  const body = await parseJsonBody(request);
  const rawAllDevices =
    body.allDevices !== undefined ? body.allDevices : body.all_devices;

  if (rawAllDevices !== undefined && typeof rawAllDevices !== 'boolean') {
    return errorResponse('Invalid logout options.', 400, 'VALIDATION_ERROR', {
      allDevices: 'allDevices must be a boolean.',
    });
  }

  const allDevices = rawAllDevices === true;
  const rawBodyToken =
    typeof (body.refreshToken || body.refresh_token) === 'string'
      ? (body.refreshToken || body.refresh_token).trim()
      : '';
  const rawToken = rawBodyToken || String(cookies[CLIENT_REFRESH_COOKIE_NAME] || '').trim();

  if (allDevices && !currentClient?.id) {
    return errorResponse(
      'Authenticated session is required to log out from all devices.',
      401,
      'UNAUTHORIZED'
    );
  }

  if (!rawToken && !currentClient?.id) {
    return errorResponse(
      'Authentication or refresh token is required to log out.',
      401,
      'UNAUTHORIZED'
    );
  }

  const now = new Date().toISOString();
  let sessionsRevoked = 0;
  let scope = 'single_device';

  if (allDevices || (!rawToken && currentClient?.id)) {
    scope = 'all_devices';
    const [revokeRes] = await env.DB.batch([
      env.DB.prepare(
        "UPDATE customer_refresh_sessions SET revoked_at = ?, revoke_reason = 'logout_all' WHERE customer_account_id = ? AND revoked_at IS NULL"
      ).bind(now, currentClient.id),
      env.DB.prepare(
        'UPDATE customer_accounts SET token_version = COALESCE(token_version, 1) + 1, updated_at = ? WHERE id = ?'
      ).bind(now, currentClient.id),
    ]);
    sessionsRevoked = Number(revokeRes?.meta?.changes || 0);
  } else if (rawToken) {
    const hash = await sha256Hex(rawToken);
    const revokeRes = currentClient?.id
      ? await env.DB.prepare(
          "UPDATE customer_refresh_sessions SET revoked_at = ?, revoke_reason = 'logout' WHERE refresh_token_hash = ? AND customer_account_id = ? AND revoked_at IS NULL"
        )
          .bind(now, hash, currentClient.id)
          .run()
      : await env.DB.prepare(
          "UPDATE customer_refresh_sessions SET revoked_at = ?, revoke_reason = 'logout' WHERE refresh_token_hash = ? AND revoked_at IS NULL"
        )
          .bind(now, hash)
          .run();
    sessionsRevoked = Number(revokeRes?.meta?.changes || 0);
  }

  if (currentClient?.id) {
    await logAdminActivity(env, {
      adminId: null,
      action: scope === 'all_devices' ? 'CLIENT_LOGOUT_ALL_DEVICES' : 'CLIENT_LOGOUT',
      entityType: 'CustomerAccount',
      entityId: currentClient.id,
      details:
        scope === 'all_devices'
          ? 'Client signed out from all devices and invalidated active access tokens'
          : 'Client signed out from current session',
      request,
    });
  }

  const res = successResponse(
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

  return appendCookiesToResponse(res, clearClientAuthCookies(request, env));
}

export async function getAuthenticatedClient(request, env, client) {
  return successResponse({ client }, 'Authenticated client profile.');
}

export async function updateClientProfile(request, env, client) {
  const body = await parseJsonBody(request);
  const validation = validateClientProfileUpdate(body);
  if (!validation.isValid) {
    return errorResponse(
      'Client profile validation failed.',
      400,
      'VALIDATION_ERROR',
      validation.errors
    );
  }

  const nextFullName =
    validation.data.fullName !== undefined ? validation.data.fullName : client.fullName;
  const nextPhone = validation.data.phone !== undefined ? validation.data.phone : client.phone;
  const nextCity = validation.data.city !== undefined ? validation.data.city : client.city;
  const nextBusinessName =
    validation.data.businessName !== undefined
      ? validation.data.businessName
      : client.businessName;

  const now = new Date().toISOString();
  const statements = [
    env.DB.prepare(
      `UPDATE customer_accounts
       SET full_name = ?, phone = ?, city = ?, business_name = ?, updated_at = ?
       WHERE id = ?`
    ).bind(nextFullName, nextPhone, nextCity, nextBusinessName, now, client.id),
  ];

  if (client.customerId) {
    statements.push(
      env.DB.prepare(
        `UPDATE customers
         SET full_name = ?, phone = ?, city = ?, business_name = ?, updated_at = ?
         WHERE id = ?`
      ).bind(nextFullName, nextPhone, nextCity, nextBusinessName, now, client.customerId)
    );
  }

  await env.DB.batch(statements);

  const updatedRow = await env.DB.prepare(
    `SELECT id, customer_id, full_name, email, phone, city, business_name,
            is_email_verified, email_verified_at, is_active, deactivated_at,
            terms_accepted, terms_accepted_at, terms_version,
            privacy_accepted, privacy_accepted_at, privacy_version,
            last_login_at, created_at, updated_at
     FROM customer_accounts WHERE id = ?`
  )
    .bind(client.id)
    .first();

  await logAdminActivity(env, {
    adminId: null,
    action: 'CLIENT_PROFILE_UPDATED',
    entityType: 'CustomerAccount',
    entityId: client.id,
    details: `Client ${client.email} updated profile`,
    request,
  });

  return successResponse({ client: mapClientResponse(updatedRow) }, 'Client profile updated.');
}

export async function changeClientPassword(request, env, client) {
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
  const row = await env.DB.prepare(
    'SELECT id, full_name, email, password_hash FROM customer_accounts WHERE id = ?'
  )
    .bind(client.id)
    .first();

  if (!row) {
    return errorResponse('Client account not found.', 404, 'NOT_FOUND');
  }

  const matches = await verifyPassword(currentPassword, row.password_hash);
  if (!matches) {
    return errorResponse('Current password is incorrect.', 401, 'INVALID_CURRENT_PASSWORD');
  }

  const newHash = await hashPassword(newPassword);
  const now = new Date().toISOString();

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE customer_accounts
       SET password_hash = ?, token_version = COALESCE(token_version, 1) + 1, updated_at = ?
       WHERE id = ?`
    ).bind(newHash, now, client.id),
    env.DB.prepare(
      "UPDATE customer_refresh_sessions SET revoked_at = ?, revoke_reason = 'password_changed' WHERE customer_account_id = ? AND revoked_at IS NULL"
    ).bind(now, client.id),
  ]);

  await logAdminActivity(env, {
    adminId: null,
    action: 'CLIENT_PASSWORD_CHANGED',
    entityType: 'CustomerAccount',
    entityId: client.id,
    details: 'Client changed password and revoked active sessions',
    request,
  });

  try {
    await sendClientSecurityNotificationEmail(env, {
      accountId: row.id,
      email: row.email,
      fullName: row.full_name,
      eventTitle: 'Your DTKS password was changed',
      eventDescription:
        'Your DreamTech Kashmir Solutions client account password was recently updated and all active sessions were signed out.',
    });
  } catch {
    // Non-blocking security notification
  }

  return appendCookiesToResponse(
    successResponse({ updated: true }, 'Password changed successfully.'),
    clearClientAuthCookies(request, env)
  );
}

export async function forgotClientPassword(request, env) {
  const body = await parseJsonBody(request);
  const validation = validateForgotPasswordInput(body);
  if (!validation.isValid) {
    return errorResponse('Please provide a valid email address.', 400, 'VALIDATION_ERROR', validation.errors);
  }

  // Uniform provider availability check before DB lookup to avoid enumeration
  if (!isEmailProviderConfigured(env)) {
    return errorResponse(
      'Password reset email delivery is currently unavailable.',
      503,
      'EMAIL_PROVIDER_UNCONFIGURED'
    );
  }

  const { email } = validation.data;
  const account = await env.DB.prepare(
    'SELECT id, full_name, email, is_email_verified, is_active FROM customer_accounts WHERE lower(email) = lower(?)'
  )
    .bind(email)
    .first();

  if (account && account.is_active && account.is_email_verified) {
    const now = new Date().toISOString();
    const tokenId = generateRandomId('ctok');
    const rawResetToken = generateRandomToken(32);
    const resetTokenHash = await sha256Hex(rawResetToken);
    const resetExpirySeconds = getResetExpirySeconds(env);
    const expiresAt = new Date(Date.now() + resetExpirySeconds * 1000).toISOString();

    // Insert new token first without revoking existing unused tokens until delivery succeeds
    await env.DB.prepare(
      `INSERT INTO customer_auth_tokens
       (id, customer_account_id, purpose, token_hash, expires_at, used_at, revoked_at, created_at)
       VALUES (?, ?, 'password_reset', ?, ?, NULL, NULL, ?)`
    )
      .bind(tokenId, account.id, resetTokenHash, expiresAt, now)
      .run();

    let emailResult = {
      sent: false,
      status: 'failed',
      detailMessage: 'Unexpected error dispatching password reset email.',
    };
    try {
      emailResult = await sendClientPasswordResetEmail(env, {
        accountId: account.id,
        email: account.email,
        fullName: account.full_name,
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
        `UPDATE customer_auth_tokens
         SET revoked_at = ?
         WHERE customer_account_id = ? AND purpose = 'password_reset' AND id != ? AND used_at IS NULL AND revoked_at IS NULL`
      )
        .bind(now, account.id, tokenId)
        .run();

      await logAdminActivity(env, {
        adminId: null,
        action: 'CLIENT_PASSWORD_RESET_REQUESTED',
        entityType: 'CustomerAccount',
        entityId: account.id,
        details: `Password reset requested for ${account.email}`,
        request,
      });
    } else {
      const revokedAt = new Date().toISOString();
      await env.DB.prepare(
        `UPDATE customer_auth_tokens
         SET revoked_at = ?
         WHERE id = ? AND purpose = 'password_reset' AND used_at IS NULL AND revoked_at IS NULL`
      )
        .bind(revokedAt, tokenId)
        .run();

      await logAdminActivity(env, {
        adminId: null,
        action: 'CLIENT_PASSWORD_RESET_DELIVERY_FAILED',
        entityType: 'CustomerAccount',
        entityId: account.id,
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
    'If an eligible account exists for that email address, a password reset email has been sent.'
  );
}

export async function resetClientPassword(request, env) {
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
    `SELECT id, customer_account_id, expires_at, used_at, revoked_at
     FROM customer_auth_tokens
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
  if (new Date(tokenRow.expires_at).getTime() <= Date.now()) {
    return errorResponse(
      'This password reset token has expired. Please request a new password reset.',
      400,
      'RESET_TOKEN_EXPIRED'
    );
  }

  const account = await env.DB.prepare(
    'SELECT id, full_name, email, is_active, is_email_verified FROM customer_accounts WHERE id = ?'
  )
    .bind(tokenRow.customer_account_id)
    .first();

  if (!account) {
    return errorResponse('Client account not found.', 404, 'CLIENT_NOT_FOUND');
  }
  if (!account.is_active) {
    return errorResponse('Client account is not active.', 403, 'ACCOUNT_DEACTIVATED');
  }
  if (!account.is_email_verified) {
    return errorResponse(
      'Please verify your email address before resetting your password.',
      403,
      'EMAIL_NOT_VERIFIED'
    );
  }

  const newHash = await hashPassword(password);
  const now = new Date().toISOString();

  // Atomically claim the single-use, unrevoked, unexpired reset token inside SQL
  const claimRes = await env.DB.prepare(
    `UPDATE customer_auth_tokens
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
      'SELECT used_at, revoked_at FROM customer_auth_tokens WHERE id = ?'
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
        `UPDATE customer_auth_tokens
         SET revoked_at = ?
         WHERE customer_account_id = ? AND purpose = 'password_reset' AND id != ? AND used_at IS NULL AND revoked_at IS NULL`
      ).bind(now, account.id, tokenRow.id),
      env.DB.prepare(
        `UPDATE customer_accounts
         SET password_hash = ?, token_version = COALESCE(token_version, 1) + 1, updated_at = ?
         WHERE id = ?`
      ).bind(newHash, now, account.id),
      env.DB.prepare(
        "UPDATE customer_refresh_sessions SET revoked_at = ?, revoke_reason = 'password_reset' WHERE customer_account_id = ? AND revoked_at IS NULL"
      ).bind(now, account.id),
    ]);
  } catch (err) {
    await env.DB.prepare('UPDATE customer_auth_tokens SET used_at = NULL WHERE id = ?')
      .bind(tokenRow.id)
      .run()
      .catch(() => {});
    throw err;
  }

  await logAdminActivity(env, {
    adminId: null,
    action: 'CLIENT_PASSWORD_RESET_COMPLETED',
    entityType: 'CustomerAccount',
    entityId: account.id,
    details: `Password reset completed for ${account.email}`,
    request,
  });

  try {
    await sendClientSecurityNotificationEmail(env, {
      accountId: account.id,
      email: account.email,
      fullName: account.full_name,
      eventTitle: 'Your DTKS password has been reset',
      eventDescription:
        'Your DreamTech Kashmir Solutions client account password was reset using a one-time reset token and all existing sessions were revoked.',
    });
  } catch {
    // Non-blocking security notification
  }

  return successResponse(
    { reset: true },
    'Password has been reset successfully. You can now sign in with your new password.'
  );
}

export async function deactivateClientAccount(request, env, client) {
  const body = await parseJsonBody(request);
  const password =
    typeof (body.password ?? body.currentPassword ?? body.current_password) === 'string'
      ? body.password ?? body.currentPassword ?? body.current_password
      : '';

  if (!password) {
    return errorResponse(
      'Current password confirmation is required to deactivate your account.',
      400,
      'VALIDATION_ERROR',
      { password: 'Password is required.' }
    );
  }

  const row = await env.DB.prepare(
    'SELECT id, full_name, email, password_hash FROM customer_accounts WHERE id = ?'
  )
    .bind(client.id)
    .first();

  if (!row) {
    return errorResponse('Client account not found.', 404, 'NOT_FOUND');
  }

  const matches = await verifyPassword(password, row.password_hash);
  if (!matches) {
    return errorResponse('Password is incorrect.', 401, 'INVALID_CREDENTIALS');
  }

  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE customer_accounts
       SET is_active = 0, deactivated_at = ?, token_version = COALESCE(token_version, 1) + 1, updated_at = ?
       WHERE id = ?`
    ).bind(now, now, client.id),
    env.DB.prepare(
      "UPDATE customer_refresh_sessions SET revoked_at = ?, revoke_reason = 'account_deactivated' WHERE customer_account_id = ? AND revoked_at IS NULL"
    ).bind(now, client.id),
  ]);

  await logAdminActivity(env, {
    adminId: null,
    action: 'CLIENT_ACCOUNT_DEACTIVATED',
    entityType: 'CustomerAccount',
    entityId: client.id,
    details: `Client account ${row.email} deactivated and sessions revoked`,
    request,
  });

  try {
    await sendClientSecurityNotificationEmail(env, {
      accountId: row.id,
      email: row.email,
      fullName: row.full_name,
      eventTitle: 'Your DTKS client account was deactivated',
      eventDescription:
        'Your DreamTech Kashmir Solutions client account has been deactivated and all active sessions have been signed out.',
    });
  } catch {
    // Non-blocking security notification
  }

  return appendCookiesToResponse(
    successResponse(
      { deactivated: true },
      'Your client account has been deactivated and all active sessions have been revoked.'
    ),
    clearClientAuthCookies(request, env)
  );
}

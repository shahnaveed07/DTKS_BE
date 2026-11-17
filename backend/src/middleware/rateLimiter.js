import { errorResponse } from '../utils/response.js';
import { hmacSha256Hex } from '../utils/crypto.js';
import { getJwtSecret } from './authMiddleware.js';

/**
 * Distributed Sliding-Window Rate Limiter (Cloudflare D1 + Native Rate Limiting Binding)
 *
 * Production Order of Precedence:
 *   1. Cloudflare Native Rate Limiting binding (`env.ADMIN_RESET_RATE_LIMITER` for admin
 *      password recovery or `env.RATE_LIMITER`), if bound.
 *   2. Cloudflare D1 Distributed `rate_limits` table (`env.DB`), shared across all Worker isolates.
 *   3. Local in-memory Map fallback (non-sensitive endpoints or non-production only).
 *      Sensitive Admin password-recovery policies FAIL CLOSED (`503 RATE_LIMITER_UNAVAILABLE`)
 *      in production when distributed backing is unavailable or fails.
 */

const memoryBuckets = new Map();
const initializedDbs = new WeakSet();

export const RATE_LIMIT_POLICIES = {
  authLogin: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 10,
    failClosedInProd: true,
    message: 'Too many login attempts. Please wait 15 minutes before trying again.',
  },
  authRefresh: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 30,
    failClosedInProd: true,
    message: 'Too many token refresh requests. Please wait a few minutes before trying again.',
  },
  clientRegister: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 10,
    failClosedInProd: true,
    message: 'Too many registration attempts. Please wait 15 minutes before trying again.',
  },
  clientRegisterEmail: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5,
    failClosedInProd: true,
    message: 'Too many registration attempts for this email address. Please wait 15 minutes before trying again.',
  },
  clientVerifyEmail: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 15,
    failClosedInProd: true,
    message: 'Too many email verification attempts. Please wait 15 minutes before trying again.',
  },
  clientVerificationEmail: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5,
    failClosedInProd: true,
    message: 'Too many verification email requests for this email address. Please wait 15 minutes before trying again.',
  },
  clientVerificationToken: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 8,
    failClosedInProd: true,
    message: 'Too many verification attempts for this verification token. Please wait 15 minutes before trying again.',
  },
  clientPasswordReset: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 8,
    failClosedInProd: true,
    message: 'Too many password reset requests. Please wait 15 minutes before trying again.',
  },
  clientPasswordResetEmail: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5,
    failClosedInProd: true,
    message: 'Too many password reset requests for this email address. Please wait 15 minutes before trying again.',
  },
  clientPasswordResetToken: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 8,
    failClosedInProd: true,
    message: 'Too many password reset attempts for this reset token. Please request a new reset link or wait 15 minutes.',
  },
  passwordReset: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 8,
    failClosedInProd: true,
    message: 'Too many password reset requests. Please wait 15 minutes before trying again.',
  },
  adminPasswordReset: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 8,
    failClosedInProd: true,
    nativeBinding: 'ADMIN_RESET_RATE_LIMITER',
    message: 'Too many administrator password reset requests. Please wait 15 minutes before trying again.',
  },
  adminPasswordResetEmail: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5,
    failClosedInProd: true,
    nativeBinding: 'ADMIN_RESET_RATE_LIMITER',
    message:
      'Too many administrator password reset requests for this email address. Please wait 15 minutes before trying again.',
  },
  adminPasswordResetToken: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 8,
    failClosedInProd: true,
    nativeBinding: 'ADMIN_RESET_RATE_LIMITER',
    message:
      'Too many password reset attempts for this reset token. Please request a new reset link or wait 15 minutes.',
  },
  adminInvite: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 20,
    failClosedInProd: true,
    message: 'Too many invitation requests. Please wait 15 minutes before trying again.',
  },
  orderTracking: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 20,
    failClosedInProd: true,
    message: 'Too many order tracking requests. Please wait 15 minutes before trying again.',
  },
  orderTrackingToken: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 15,
    failClosedInProd: true,
    message: 'Too many tracking requests for this order token. Please wait 15 minutes before trying again.',
  },
  orderTrackingResend: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 8,
    failClosedInProd: true,
    message: 'Too many tracking link resend requests. Please wait 15 minutes before trying again.',
  },
  orderTrackingResendEmail: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5,
    failClosedInProd: true,
    message:
      'Too many tracking link resend requests for this email address. Please wait 15 minutes before trying again.',
  },
  orderTrackingResendOrder: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5,
    failClosedInProd: true,
    message:
      'Too many tracking link resend requests for this order number. Please wait 15 minutes before trying again.',
  },
  publicSubmission: {
    windowMs: 10 * 60 * 1000, // 10 minutes
    maxRequests: 15,
    failClosedInProd: true,
    message: 'Submission rate limit exceeded. Please wait a few minutes before submitting again.',
  },
  generalApi: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 240,
    message: 'Too many requests. Please slow down.',
  },
};

function parsePositiveInt(raw, fallback) {
  const num = Number.parseInt(String(raw ?? ''), 10);
  return Number.isFinite(num) && num > 0 ? num : fallback;
}

function isProductionEnv(env) {
  return String(env?.ENVIRONMENT || '').toLowerCase() === 'production';
}

export function getAdminResetRateLimitConfig(env = {}) {
  const windowSeconds = parsePositiveInt(
    env?.ADMIN_PASSWORD_RESET_WINDOW_SECONDS ?? env?.ADMIN_RESET_WINDOW_SECONDS,
    900
  );
  return {
    windowMs: windowSeconds * 1000,
    ipMax: parsePositiveInt(
      env?.ADMIN_PASSWORD_RESET_IP_MAX ?? env?.ADMIN_RESET_IP_MAX,
      RATE_LIMIT_POLICIES.adminPasswordReset.maxRequests
    ),
    emailMax: parsePositiveInt(
      env?.ADMIN_PASSWORD_RESET_EMAIL_MAX ?? env?.ADMIN_RESET_EMAIL_MAX,
      RATE_LIMIT_POLICIES.adminPasswordResetEmail.maxRequests
    ),
    tokenMax: parsePositiveInt(
      env?.ADMIN_PASSWORD_RESET_TOKEN_MAX ?? env?.ADMIN_RESET_TOKEN_MAX,
      RATE_LIMIT_POLICIES.adminPasswordResetToken.maxRequests
    ),
  };
}

function resolveEffectivePolicy(policyName, env) {
  const base = RATE_LIMIT_POLICIES[policyName] || RATE_LIMIT_POLICIES.generalApi;
  if (
    policyName === 'adminPasswordReset' ||
    policyName === 'adminPasswordResetEmail' ||
    policyName === 'adminPasswordResetToken'
  ) {
    const cfg = getAdminResetRateLimitConfig(env);
    const maxRequests =
      policyName === 'adminPasswordReset'
        ? cfg.ipMax
        : policyName === 'adminPasswordResetEmail'
        ? cfg.emailMax
        : cfg.tokenMax;
    return {
      ...base,
      windowMs: cfg.windowMs,
      maxRequests,
    };
  }
  return base;
}

function getRateLimitHmacSecret(env = {}) {
  const dedicated =
    typeof env?.RATE_LIMIT_HMAC_SECRET === 'string' ? env.RATE_LIMIT_HMAC_SECRET.trim() : '';
  if (dedicated.length >= 16) return dedicated;
  return getJwtSecret(env);
}

export async function buildRateLimitIdentifierHmac(domain, value, env = {}) {
  const secret = getRateLimitHmacSecret(env);
  return hmacSha256Hex(`${domain}:${String(value || '')}`, secret);
}

export function getClientIp(request, env = null) {
  const cfIp = request.headers.get('CF-Connecting-IP')?.trim();
  if (cfIp) return cfIp;

  if (isProductionEnv(env)) {
    // Never trust client-supplied X-Forwarded-For ahead of Cloudflare headers in production
    return request.headers.get('X-Real-IP')?.trim() || '0.0.0.0';
  }

  return (
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    request.headers.get('X-Real-IP')?.trim() ||
    '127.0.0.1'
  );
}

async function ensureRateLimitsTable(db) {
  if (!db || initializedDbs.has(db)) return;
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS rate_limits (
         rate_key TEXT PRIMARY KEY,
         window_start INTEGER NOT NULL,
         request_count INTEGER NOT NULL DEFAULT 1,
         expires_at INTEGER NOT NULL
       )`
    )
    .run();
  initializedDbs.add(db);
}

function buildRateLimitResponse(policy, resetSeconds) {
  return {
    allowed: false,
    response: errorResponse(
      policy.message,
      429,
      'RATE_LIMIT_EXCEEDED',
      { retryAfterSeconds: resetSeconds },
      {
        'Retry-After': String(resetSeconds),
        'X-RateLimit-Limit': String(policy.maxRequests),
        'X-RateLimit-Remaining': '0',
      }
    ),
  };
}

function buildRateLimiterUnavailableResponse() {
  return {
    allowed: false,
    response: errorResponse(
      'Rate limiting protection is temporarily unavailable for this security-sensitive operation. Please try again shortly.',
      503,
      'RATE_LIMITER_UNAVAILABLE'
    ),
  };
}

export async function checkRateLimit(
  request,
  policyName = 'generalApi',
  env = null,
  customKeySuffix = '',
  options = {}
) {
  const policy = resolveEffectivePolicy(policyName, env);
  const includeIp = options?.includeIp !== false;
  const failClosed = Boolean(policy.failClosedInProd || options?.failClosed);
  const ip = includeIp ? getClientIp(request, env) : '';
  const key = includeIp
    ? `${policyName}:${ip}${customKeySuffix ? `:${customKeySuffix}` : ''}`
    : `${policyName}:${customKeySuffix || getClientIp(request, env)}`;
  const now = Date.now();

  let nativeLimiterSucceeded = false;
  let dbFailed = false;

  // 1. Optional Cloudflare Native Rate Limiting Binding
  const nativeBinding =
    policy.nativeBinding === 'ADMIN_RESET_RATE_LIMITER'
      ? env?.ADMIN_RESET_RATE_LIMITER || env?.RATE_LIMITER
      : env?.RATE_LIMITER;

  if (nativeBinding && typeof nativeBinding.limit === 'function') {
    try {
      const outcome = await nativeBinding.limit({ key });
      if (outcome && outcome.success === false) {
        const resetSeconds = Math.ceil(policy.windowMs / 1000);
        return buildRateLimitResponse(policy, resetSeconds);
      }
      nativeLimiterSucceeded = true;
    } catch (err) {
      console.error('[DTKS RateLimiter Warning]: Native rate limiter binding error:', err?.message || err);
    }
  }

  // 2. Distributed Cloudflare D1 Rate Limiting across Worker isolates (atomic single-statement upsert)
  if (env?.DB) {
    try {
      await ensureRateLimitsTable(env.DB);
      const expiresAt = now + policy.windowMs;

      // Probabilistic pruning of expired rows (~2% of requests)
      if (Math.random() < 0.02) {
        await env.DB.prepare('DELETE FROM rate_limits WHERE expires_at <= ?')
          .bind(now)
          .run()
          .catch(() => {});
      }

      const row = await env.DB.prepare(
        `INSERT INTO rate_limits (rate_key, window_start, request_count, expires_at)
         VALUES (?, ?, 1, ?)
         ON CONFLICT(rate_key) DO UPDATE SET
           window_start = CASE
             WHEN rate_limits.expires_at <= excluded.window_start THEN excluded.window_start
             ELSE rate_limits.window_start
           END,
           request_count = CASE
             WHEN rate_limits.expires_at <= excluded.window_start THEN 1
             ELSE rate_limits.request_count + 1
           END,
           expires_at = CASE
             WHEN rate_limits.expires_at <= excluded.window_start THEN excluded.expires_at
             ELSE rate_limits.expires_at
           END
         RETURNING window_start, request_count`
      )
        .bind(key, now, expiresAt)
        .first();

      const windowStart = Number(row?.window_start ?? now);
      const count = Number(row?.request_count ?? 1);

      const remaining = Math.max(0, policy.maxRequests - count);
      const resetSeconds = Math.max(1, Math.ceil((windowStart + policy.windowMs - now) / 1000));

      if (count > policy.maxRequests) {
        return buildRateLimitResponse(policy, resetSeconds);
      }

      return {
        allowed: true,
        headers: {
          'X-RateLimit-Limit': String(policy.maxRequests),
          'X-RateLimit-Remaining': String(remaining),
        },
      };
    } catch (err) {
      dbFailed = true;
      console.error('[DTKS RateLimiter Warning]: D1 rate_limits query error:', err?.message || err);
    }
  }

  // Sensitive password-recovery endpoints must NEVER silently degrade to isolate-local
  // in-memory rate limiting in production when shared distributed backing is unavailable.
  if (failClosed && isProductionEnv(env) && (dbFailed || !nativeLimiterSucceeded)) {
    return buildRateLimiterUnavailableResponse();
  }

  // 3. In-memory fallback (non-production or non-sensitive general routes only)
  let record = memoryBuckets.get(key);
  if (!record || now - record.windowStart >= policy.windowMs) {
    record = { windowStart: now, count: 0 };
  }

  record.count += 1;
  memoryBuckets.set(key, record);

  if (memoryBuckets.size > 5000) {
    for (const [k, v] of memoryBuckets.entries()) {
      if (now - v.windowStart > 30 * 60 * 1000) {
        memoryBuckets.delete(k);
      }
    }
  }

  const remaining = Math.max(0, policy.maxRequests - record.count);
  const resetSeconds = Math.max(1, Math.ceil((record.windowStart + policy.windowMs - now) / 1000));

  if (record.count > policy.maxRequests) {
    return buildRateLimitResponse(policy, resetSeconds);
  }

  return {
    allowed: true,
    headers: {
      'X-RateLimit-Limit': String(policy.maxRequests),
      'X-RateLimit-Remaining': String(remaining),
    },
  };
}

/**
 * Enforces layered Admin password-recovery protection:
 *   - Per-IP limit (`adminPasswordReset`)
 *   - Per-normalized-email HMAC limit on forgot-password (`adminPasswordResetEmail`)
 *   - Per-token HMAC limit on reset-password (`adminPasswordResetToken`)
 */
export async function enforceAdminPasswordResetRateLimits(
  request,
  env,
  { mode = 'forgot', body = null, skipIpCheck = false } = {}
) {
  if (!skipIpCheck) {
    const ipCheck = await checkRateLimit(request, 'adminPasswordReset', env);
    if (!ipCheck.allowed) return ipCheck;
  }

  if (mode === 'forgot' && body && typeof body.email === 'string') {
    const normalizedEmail = body.email.trim().toLowerCase().slice(0, 254);
    if (normalizedEmail) {
      const emailHmac = await buildRateLimitIdentifierHmac('admin-reset-email', normalizedEmail, env);
      const emailCheck = await checkRateLimit(
        request,
        'adminPasswordResetEmail',
        env,
        `em:${emailHmac}`,
        { includeIp: false }
      );
      if (!emailCheck.allowed) return emailCheck;
    }
  }

  if (mode === 'reset' && body && typeof body.token === 'string') {
    const cleanToken = body.token.trim();
    if (cleanToken) {
      const tokenHmac = await buildRateLimitIdentifierHmac('admin-reset-token', cleanToken, env);
      const tokenCheck = await checkRateLimit(
        request,
        'adminPasswordResetToken',
        env,
        `tok:${tokenHmac}`,
        { includeIp: false }
      );
      if (!tokenCheck.allowed) return tokenCheck;
    }
  }

  return { allowed: true };
}

export async function enforceClientPasswordResetRateLimits(
  request,
  env,
  { mode = 'forgot', body = null, skipIpCheck = false } = {}
) {
  if (!skipIpCheck) {
    const ipCheck = await checkRateLimit(request, 'clientPasswordReset', env);
    if (!ipCheck.allowed) return ipCheck;
  }

  if (mode === 'forgot' && body && typeof body.email === 'string') {
    const normalizedEmail = body.email.trim().toLowerCase().slice(0, 254);
    if (normalizedEmail) {
      const emailHmac = await buildRateLimitIdentifierHmac('client-reset-email', normalizedEmail, env);
      const emailCheck = await checkRateLimit(
        request,
        'clientPasswordResetEmail',
        env,
        `em:${emailHmac}`,
        { includeIp: false }
      );
      if (!emailCheck.allowed) return emailCheck;
    }
  }

  if (mode === 'reset' && body && typeof body.token === 'string') {
    const cleanToken = body.token.trim();
    if (cleanToken) {
      const tokenHmac = await buildRateLimitIdentifierHmac('client-reset-token', cleanToken, env);
      const tokenCheck = await checkRateLimit(
        request,
        'clientPasswordResetToken',
        env,
        `tok:${tokenHmac}`,
        { includeIp: false }
      );
      if (!tokenCheck.allowed) return tokenCheck;
    }
  }

  return { allowed: true };
}

export async function enforceClientVerificationRateLimits(
  request,
  env,
  { mode = 'resend', body = null, skipIpCheck = false } = {}
) {
  if (!skipIpCheck) {
    const ipCheck = await checkRateLimit(request, 'clientVerifyEmail', env);
    if (!ipCheck.allowed) return ipCheck;
  }

  if (mode === 'resend' && body && typeof body.email === 'string') {
    const normalizedEmail = body.email.trim().toLowerCase().slice(0, 254);
    if (normalizedEmail) {
      const emailHmac = await buildRateLimitIdentifierHmac('client-verify-email', normalizedEmail, env);
      const emailCheck = await checkRateLimit(
        request,
        'clientVerificationEmail',
        env,
        `em:${emailHmac}`,
        { includeIp: false }
      );
      if (!emailCheck.allowed) return emailCheck;
    }
  }

  if (mode === 'verify' && body && typeof body.token === 'string') {
    const cleanToken = body.token.trim();
    if (cleanToken) {
      const tokenHmac = await buildRateLimitIdentifierHmac('client-verify-token', cleanToken, env);
      const tokenCheck = await checkRateLimit(
        request,
        'clientVerificationToken',
        env,
        `tok:${tokenHmac}`,
        { includeIp: false }
      );
      if (!tokenCheck.allowed) return tokenCheck;
    }
  }

  return { allowed: true };
}

export async function enforceClientRegisterRateLimits(
  request,
  env,
  { body = null, skipIpCheck = false } = {}
) {
  if (!skipIpCheck) {
    const ipCheck = await checkRateLimit(request, 'clientRegister', env);
    if (!ipCheck.allowed) return ipCheck;
  }

  if (body && typeof body.email === 'string') {
    const normalizedEmail = body.email.trim().toLowerCase().slice(0, 254);
    if (normalizedEmail) {
      const emailHmac = await buildRateLimitIdentifierHmac('client-register-email', normalizedEmail, env);
      const emailCheck = await checkRateLimit(
        request,
        'clientRegisterEmail',
        env,
        `em:${emailHmac}`,
        { includeIp: false }
      );
      if (!emailCheck.allowed) return emailCheck;
    }
  }

  return { allowed: true };
}

export async function enforceOrderTrackingRateLimits(
  request,
  env,
  { body = null, skipIpCheck = false } = {}
) {
  if (!skipIpCheck) {
    const ipCheck = await checkRateLimit(request, 'orderTracking', env);
    if (!ipCheck.allowed) return ipCheck;
  }

  if (body && typeof body.token === 'string') {
    const cleanToken = body.token.trim();
    if (cleanToken) {
      const tokenHmac = await buildRateLimitIdentifierHmac('order-track-token', cleanToken, env);
      const tokenCheck = await checkRateLimit(
        request,
        'orderTrackingToken',
        env,
        `tok:${tokenHmac}`,
        { includeIp: false }
      );
      if (!tokenCheck.allowed) return tokenCheck;
    }
  }

  return { allowed: true };
}

export async function enforceOrderTrackingResendRateLimits(
  request,
  env,
  { body = null, skipIpCheck = false } = {}
) {
  if (!skipIpCheck) {
    const ipCheck = await checkRateLimit(request, 'orderTrackingResend', env);
    if (!ipCheck.allowed) return ipCheck;
  }

  const rawEmail = body?.email ?? body?.customerEmail ?? body?.customer_email;
  if (typeof rawEmail === 'string') {
    const normalizedEmail = rawEmail.trim().toLowerCase().slice(0, 254);
    if (normalizedEmail) {
      const emailHmac = await buildRateLimitIdentifierHmac(
        'order-track-resend-email',
        normalizedEmail,
        env
      );
      const emailCheck = await checkRateLimit(
        request,
        'orderTrackingResendEmail',
        env,
        `em:${emailHmac}`,
        { includeIp: false }
      );
      if (!emailCheck.allowed) return emailCheck;
    }
  }

  const rawOrderNumber =
    body?.orderNumber ?? body?.order_number ?? body?.referenceId ?? body?.ref;
  if (typeof rawOrderNumber === 'string') {
    const normalizedOrder = rawOrderNumber.trim().toUpperCase().slice(0, 64);
    if (normalizedOrder) {
      const orderHmac = await buildRateLimitIdentifierHmac(
        'order-track-resend-order',
        normalizedOrder,
        env
      );
      const orderCheck = await checkRateLimit(
        request,
        'orderTrackingResendOrder',
        env,
        `ord:${orderHmac}`,
        { includeIp: false }
      );
      if (!orderCheck.allowed) return orderCheck;
    }
  }

  return { allowed: true };
}

export async function resetRateLimiter(env = null) {
  memoryBuckets.clear();
  if (env?.DB) {
    try {
      await env.DB.prepare('DELETE FROM rate_limits').run();
    } catch {
      // Ignore if table not yet created
    }
  }
}

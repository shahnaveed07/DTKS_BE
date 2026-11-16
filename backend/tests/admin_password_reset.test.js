import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import workerApp from '../src/index.js';
import { createNodeWorkerEnv } from '../src/database/d1Adapter.js';
import { resetRateLimiter } from '../src/middleware/rateLimiter.js';
import { ensureDatabaseSeeded } from '../src/database/seed.js';
import { sha256Hex, hashPassword } from '../src/utils/crypto.js';
import { PENDING_INVITE_PASSWORD_SENTINEL } from '../src/config/constants.js';

const SUPER_ADMIN_EMAIL = 'super-reset@dtks-test.studio';
const SUPER_ADMIN_PASSWORD = 'SuperReset#2026!Strong';
const ACTIVE_ADMIN_EMAIL = 'ops-reset@dtks-test.studio';
const ACTIVE_ADMIN_PASSWORD = 'OpsReset#2026!Strong';
const INACTIVE_ADMIN_EMAIL = 'inactive-reset@dtks-test.studio';
const INACTIVE_ADMIN_PASSWORD = 'InactiveReset#2026!Strong';
const PENDING_ADMIN_EMAIL = 'pending-reset@dtks-test.studio';
const CLIENT_EMAIL = 'client-isolation@dtks-test.studio';
const CLIENT_PASSWORD = 'ClientIso#2026!Strong';
const TEST_JWT_SECRET = 'dtks-admin-password-reset-suite-256-bit-hmac-secret-2026';

describe('DTKS Admin Forgot Password & Reset Password Suite (/api/v1/auth/*)', () => {
  let tmpDir;
  let dbPath;
  let r2Dir;
  let env;
  let capturedEmails = [];
  let emailMode = 'ok'; // 'ok' | 'fail_all' | 'fail_security_only'

  let activeAdminId = 'adm-ops-reset';
  let inactiveAdminId = 'adm-inactive-reset';
  let pendingAdminId = 'adm-pending-reset';
  let clientAccountId = 'cacc-iso-1';

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dtks-admin-reset-suite-'));
    dbPath = path.join(tmpDir, 'dtks-admin-reset.sqlite');
    r2Dir = path.join(tmpDir, 'r2-storage');

    const mockEmailFetch = async (url, init) => {
      const payload = JSON.parse(init.body);
      if (emailMode === 'fail_all') {
        return new Response(JSON.stringify({ message: 'Upstream Resend failure' }), {
          status: 502,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (
        emailMode === 'fail_security_only' &&
        String(payload.subject || '').includes('[DTKS Admin Security]')
      ) {
        return new Response(JSON.stringify({ message: 'Security notification timeout' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      capturedEmails.push(payload);
      return new Response(JSON.stringify({ id: `re_reset_${capturedEmails.length}` }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    };

    env = createNodeWorkerEnv({
      dbPath,
      r2Dir,
      overrides: {
        ENVIRONMENT: 'development',
        APP_URL: 'https://dreamtechkashmirsolutions.studio',
        ADMIN_NOTIFICATION_EMAIL: 'contact@dreamtechkashmirsolutions.studio',
        JWT_SECRET: TEST_JWT_SECRET,
        INITIAL_ADMIN_NAME: 'Principal Super Admin',
        INITIAL_ADMIN_EMAIL: SUPER_ADMIN_EMAIL,
        INITIAL_ADMIN_PASSWORD: SUPER_ADMIN_PASSWORD,
        RESEND_API_KEY: 're_test_admin_reset_live_key_123456',
        EMAIL_FETCH: mockEmailFetch,
      },
    });

    await resetRateLimiter(env);
    await ensureDatabaseSeeded(env);

    const now = new Date().toISOString();
    const superRow = await env.DB.prepare('SELECT id FROM admins WHERE lower(email) = lower(?)')
      .bind(SUPER_ADMIN_EMAIL)
      .first();

    // Create active invited-and-accepted admin
    await env.DB.prepare(
      `INSERT INTO admins
       (id, name, email, password_hash, role, is_active, token_version, invited_by_admin_id, invite_accepted_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'admin', 1, 1, ?, ?, ?, ?)`
    )
      .bind(
        activeAdminId,
        'Operations Manager',
        ACTIVE_ADMIN_EMAIL,
        await hashPassword(ACTIVE_ADMIN_PASSWORD),
        superRow.id,
        now,
        now,
        now
      )
      .run();

    // Create deactivated/inactive admin
    await env.DB.prepare(
      `INSERT INTO admins
       (id, name, email, password_hash, role, is_active, token_version, invited_by_admin_id, invite_accepted_at, deactivated_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'editor', 0, 1, ?, ?, ?, ?, ?)`
    )
      .bind(
        inactiveAdminId,
        'Inactive Editor',
        INACTIVE_ADMIN_EMAIL,
        await hashPassword(INACTIVE_ADMIN_PASSWORD),
        superRow.id,
        now,
        now,
        now,
        now
      )
      .run();

    // Create pending-invite admin (has not accepted initial invitation)
    await env.DB.prepare(
      `INSERT INTO admins
       (id, name, email, password_hash, role, is_active, token_version, invited_by_admin_id, invite_accepted_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'admin', 0, 1, ?, NULL, ?, ?)`
    )
      .bind(
        pendingAdminId,
        'Pending Invite Admin',
        PENDING_ADMIN_EMAIL,
        PENDING_INVITE_PASSWORD_SENTINEL,
        superRow.id,
        now,
        now
      )
      .run();

    // Create verified active client account for cross-domain token isolation tests
    await env.DB.prepare(
      `INSERT INTO customer_accounts
       (id, full_name, email, phone, password_hash, is_email_verified, email_verified_at, is_active, token_version, terms_accepted, terms_accepted_at, terms_version, privacy_accepted, privacy_accepted_at, privacy_version, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 1, ?, 1, 1, 1, ?, '2026-01', 1, ?, '2026-01', ?, ?)`
    )
      .bind(
        clientAccountId,
        'Tariq Client',
        CLIENT_EMAIL,
        '+91 99060 11223',
        await hashPassword(CLIENT_PASSWORD),
        now,
        now,
        now,
        now,
        now
      )
      .run();
  });

  after(() => {
    try {
      env?.DB?.close?.();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  async function apiRequest(pathname, options = {}) {
    const {
      method = 'GET',
      body = null,
      token = null,
      headers = {},
      ip = '198.51.100.77',
      origin = 'https://dreamtechkashmirsolutions.studio',
      customEnv = env,
    } = options;

    const reqHeaders = new Headers(headers);
    if (origin !== null) reqHeaders.set('Origin', origin);
    if (ip !== null) reqHeaders.set('CF-Connecting-IP', ip);
    if (token) reqHeaders.set('Authorization', `Bearer ${token}`);
    if (
      !reqHeaders.has('X-Auth-Mode') &&
      (pathname.endsWith('/login') || pathname.endsWith('/refresh'))
    ) {
      reqHeaders.set('X-Auth-Mode', 'bearer');
    }

    let requestBody = body;
    if (body && typeof body === 'object' && !Buffer.isBuffer(body)) {
      reqHeaders.set('Content-Type', 'application/json');
      requestBody = JSON.stringify(body);
    }

    const request = new Request(`https://api.dreamtechkashmirsolutions.studio${pathname}`, {
      method,
      headers: reqHeaders,
      body: requestBody,
    });

    const response = await workerApp.fetch(request, customEnv, {});
    const contentType = response.headers.get('content-type') || '';
    const json = contentType.includes('application/json') ? await response.json() : null;
    return { status: response.status, headers: response.headers, json, response };
  }

  function extractLatestEmail(recipientEmail) {
    return [...capturedEmails]
      .reverse()
      .find((m) => Array.isArray(m.to) && m.to.includes(recipientEmail));
  }

  function extractTokenFromEmailText(emailPayload) {
    assert.ok(emailPayload, 'Expected email payload');
    const adminFragmentMatch = /\/admin\/reset-password#token=([a-f0-9]+)/i.exec(
      emailPayload.text || ''
    );
    if (adminFragmentMatch?.[1]) {
      return adminFragmentMatch[1];
    }
    const clientTokenMatch = /[?#]token=([a-f0-9]+)/i.exec(emailPayload.text || '');
    assert.ok(clientTokenMatch && clientTokenMatch[1], 'Expected raw token inside email reset link');
    return clientTokenMatch[1];
  }

  it('0. Migration & Schema Readiness: admin_auth_tokens exists and GET /api/v1/ready succeeds', async () => {
    const readyRes = await apiRequest('/api/v1/ready');
    assert.equal(readyRes.status, 200);
    assert.equal(readyRes.json.data.status, 'ready');
    assert.equal(readyRes.json.data.schema, 'valid');

    const tableRow = await env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'admin_auth_tokens'"
    ).first();
    assert.equal(tableRow?.name, 'admin_auth_tokens');
  });

  it('1–7. Forgot Password: Email dispatch, SHA-256 hashing, uniform anti-enumeration, provider failure handling', async () => {
    await resetRateLimiter(env);
    const baselineEmailCount = capturedEmails.length;

    // 6. Missing/unconfigured Resend key fails cleanly BEFORE lookup (uniform for active & nonexistent)
    const unconfiguredActive = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.1',
      customEnv: { ...env, RESEND_API_KEY: '' },
      body: { email: ACTIVE_ADMIN_EMAIL },
    });
    assert.equal(unconfiguredActive.status, 503);
    assert.equal(unconfiguredActive.json.error.code, 'EMAIL_PROVIDER_UNCONFIGURED');

    const unconfiguredUnknown = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.2',
      customEnv: { ...env, RESEND_API_KEY: 're_replace_with_key' },
      body: { email: 'nonexistent@dtks-test.studio' },
    });
    assert.equal(unconfiguredUnknown.status, 503);
    assert.equal(unconfiguredUnknown.json.error.code, 'EMAIL_PROVIDER_UNCONFIGURED');
    assert.equal(capturedEmails.length, baselineEmailCount);

    // Invalid email payload rejected cleanly
    const invalidEmailRes = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.3',
      body: { email: 'not-an-email' },
    });
    assert.equal(invalidEmailRes.status, 400);
    assert.equal(invalidEmailRes.json.error.code, 'VALIDATION_ERROR');

    // 7. Resend API delivery failure for eligible admin STILL returns uniform 200 (anti-enumeration),
    // immediately revokes the newly generated token, and logs an internal audit event
    emailMode = 'fail_all';
    const failSendRes = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.4',
      body: { email: ACTIVE_ADMIN_EMAIL },
    });
    emailMode = 'ok';
    assert.equal(failSendRes.status, 200);
    assert.equal(failSendRes.json.success, true);
    assert.deepEqual(failSendRes.json.data, { requested: true });
    assert.equal(
      failSendRes.json.message,
      'If an eligible administrator account exists for that email address, a password reset email has been sent.'
    );
    assert.equal(capturedEmails.length, baselineEmailCount);

    const failedTokenRow = await env.DB.prepare(
      "SELECT id, token_hash, used_at, revoked_at FROM admin_auth_tokens WHERE admin_id = ? AND purpose = 'password_reset' ORDER BY created_at DESC LIMIT 1"
    )
      .bind(activeAdminId)
      .first();
    assert.ok(failedTokenRow, 'Failed delivery row should be recorded and immediately revoked');
    assert.equal(failedTokenRow.used_at, null);
    assert.ok(failedTokenRow.revoked_at, 'Token from failed email delivery must be revoked immediately');

    const failedAuditRow = await env.DB.prepare(
      "SELECT action, details FROM activity_logs WHERE action = 'ADMIN_PASSWORD_RESET_DELIVERY_FAILED' ORDER BY timestamp DESC LIMIT 1"
    ).first();
    assert.ok(failedAuditRow, 'Internal security/audit event must be recorded for failed delivery');
    assert.ok(failedAuditRow.details.includes('failed'));

    // 1. Active admin (with whitespace/mixed case) receives branded reset email with #token= fragment link
    const activeForgotRes = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.5',
      body: { email: `  ${ACTIVE_ADMIN_EMAIL.toUpperCase()}  ` },
    });
    assert.equal(activeForgotRes.status, 200);
    assert.equal(activeForgotRes.json.success, true);
    assert.deepEqual(activeForgotRes.json.data, failSendRes.json.data);
    assert.equal(activeForgotRes.json.message, failSendRes.json.message);
    assert.equal(capturedEmails.length, baselineEmailCount + 1);

    const resetEmail = extractLatestEmail(ACTIVE_ADMIN_EMAIL);
    assert.equal(resetEmail.subject, '[DTKS Admin] Reset your administrator password');
    assert.ok(resetEmail.text.includes('Hello Operations Manager,'));
    assert.ok(
      resetEmail.text.includes('https://dreamtechkashmirsolutions.studio/admin/reset-password#token='),
      'Admin reset email must deliver token via URL fragment (#token=)'
    );
    assert.equal(
      resetEmail.text.includes('/admin/reset-password?token='),
      false,
      'Admin reset email must NOT deliver token in URL query string (?token=)'
    );
    assert.ok(resetEmail.text.includes('60 minutes'));
    assert.ok(resetEmail.text.includes('Security Notice:'));
    assert.ok(resetEmail.text.includes('DreamTech Kashmir Solutions'));
    assert.ok(resetEmail.text.includes('contact@dreamtechkashmirsolutions.studio'));

    // 2. Token stored hashed in admin_auth_tokens; raw token NOT in DB or activity_logs
    const firstRawToken = extractTokenFromEmailText(resetEmail);
    assert.ok(firstRawToken.length >= 64);
    const storedRow = await env.DB.prepare(
      "SELECT id, admin_id, purpose, token_hash, used_at, revoked_at FROM admin_auth_tokens WHERE admin_id = ? AND purpose = 'password_reset' ORDER BY created_at DESC LIMIT 1"
    )
      .bind(activeAdminId)
      .first();
    assert.ok(storedRow);
    assert.equal(storedRow.token_hash, await sha256Hex(firstRawToken));
    assert.notEqual(storedRow.token_hash, firstRawToken);
    assert.equal(storedRow.used_at, null);
    assert.equal(storedRow.revoked_at, null);

    const logsRes = await env.DB.prepare('SELECT action, details FROM activity_logs').all();
    const serializedLogs = JSON.stringify(logsRes.results || []);
    assert.ok(serializedLogs.includes('ADMIN_PASSWORD_RESET_REQUESTED'));
    assert.equal(serializedLogs.includes(firstRawToken), false, 'Raw reset token must NEVER be logged');

    // 3, 4, 5 & Anti-enumeration: Nonexistent, inactive, and pending invite return IDENTICAL 200 shape & message and send NO email
    const emailsBeforeNonEligible = capturedEmails.length;
    const nonexistentRes = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.6',
      body: { email: 'nobody@dtks-test.studio' },
    });
    const inactiveRes = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.7',
      body: { email: INACTIVE_ADMIN_EMAIL },
    });
    const pendingRes = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.8',
      body: { email: PENDING_ADMIN_EMAIL },
    });

    assert.equal(capturedEmails.length, emailsBeforeNonEligible, 'No emails sent for non-eligible accounts');
    for (const r of [nonexistentRes, inactiveRes, pendingRes]) {
      assert.equal(r.status, 200);
      assert.equal(r.json.success, true);
      assert.equal(r.json.message, activeForgotRes.json.message);
      assert.deepEqual(r.json.data, activeForgotRes.json.data);
    }

    // Active root super_admin (not invited, directly bootstrapped) CAN also request reset
    const superForgotRes = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.9',
      body: { email: SUPER_ADMIN_EMAIL },
    });
    assert.equal(superForgotRes.status, 200);
    assert.ok(extractLatestEmail(SUPER_ADMIN_EMAIL));
  });

  it('8–18. Reset Password Lifecycle: Prior token revocation, invalid/expired/used/revoked, weak/mismatch, concurrency, session & token_version revocation', async () => {
    await resetRateLimiter(env);

    // Log in Active Admin across two sessions BEFORE reset to verify both access & refresh invalidation
    const loginA = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '198.51.100.20',
      body: { email: ACTIVE_ADMIN_EMAIL, password: ACTIVE_ADMIN_PASSWORD },
    });
    assert.equal(loginA.status, 200);
    const oldAccessToken = loginA.json.data.accessToken;
    const oldRefreshToken = loginA.json.data.refreshToken;

    // Request a fresh reset token for Active Admin -> revokes any prior unused token
    const forgot1 = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.21',
      body: { email: ACTIVE_ADMIN_EMAIL },
    });
    assert.equal(forgot1.status, 200);
    const revokedToken = extractTokenFromEmailText(extractLatestEmail(ACTIVE_ADMIN_EMAIL));

    const forgot2 = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.22',
      body: { email: ACTIVE_ADMIN_EMAIL },
    });
    assert.equal(forgot2.status, 200);
    const validRawToken = extractTokenFromEmailText(extractLatestEmail(ACTIVE_ADMIN_EMAIL));
    assert.notEqual(validRawToken, revokedToken);

    // 13. Revoked token is rejected
    const useRevokedRes = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.23',
      body: {
        token: revokedToken,
        newPassword: 'BrandNew#2026!Strong',
        confirmPassword: 'BrandNew#2026!Strong',
      },
    });
    assert.equal(useRevokedRes.status, 400);
    assert.equal(useRevokedRes.json.error.code, 'RESET_TOKEN_USED');

    // 10. Invalid token rejected
    const invalidTokenRes = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.24',
      body: {
        token: 'f'.repeat(64),
        newPassword: 'BrandNew#2026!Strong',
        confirmPassword: 'BrandNew#2026!Strong',
      },
    });
    assert.equal(invalidTokenRes.status, 400);
    assert.equal(invalidTokenRes.json.error.code, 'INVALID_RESET_TOKEN');

    // 11. Expired token rejected
    const expiredRaw = 'e'.repeat(64);
    await env.DB.prepare(
      `INSERT INTO admin_auth_tokens (id, admin_id, purpose, token_hash, expires_at, created_at)
       VALUES ('atok-expired-1', ?, 'password_reset', ?, '2020-01-01T00:00:00.000Z', datetime('now'))`
    )
      .bind(activeAdminId, await sha256Hex(expiredRaw))
      .run();
    const expiredTokenRes = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.25',
      body: {
        token: expiredRaw,
        newPassword: 'BrandNew#2026!Strong',
        confirmPassword: 'BrandNew#2026!Strong',
      },
    });
    assert.equal(expiredTokenRes.status, 400);
    assert.equal(expiredTokenRes.json.error.code, 'RESET_TOKEN_EXPIRED');

    // 14. Weak password rejected
    const weakPwRes = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.26',
      body: {
        token: validRawToken,
        newPassword: 'password123',
        confirmPassword: 'password123',
      },
    });
    assert.equal(weakPwRes.status, 400);
    assert.equal(weakPwRes.json.error.code, 'VALIDATION_ERROR');

    // 15. Mismatched or missing confirmPassword rejected
    const mismatchRes = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.27',
      body: {
        token: validRawToken,
        newPassword: 'BrandNew#2026!Strong',
        confirmPassword: 'Different#2026!Strong',
      },
    });
    assert.equal(mismatchRes.status, 400);
    assert.equal(mismatchRes.json.error.code, 'VALIDATION_ERROR');

    const missingConfirmRes = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.28',
      body: {
        token: validRawToken,
        newPassword: 'BrandNew#2026!Strong',
      },
    });
    assert.equal(missingConfirmRes.status, 400);
    assert.equal(missingConfirmRes.json.error.code, 'VALIDATION_ERROR');

    // 9 & 16. Concurrent reset attempts with the same token: strictly ONE succeeds, ONE fails!
    // Also test non-blocking security alert failure (`fail_security_only`) does not fail password reset
    emailMode = 'fail_security_only';
    const newPassword = 'ResetDone#2026!Strong';
    const [race1, race2] = await Promise.all([
      apiRequest('/api/v1/auth/reset-password', {
        method: 'POST',
        ip: '198.51.100.29',
        body: {
          token: validRawToken,
          newPassword,
          confirmPassword: newPassword,
        },
      }),
      apiRequest('/api/v1/auth/reset-password', {
        method: 'POST',
        ip: '198.51.100.30',
        body: {
          token: validRawToken,
          newPassword,
          confirmPassword: newPassword,
        },
      }),
    ]);
    emailMode = 'ok';

    const statuses = [race1.status, race2.status].sort();
    assert.deepEqual(statuses, [200, 400]);
    const winner = race1.status === 200 ? race1 : race2;
    const loser = race1.status === 400 ? race1 : race2;
    assert.equal(winner.json.data.reset, true);
    assert.equal(loser.json.error.code, 'RESET_TOKEN_USED');

    // 12. Reusing the already-used token later is rejected with RESET_TOKEN_USED
    const reuseRes = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.31',
      body: {
        token: validRawToken,
        password: 'Another#2026!Password',
        confirmPassword: 'Another#2026!Password',
      },
    });
    assert.equal(reuseRes.status, 400);
    assert.equal(reuseRes.json.error.code, 'RESET_TOKEN_USED');

    // 17. Old password fails login, new password succeeds
    const oldPwLogin = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '198.51.100.32',
      body: { email: ACTIVE_ADMIN_EMAIL, password: ACTIVE_ADMIN_PASSWORD },
    });
    assert.equal(oldPwLogin.status, 401);

    const newPwLogin = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '198.51.100.33',
      body: { email: ACTIVE_ADMIN_EMAIL, password: newPassword },
    });
    assert.equal(newPwLogin.status, 200);
    assert.ok(newPwLogin.json.data.accessToken);

    // 18. Old access token & refresh token were invalidated immediately
    const oldMeRes = await apiRequest('/api/v1/auth/me', { token: oldAccessToken });
    assert.equal(oldMeRes.status, 401);
    assert.equal(oldMeRes.json.error.code, 'SESSION_REVOKED');

    const oldRefreshRes = await apiRequest('/api/v1/auth/refresh', {
      method: 'POST',
      body: { refreshToken: oldRefreshToken },
    });
    assert.equal(oldRefreshRes.status, 401);
    assert.equal(oldRefreshRes.json.error.code, 'INVALID_REFRESH_TOKEN');

    // Security notification email test on super_admin using `password` alias + post-reset email assertion
    const superEmailBefore = capturedEmails.length;
    const superRawToken = extractTokenFromEmailText(extractLatestEmail(SUPER_ADMIN_EMAIL));
    const superResetNewPw = 'SuperNewReset#2026!';
    const superResetRes = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.34',
      body: {
        token: superRawToken,
        password: superResetNewPw,
        confirmPassword: superResetNewPw,
      },
    });
    assert.equal(superResetRes.status, 200);
    const securityAlerts = capturedEmails
      .slice(superEmailBefore)
      .filter((m) => m.to.includes(SUPER_ADMIN_EMAIL) && m.subject.includes('[DTKS Admin Security]'));
    assert.equal(securityAlerts.length, 1);

    // Audit log check: completion logged cleanly with zero raw tokens
    const auditRows = await env.DB.prepare('SELECT action, details FROM activity_logs').all();
    const auditJson = JSON.stringify(auditRows.results || []);
    assert.ok(auditJson.includes('ADMIN_PASSWORD_RESET_COMPLETED'));
    assert.equal(auditJson.includes(validRawToken), false);
    assert.equal(auditJson.includes(superRawToken), false);
    assert.equal(auditJson.includes(newPassword), false);
  });

  it('19–22. Cross-Domain Token Isolation (Admin <-> Client), Inactive/Pending Guard, Dedicated Rate Limiting & Auth Regression', async () => {
    await resetRateLimiter(env);

    // 19. Client reset token REJECTED by Admin reset-password endpoint
    const clientForgotRes = await apiRequest('/api/v1/client/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.40',
      body: { email: CLIENT_EMAIL },
    });
    assert.equal(clientForgotRes.status, 200);
    const clientResetToken = extractTokenFromEmailText(extractLatestEmail(CLIENT_EMAIL));

    const clientTokenOnAdminReset = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.41',
      body: {
        token: clientResetToken,
        newPassword: 'HijackAdmin#2026!Strong',
        confirmPassword: 'HijackAdmin#2026!Strong',
      },
    });
    assert.equal(clientTokenOnAdminReset.status, 400);
    assert.equal(clientTokenOnAdminReset.json.error.code, 'INVALID_RESET_TOKEN');

    // 20. Admin reset token REJECTED by Client reset-password endpoint
    const adminForgotRes = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.42',
      body: { email: ACTIVE_ADMIN_EMAIL },
    });
    assert.equal(adminForgotRes.status, 200);
    const adminResetToken = extractTokenFromEmailText(extractLatestEmail(ACTIVE_ADMIN_EMAIL));

    const adminTokenOnClientReset = await apiRequest('/api/v1/client/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.43',
      body: {
        token: adminResetToken,
        newPassword: 'HijackClient#2026!Strong',
        confirmPassword: 'HijackClient#2026!Strong',
      },
    });
    assert.equal(adminTokenOnClientReset.status, 400);
    assert.equal(adminTokenOnClientReset.json.error.code, 'INVALID_RESET_TOKEN');

    // Client login with original password still works (client unaffected)
    const clientLoginRes = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '198.51.100.44',
      body: { email: CLIENT_EMAIL, password: CLIENT_PASSWORD },
    });
    assert.equal(clientLoginRes.status, 200);

    // 21. Even if a token exists for a deactivated or pending-invite admin, reset-password rejects it
    const futureExpiry = new Date(Date.now() + 3600 * 1000).toISOString();
    const inactiveTok = 'b'.repeat(64);
    const pendingTok = 'c'.repeat(64);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO admin_auth_tokens (id, admin_id, purpose, token_hash, expires_at, created_at)
         VALUES ('atok-deact-guard', ?, 'password_reset', ?, ?, datetime('now'))`
      ).bind(inactiveAdminId, await sha256Hex(inactiveTok), futureExpiry),
      env.DB.prepare(
        `INSERT INTO admin_auth_tokens (id, admin_id, purpose, token_hash, expires_at, created_at)
         VALUES ('atok-pend-guard', ?, 'password_reset', ?, ?, datetime('now'))`
      ).bind(pendingAdminId, await sha256Hex(pendingTok), futureExpiry),
    ]);

    const deactResetRes = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.45',
      body: {
        token: inactiveTok,
        newPassword: 'ShouldFail#2026!Strong',
        confirmPassword: 'ShouldFail#2026!Strong',
      },
    });
    assert.equal(deactResetRes.status, 403);
    assert.equal(deactResetRes.json.error.code, 'ACCOUNT_DEACTIVATED');

    const pendResetRes = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.46',
      body: {
        token: pendingTok,
        newPassword: 'ShouldFail#2026!Strong',
        confirmPassword: 'ShouldFail#2026!Strong',
      },
    });
    assert.equal(pendResetRes.status, 403);
    assert.equal(pendResetRes.json.error.code, 'INVITE_PENDING');

    // 22a. Dedicated per-IP rate limiting enforced (max 8 requests / 15 min per IP across adminPasswordReset)
    const rateIp = '203.0.113.99';
    for (let i = 0; i < 8; i++) {
      const okAttempt = await apiRequest('/api/v1/auth/forgot-password', {
        method: 'POST',
        ip: rateIp,
        body: { email: `rate-check-${i}@dtks-test.studio` },
      });
      assert.equal(okAttempt.status, 200);
    }
    const ninthForgot = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: rateIp,
      body: { email: 'rate-check-9@dtks-test.studio' },
    });
    assert.equal(ninthForgot.status, 429);
    assert.equal(ninthForgot.json.error.code, 'RATE_LIMIT_EXCEEDED');
    assert.ok(ninthForgot.headers.get('Retry-After'));

    // Same IP is ALSO blocked on admin reset-password under adminPasswordReset policy
    const resetBlocked = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: rateIp,
      body: {
        token: adminResetToken,
        newPassword: 'ShouldRateLimit#2026!',
        confirmPassword: 'ShouldRateLimit#2026!',
      },
    });
    assert.equal(resetBlocked.status, 429);

    // Client forgot-password on same IP is NOT blocked (policies are independent)
    const clientNotBlocked = await apiRequest('/api/v1/client/auth/forgot-password', {
      method: 'POST',
      ip: rateIp,
      body: { email: 'client-rate-independent@dtks-test.studio' },
    });
    assert.equal(clientNotBlocked.status, 200);

    // 22b. Regression: Existing Super Admin login + authenticated change-password still work
    const superLogin = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '198.51.100.50',
      body: { email: SUPER_ADMIN_EMAIL, password: 'SuperNewReset#2026!' },
    });
    assert.equal(superLogin.status, 200);
    const superJwt = superLogin.json.data.accessToken;

    const changePwRes = await apiRequest('/api/v1/auth/change-password', {
      method: 'POST',
      token: superJwt,
      ip: '198.51.100.50',
      body: {
        currentPassword: 'SuperNewReset#2026!',
        newPassword: SUPER_ADMIN_PASSWORD,
        confirmPassword: SUPER_ADMIN_PASSWORD,
      },
    });
    assert.equal(changePwRes.status, 200);
    assert.equal(changePwRes.json.data.updated, true);

    const reloginOriginal = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '198.51.100.51',
      body: { email: SUPER_ADMIN_EMAIL, password: SUPER_ADMIN_PASSWORD },
    });
    assert.equal(reloginOriginal.status, 200);
  });

  it('23–27. Security Hardening: Delivery-failure preserves unrelated valid tokens, HMAC email/token rate limits across IPs, production fail-closed limiter & atomic DB expiry', async () => {
    await resetRateLimiter(env);

    // 23. Prior valid token for same admin and unrelated tokens for other admins stay valid if a subsequent delivery fails
    const okReq = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.60',
      body: { email: ACTIVE_ADMIN_EMAIL },
    });
    assert.equal(okReq.status, 200);
    const stillValidToken = extractTokenFromEmailText(extractLatestEmail(ACTIVE_ADMIN_EMAIL));
    const stillValidHash = await sha256Hex(stillValidToken);

    emailMode = 'fail_all';
    const failWhileExisting = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.61',
      body: { email: ACTIVE_ADMIN_EMAIL },
    });
    emailMode = 'ok';
    assert.equal(failWhileExisting.status, 200);
    assert.deepEqual(failWhileExisting.json.data, { requested: true });

    const existingRowAfterFail = await env.DB.prepare(
      'SELECT revoked_at, used_at FROM admin_auth_tokens WHERE token_hash = ?'
    )
      .bind(stillValidHash)
      .first();
    assert.equal(
      existingRowAfterFail.revoked_at,
      null,
      'Unrelated prior valid token must remain unrevoked when new delivery fails'
    );

    const activeFailedCount = await env.DB.prepare(
      `SELECT COUNT(*) AS cnt FROM admin_auth_tokens
       WHERE admin_id = ? AND purpose = 'password_reset' AND used_at IS NULL AND revoked_at IS NULL`
    )
      .bind(activeAdminId)
      .first();
    assert.equal(Number(activeFailedCount.cnt), 1, 'Only the previously delivered token remains active');

    // Verify stillValidToken actually resets password cleanly
    const completeValidRes = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.62',
      body: {
        token: stillValidToken,
        newPassword: 'AfterFailKeep#2026!',
        confirmPassword: 'AfterFailKeep#2026!',
      },
    });
    assert.equal(completeValidRes.status, 200);

    // 24. Distributed target-email rate limiting across different IPs (keyed via HMAC, NEVER raw email in rate_limits)
    await resetRateLimiter(env);
    const targetedEmail = 'target-flood@dtks-test.studio';
    const customEmailLimitEnv = { ...env, ADMIN_PASSWORD_RESET_EMAIL_MAX: '3' };
    for (let i = 0; i < 3; i++) {
      const res = await apiRequest('/api/v1/auth/forgot-password', {
        method: 'POST',
        ip: `198.51.101.${10 + i}`, // different IP every attempt
        customEnv: customEmailLimitEnv,
        body: { email: i % 2 === 0 ? targetedEmail : targetedEmail.toUpperCase() },
      });
      assert.equal(res.status, 200);
    }
    const fourthAcrossIps = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.101.99',
      customEnv: customEmailLimitEnv,
      body: { email: `  ${targetedEmail}  ` },
    });
    assert.equal(fourthAcrossIps.status, 429);
    assert.equal(fourthAcrossIps.json.error.code, 'RATE_LIMIT_EXCEEDED');

    // Admin account was NOT locked out (`is_active` preserved on active admins)
    const activeAdminCheck = await env.DB.prepare('SELECT is_active FROM admins WHERE id = ?')
      .bind(activeAdminId)
      .first();
    assert.equal(activeAdminCheck.is_active, 1);

    // Confirm raw email & raw tokens NEVER appear in rate_limits table
    const rateKeys = await env.DB.prepare('SELECT rate_key FROM rate_limits').all();
    const serializedKeys = JSON.stringify(rateKeys.results || []);
    assert.equal(serializedKeys.includes(targetedEmail), false, 'Raw email must never be stored in rate_limits');
    assert.ok(serializedKeys.includes('adminPasswordResetEmail:em:'));

    // 25. Distributed token-attempt rate limiting across different IPs (keyed via HMAC, NEVER raw token or token_hash)
    const probedToken = 'a'.repeat(64);
    const probedTokenSha256 = await sha256Hex(probedToken);
    const customTokenLimitEnv = { ...env, ADMIN_PASSWORD_RESET_TOKEN_MAX: '3' };
    for (let i = 0; i < 3; i++) {
      const res = await apiRequest('/api/v1/auth/reset-password', {
        method: 'POST',
        ip: `198.51.102.${10 + i}`,
        customEnv: customTokenLimitEnv,
        body: {
          token: probedToken,
          newPassword: 'TokenProbe#2026!Strong',
          confirmPassword: 'TokenProbe#2026!Strong',
        },
      });
      assert.equal(res.status, 400);
      assert.equal(res.json.error.code, 'INVALID_RESET_TOKEN');
    }
    const fourthTokenAttempt = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.102.99',
      customEnv: customTokenLimitEnv,
      body: {
        token: probedToken,
        newPassword: 'TokenProbe#2026!Strong',
        confirmPassword: 'TokenProbe#2026!Strong',
      },
    });
    assert.equal(fourthTokenAttempt.status, 429);
    assert.equal(fourthTokenAttempt.json.error.code, 'RATE_LIMIT_EXCEEDED');

    const rateKeysAfterTok = await env.DB.prepare('SELECT rate_key FROM rate_limits').all();
    const serializedTokKeys = JSON.stringify(rateKeysAfterTok.results || []);
    assert.equal(serializedTokKeys.includes(probedToken), false, 'Raw token must never be stored in rate_limits');
    assert.equal(
      serializedTokKeys.includes(probedTokenSha256),
      false,
      'Rate-limit token key must use keyed HMAC rather than matching DB token_hash'
    );
    assert.ok(serializedTokKeys.includes('adminPasswordResetToken:tok:'));

    // 26. Fail closed in production (`ENVIRONMENT === 'production'`) when distributed rate limiter fails/unavailable
    const failingRateLimitDb = {
      prepare() {
        return {
          bind() {
            return this;
          },
          async first() {
            throw new Error('Simulated D1 outage');
          },
          async run() {
            throw new Error('Simulated D1 outage');
          },
        };
      },
    };
    const prodFailClosedEnv = {
      ...env,
      ENVIRONMENT: 'production',
      DB: failingRateLimitDb,
      ADMIN_RESET_RATE_LIMITER: null,
      RATE_LIMITER: null,
    };
    const prodForgotFailClosed = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '203.0.113.200',
      customEnv: prodFailClosedEnv,
      body: { email: ACTIVE_ADMIN_EMAIL },
    });
    assert.equal(prodForgotFailClosed.status, 503);
    assert.equal(prodForgotFailClosed.json.error.code, 'RATE_LIMITER_UNAVAILABLE');

    const prodResetFailClosed = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '203.0.113.201',
      customEnv: prodFailClosedEnv,
      body: {
        token: 'd'.repeat(64),
        newPassword: 'ProdFailClosed#2026!',
        confirmPassword: 'ProdFailClosed#2026!',
      },
    });
    assert.equal(prodResetFailClosed.status, 503);
    assert.equal(prodResetFailClosed.json.error.code, 'RATE_LIMITER_UNAVAILABLE');

    // Native ADMIN_RESET_RATE_LIMITER binding rejects cleanly when returning { success: false }
    const nativeRejectedEnv = {
      ...env,
      ENVIRONMENT: 'production',
      ADMIN_RESET_RATE_LIMITER: {
        async limit() {
          return { success: false };
        },
      },
    };
    const nativeBlocked = await apiRequest('/api/v1/auth/forgot-password', {
      method: 'POST',
      ip: '203.0.113.202',
      customEnv: nativeRejectedEnv,
      body: { email: ACTIVE_ADMIN_EMAIL },
    });
    assert.equal(nativeBlocked.status, 429);
    assert.equal(nativeBlocked.json.error.code, 'RATE_LIMIT_EXCEEDED');

    // 27. Atomic DB-level expiry enforcement inside UPDATE predicate (`julianday(expires_at) > julianday(?)`)
    // Verify that even if an initial read saw an unexpired row that expired right before the UPDATE claim,
    // the atomic UPDATE returns 0 changes and rejects with RESET_TOKEN_EXPIRED.
    await resetRateLimiter(env);
    const raceExpiryRaw = 'ab'.repeat(32);
    const raceExpiryHash = await sha256Hex(raceExpiryRaw);
    const futureStr = new Date(Date.now() + 60000).toISOString();
    await env.DB.prepare(
      `INSERT INTO admin_auth_tokens (id, admin_id, purpose, token_hash, expires_at, created_at)
       VALUES ('atok-atomic-exp-1', ?, 'password_reset', ?, ?, datetime('now'))`
    )
      .bind(activeAdminId, raceExpiryHash, futureStr)
      .run();

    // Flip expires_at to the past ONLY when the SELECT on admins runs (simulating expiration between read & atomic claim)
    let flipped = false;
    const baseDb = env.DB;
    const raceExpiryDb = {
      async batch(stmts) {
        return baseDb.batch(stmts);
      },
      prepare(sql) {
        const stmt = baseDb.prepare(sql);
        if (!flipped && /FROM admins WHERE id = \?/i.test(sql)) {
          flipped = true;
          const origBind = stmt.bind.bind(stmt);
          stmt.bind = (...args) => {
            const bound = origBind(...args);
            const origFirst = bound.first.bind(bound);
            bound.first = async () => {
              await baseDb
                .prepare("UPDATE admin_auth_tokens SET expires_at = '2020-01-01T00:00:00.000Z' WHERE id = 'atok-atomic-exp-1'")
                .run();
              return origFirst();
            };
            return bound;
          };
        }
        return stmt;
      },
    };

    const atomicExpiredRes = await apiRequest('/api/v1/auth/reset-password', {
      method: 'POST',
      ip: '198.51.103.10',
      customEnv: { ...env, DB: raceExpiryDb },
      body: {
        token: raceExpiryRaw,
        newPassword: 'AtomicExpiryFail#2026!',
        confirmPassword: 'AtomicExpiryFail#2026!',
      },
    });
    assert.equal(atomicExpiredRes.status, 400);
    assert.equal(atomicExpiredRes.json.error.code, 'RESET_TOKEN_EXPIRED');

    const tokenAfterRace = await env.DB.prepare(
      "SELECT used_at FROM admin_auth_tokens WHERE id = 'atok-atomic-exp-1'"
    ).first();
    assert.equal(tokenAfterRace.used_at, null, 'Expired token must NOT be claimed as used');
  });
});

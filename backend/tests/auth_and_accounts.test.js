import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import workerApp from '../src/index.js';
import { createNodeWorkerEnv } from '../src/database/d1Adapter.js';
import { resetRateLimiter } from '../src/middleware/rateLimiter.js';
import { ensureDatabaseSeeded } from '../src/database/seed.js';
import { sha256Hex } from '../src/utils/crypto.js';

const TEST_SUPER_EMAIL = 'superadmin@dtks-test.studio';
const TEST_SUPER_PASSWORD = 'SuperAdmin#2026!Strong';
const TEST_JWT_SECRET = 'dtks-auth-accounts-test-256-bit-random-hmac-secret-2026';

describe('DTKS Admin Account Management & Client Auth Test Suite (/api/v1)', () => {
  let tmpDir;
  let dbPath;
  let r2Dir;
  let env;
  let capturedEmails = [];
  let emailShouldFail = false;

  let superToken = '';
  let superRefreshToken = '';
  let adminAccountId = '';
  let adminToken = '';
  let editorAccountId = '';
  let editorToken = '';

  let clientAToken = '';
  let clientARefresh = '';
  let clientACustomerId = '';
  let clientBToken = '';
  let clientBOrderId = '';

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dtks-auth-suite-'));
    dbPath = path.join(tmpDir, 'dtks-auth.sqlite');
    r2Dir = path.join(tmpDir, 'r2-storage');

    const mockEmailFetch = async (url, init) => {
      if (emailShouldFail) {
        return new Response(JSON.stringify({ message: 'Upstream Resend error' }), {
          status: 502,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      const payload = JSON.parse(init.body);
      capturedEmails.push(payload);
      return new Response(JSON.stringify({ id: `re_msg_${capturedEmails.length}` }), {
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
        JWT_SECRET: TEST_JWT_SECRET,
        INITIAL_ADMIN_NAME: 'Principal Super Admin',
        INITIAL_ADMIN_EMAIL: TEST_SUPER_EMAIL,
        INITIAL_ADMIN_PASSWORD: TEST_SUPER_PASSWORD,
        RESEND_API_KEY: 're_test_live_mock_key_123456',
        EMAIL_FETCH: mockEmailFetch,
      },
    });

    await resetRateLimiter(env);
    await ensureDatabaseSeeded(env);
  });

  after(() => {
    try {
      env?.DB?.close?.();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  function extractTokenFromLatestEmail(recipientEmail) {
    const email = [...capturedEmails]
      .reverse()
      .find((m) => Array.isArray(m.to) && m.to.includes(recipientEmail));
    assert.ok(email, `Expected email dispatched to ${recipientEmail}`);
    const match = /[?#]token=([a-f0-9]+)/i.exec(email.text || '');
    assert.ok(match && match[1], `Expected token link in email text to ${recipientEmail}`);
    return match[1];
  }

  async function apiRequest(pathname, options = {}) {
    const {
      method = 'GET',
      body = null,
      token = null,
      headers = {},
      ip = '127.0.0.10',
      origin = 'https://dreamtechkashmirsolutions.studio',
      customEnv = env,
    } = options;

    const reqHeaders = new Headers(headers);
    if (origin) reqHeaders.set('Origin', origin);
    if (ip) reqHeaders.set('CF-Connecting-IP', ip);
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

    const request = new Request(`https://dreamtechkashmirsolutions.studio${pathname}`, {
      method,
      headers: reqHeaders,
      body: requestBody,
    });

    const response = await workerApp.fetch(request, customEnv, {});
    const contentType = response.headers.get('content-type') || '';
    const json = contentType.includes('application/json') ? await response.json() : null;
    return { status: response.status, headers: response.headers, json, response };
  }

  // =========================================================================
  // FEATURE A — ADMIN ACCOUNT MANAGEMENT & RBAC TESTS
  // =========================================================================

  it('A1. CORS Preflight: Supports X-CSRF-Token header for authorized origins and blocks unauthorized origins', async () => {
    const preflight = await apiRequest('/api/v1/client/auth/login', {
      method: 'OPTIONS',
      headers: {
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type, Authorization, X-CSRF-Token',
      },
    });
    assert.equal(preflight.status, 204);
    const allowHeaders = preflight.headers.get('Access-Control-Allow-Headers') || '';
    assert.ok(allowHeaders.includes('X-CSRF-Token'));

    const badOrigin = await apiRequest('/api/v1/client/auth/login', {
      method: 'OPTIONS',
      origin: 'https://evil.example.org',
    });
    assert.equal(badOrigin.status, 403);
  });

  it('A2. Admin Login & Invalid Credentials: Super Admin logs in; invalid credentials rejected', async () => {
    const badRes = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '10.1.1.1',
      body: { email: TEST_SUPER_EMAIL, password: 'WrongPassword#2026' },
    });
    assert.equal(badRes.status, 401);
    assert.equal(badRes.json.error.code, 'INVALID_CREDENTIALS');

    const loginRes = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '10.1.1.2',
      body: { email: TEST_SUPER_EMAIL, password: TEST_SUPER_PASSWORD },
    });
    assert.equal(loginRes.status, 200);
    assert.equal(loginRes.json.data.admin.role, 'super_admin');
    superToken = loginRes.json.data.accessToken;
    superRefreshToken = loginRes.json.data.refreshToken;
    assert.ok(superToken);
    assert.ok(superRefreshToken);
  });

  it('A3. Admin Account Creation via Invitation: Hashes invite token, keeps pending until accepted, rejects unconfigured/failed email', async () => {
    // Email failure keeps account pending and reports delivery failure accurately
    emailShouldFail = true;
    const failedCreateRes = await apiRequest('/api/v1/admin/accounts', {
      method: 'POST',
      token: superToken,
      body: {
        name: 'Pending Failed Admin',
        email: 'failed-invite@dtks-test.studio',
        role: 'admin',
      },
    });
    emailShouldFail = false;
    assert.equal(failedCreateRes.status, 503);
    assert.equal(failedCreateRes.json.error.code, 'EMAIL_DELIVERY_FAILED');
    assert.equal(failedCreateRes.json.error.details.invitationEmailSent, false);
    const failedAdminId = failedCreateRes.json.error.details.account.id;
    assert.equal(failedCreateRes.json.error.details.account.isActive, false);

    // Resend invitation succeeds when provider recovers
    const resendRes = await apiRequest(`/api/v1/admin/accounts/${failedAdminId}/resend-invite`, {
      method: 'POST',
      token: superToken,
    });
    assert.equal(resendRes.status, 200);
    assert.equal(resendRes.json.data.invitationEmailSent, true);

    // Create normal admin & editor accounts cleanly
    const createAdminRes = await apiRequest('/api/v1/admin/accounts', {
      method: 'POST',
      token: superToken,
      body: {
        name: 'Operations Admin',
        email: 'ops.admin@dtks-test.studio',
        role: 'admin',
      },
    });
    assert.equal(createAdminRes.status, 201);
    assert.equal(createAdminRes.json.data.invitationEmailSent, true);
    assert.equal(createAdminRes.json.data.account.password_hash, undefined);
    assert.equal(createAdminRes.json.data.account.invitePending, true);
    assert.equal(createAdminRes.json.data.account.isActive, false);
    adminAccountId = createAdminRes.json.data.account.id;

    // Pending admin cannot log in before accepting invite
    const pendingLoginRes = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '10.1.1.3',
      body: { email: 'ops.admin@dtks-test.studio', password: 'AnyPassword#2026' },
    });
    assert.equal(pendingLoginRes.status, 403);
    assert.equal(pendingLoginRes.json.error.code, 'INVITE_PENDING');

    // Verify invitation token is stored as SHA-256 hash in D1
    const rawInviteToken = extractTokenFromLatestEmail('ops.admin@dtks-test.studio');
    const inviteRow = await env.DB.prepare(
      'SELECT token_hash FROM admin_invitations WHERE admin_id = ?'
    )
      .bind(adminAccountId)
      .first();
    assert.equal(inviteRow.token_hash, await sha256Hex(rawInviteToken));
    assert.notEqual(inviteRow.token_hash, rawInviteToken);

    // Weak password rejected on invite acceptance
    const weakInviteRes = await apiRequest('/api/v1/auth/accept-invite', {
      method: 'POST',
      body: { token: rawInviteToken, password: 'weak', confirmPassword: 'weak' },
    });
    assert.equal(weakInviteRes.status, 400);

    // Valid invite acceptance activates account
    const opsPassword = 'OpsAdmin#2026!Strong';
    const acceptRes = await apiRequest('/api/v1/auth/accept-invite', {
      method: 'POST',
      body: {
        token: rawInviteToken,
        password: opsPassword,
        confirmPassword: opsPassword,
      },
    });
    assert.equal(acceptRes.status, 200);
    assert.equal(acceptRes.json.data.activated, true);
    assert.equal(acceptRes.json.data.account.isActive, true);

    // Single-use: reusing the invite token must fail
    const reuseInviteRes = await apiRequest('/api/v1/auth/accept-invite', {
      method: 'POST',
      body: {
        token: rawInviteToken,
        password: opsPassword,
        confirmPassword: opsPassword,
      },
    });
    assert.equal(reuseInviteRes.status, 400);
    assert.equal(reuseInviteRes.json.error.code, 'INVITE_TOKEN_ALREADY_USED');

    // Operations Admin logs in
    const opsLoginRes = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '10.1.1.4',
      body: { email: 'ops.admin@dtks-test.studio', password: opsPassword },
    });
    assert.equal(opsLoginRes.status, 200);
    adminToken = opsLoginRes.json.data.accessToken;

    // Create & activate Editor account
    const createEditorRes = await apiRequest('/api/v1/admin/accounts', {
      method: 'POST',
      token: superToken,
      body: {
        name: 'Content Editor',
        email: 'editor@dtks-test.studio',
        role: 'editor',
      },
    });
    assert.equal(createEditorRes.status, 201);
    editorAccountId = createEditorRes.json.data.account.id;
    const editorInviteToken = extractTokenFromLatestEmail('editor@dtks-test.studio');
    const editorPassword = 'EditorPass#2026!Strong';
    const acceptEditorRes = await apiRequest('/api/v1/auth/accept-invite', {
      method: 'POST',
      body: {
        token: editorInviteToken,
        password: editorPassword,
        confirmPassword: editorPassword,
      },
    });
    assert.equal(acceptEditorRes.status, 200);
    const editorLoginRes = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '10.1.1.5',
      body: { email: 'editor@dtks-test.studio', password: editorPassword },
    });
    assert.equal(editorLoginRes.status, 200);
    editorToken = editorLoginRes.json.data.accessToken;
  });

  it('A4. Cross-Role Authorization & Role Escalation Rejection: Enforces super_admin > admin > editor boundaries', async () => {
    // Ordinary admin CAN view admin accounts
    const adminListRes = await apiRequest('/api/v1/admin/accounts', { token: adminToken });
    assert.equal(adminListRes.status, 200);
    assert.ok(adminListRes.json.data.accounts.length >= 3);

    // Editor CANNOT view admin accounts (403 FORBIDDEN)
    const editorListRes = await apiRequest('/api/v1/admin/accounts', { token: editorToken });
    assert.equal(editorListRes.status, 403);
    assert.equal(editorListRes.json.error.code, 'FORBIDDEN');

    // Ordinary admin CANNOT create new admin or super_admin (403 FORBIDDEN)
    const adminCreateAttempt = await apiRequest('/api/v1/admin/accounts', {
      method: 'POST',
      token: adminToken,
      body: {
        name: 'Rogue Super',
        email: 'rogue@dtks-test.studio',
        role: 'super_admin',
      },
    });
    assert.equal(adminCreateAttempt.status, 403);

    // Editor CANNOT create admin or elevate role (403 FORBIDDEN)
    const editorEscalate = await apiRequest(`/api/v1/admin/accounts/${editorAccountId}`, {
      method: 'PATCH',
      token: editorToken,
      body: { role: 'super_admin' },
    });
    assert.equal(editorEscalate.status, 403);

    // Ordinary admin CANNOT escalate own role or change another admin's status (403 FORBIDDEN)
    const adminEscalate = await apiRequest(`/api/v1/admin/accounts/${adminAccountId}`, {
      method: 'PATCH',
      token: adminToken,
      body: { role: 'super_admin' },
    });
    assert.equal(adminEscalate.status, 403);

    const adminSelfProfileEscalate = await apiRequest('/api/v1/auth/profile', {
      method: 'PATCH',
      token: adminToken,
      body: { name: 'Attempt', role: 'super_admin' },
    });
    assert.equal(adminSelfProfileEscalate.status, 400);

    // Mass-assignment of password_hash rejected even for super_admin
    const massAssignRes = await apiRequest(`/api/v1/admin/accounts/${adminAccountId}`, {
      method: 'PATCH',
      token: superToken,
      body: { password_hash: 'tampered', name: 'Legit' },
    });
    assert.equal(massAssignRes.status, 400);
  });

  it('A5. Last Active Super Admin Protection, Deactivation & Immediate Session Revocation', async () => {
    const superAdminRow = await env.DB.prepare(
      'SELECT id FROM admins WHERE lower(email) = lower(?)'
    )
      .bind(TEST_SUPER_EMAIL)
      .first();

    // Cannot deactivate last active super_admin
    const deactivateLastSuper = await apiRequest(
      `/api/v1/admin/accounts/${superAdminRow.id}/status`,
      {
        method: 'PATCH',
        token: superToken,
        body: { isActive: false },
      }
    );
    assert.equal(deactivateLastSuper.status, 409);
    assert.equal(deactivateLastSuper.json.error.code, 'LAST_SUPER_ADMIN_PROTECTED');

    // Cannot demote last active super_admin
    const demoteLastSuper = await apiRequest(`/api/v1/admin/accounts/${superAdminRow.id}`, {
      method: 'PATCH',
      token: superToken,
      body: { role: 'admin' },
    });
    assert.equal(demoteLastSuper.status, 409);
    assert.equal(demoteLastSuper.json.error.code, 'LAST_SUPER_ADMIN_PROTECTED');

    // Revoke all sessions for Operations Admin -> existing access token immediately rejected
    const revokeRes = await apiRequest(`/api/v1/admin/accounts/${adminAccountId}/sessions`, {
      method: 'DELETE',
      token: superToken,
    });
    assert.equal(revokeRes.status, 200);

    const revokedAccessUse = await apiRequest('/api/v1/auth/me', { token: adminToken });
    assert.equal(revokedAccessUse.status, 401);
    assert.equal(revokedAccessUse.json.error.code, 'SESSION_REVOKED');

    // Operations Admin logs back in, then gets deactivated -> login and token rejected
    const opsRelogin = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '10.1.1.6',
      body: { email: 'ops.admin@dtks-test.studio', password: 'OpsAdmin#2026!Strong' },
    });
    assert.equal(opsRelogin.status, 200);
    const freshOpsToken = opsRelogin.json.data.accessToken;

    const deactivateOps = await apiRequest(`/api/v1/admin/accounts/${adminAccountId}/status`, {
      method: 'PATCH',
      token: superToken,
      body: { isActive: false },
    });
    assert.equal(deactivateOps.status, 200);
    assert.equal(deactivateOps.json.data.account.isActive, false);

    // Deactivated admin access token and login rejected
    const deactivatedMe = await apiRequest('/api/v1/auth/me', { token: freshOpsToken });
    assert.equal(deactivatedMe.status, 403);
    assert.equal(deactivatedMe.json.error.code, 'ACCOUNT_DEACTIVATED');

    const deactivatedLogin = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '10.1.1.7',
      body: { email: 'ops.admin@dtks-test.studio', password: 'OpsAdmin#2026!Strong' },
    });
    assert.equal(deactivatedLogin.status, 403);
    assert.equal(deactivatedLogin.json.error.code, 'ACCOUNT_DEACTIVATED');
  });

  // =========================================================================
  // FEATURE B, C, D & E — CLIENT REGISTRATION, LINKING, AUTH & DATA ISOLATION
  // =========================================================================

  it('B1. Guest Order Regression + Safe Pre-Registration Customer Linking on Email Verification', async () => {
    // 1. Guest submits a website order BEFORE registering a client account
    const guestEmail = 'clientA@dtks-test.studio';
    const guestOrderRes = await apiRequest('/api/v1/orders', {
      method: 'POST',
      body: {
        service_id: 'svc-business-websites',
        package_id: 'pkg-business-website',
        project_name: 'Srinagar Heritage Portal',
        business_name: 'Heritage Crafts',
        project_description: 'Multi-page corporate website with catalog and inquiry form.',
        budget: '₹15,000 – ₹30,000',
        customer_name: 'Amina Jan',
        customer_email: guestEmail,
        customer_phone: '+91 99061 55501',
        customer_city: 'Srinagar',
      },
    });
    assert.equal(guestOrderRes.status, 201);
    const guestOrderId = guestOrderRes.json.data.order.id;
    const guestTrackingToken = guestOrderRes.json.data.trackingToken;
    assert.ok(guestTrackingToken && guestTrackingToken.length >= 64);
    assert.equal(guestOrderRes.json.data.order.status, 'Pending');

    // Admin adds internal admin_notes and quotation to that order
    const adminQuoteRes = await apiRequest(`/api/v1/orders/${guestOrderId}`, {
      method: 'PATCH',
      token: superToken,
      body: {
        status: 'Quotation Sent',
        quotation_amount: 24000,
        quotation_notes: 'Includes custom CMS and responsive gallery.',
        customer_update: 'Quotation ready for review.',
        admin_notes: 'CONFIDENTIAL MARGIN NOTE: 35% margin target',
      },
    });
    assert.equal(adminQuoteRes.status, 200);

    // Guest tracking works via private tracking token and never leaks admin_notes or PII
    const trackRes = await apiRequest('/api/v1/orders/track', {
      method: 'POST',
      body: { token: guestTrackingToken },
    });
    assert.equal(trackRes.status, 200);
    assert.equal(trackRes.json.data.order.admin_notes, undefined);
    assert.equal(trackRes.json.data.order.customer_email, undefined);

    // 2. Client registration validation: invalid email, weak password, mismatched confirmPassword
    const invalidEmailReg = await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '10.2.0.1',
      body: {
        fullName: 'Amina Jan',
        email: 'not-an-email',
        phone: '+91 99061 55501',
        password: 'Client#2026!Strong',
        confirmPassword: 'Client#2026!Strong',
        acceptTerms: true,
      },
    });
    assert.equal(invalidEmailReg.status, 400);

    const weakPwReg = await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '10.2.0.2',
      body: {
        fullName: 'Amina Jan',
        email: 'clienta@dtks-test.studio',
        phone: '+91 99061 55501',
        password: 'password123',
        confirmPassword: 'password123',
        acceptTerms: true,
      },
    });
    assert.equal(weakPwReg.status, 400);

    const mismatchPwReg = await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '10.2.0.3',
      body: {
        fullName: 'Amina Jan',
        email: 'clienta@dtks-test.studio',
        phone: '+91 99061 55501',
        password: 'Client#2026!Strong',
        confirmPassword: 'Different#2026!Strong',
        acceptTerms: true,
      },
    });
    assert.equal(mismatchPwReg.status, 400);

    // 3. Unconfigured email provider fails gracefully without claiming sent & keeps account pending
    const unconfiguredRes = await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '10.2.0.4',
      customEnv: { ...env, RESEND_API_KEY: '' },
      body: {
        fullName: 'Unverified Pending',
        email: 'pending-unconfigured@dtks-test.studio',
        phone: '+91 99061 55599',
        password: 'Client#2026!Strong',
        confirmPassword: 'Client#2026!Strong',
        acceptTerms: true,
      },
    });
    assert.equal(unconfiguredRes.status, 503);
    assert.equal(unconfiguredRes.json.error.code, 'EMAIL_PROVIDER_UNCONFIGURED');
    assert.equal(unconfiguredRes.json.error.details.accountCreated, true);
    assert.equal(unconfiguredRes.json.error.details.accountPendingVerification, true);
    assert.equal(unconfiguredRes.json.error.details.verificationEmailSent, false);
    assert.equal(unconfiguredRes.json.error.details.canResendVerification, true);

    // 4. Successful registration with case-insensitive email normalization & legal acceptance
    const regRes = await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '10.2.0.5',
      body: {
        fullName: 'Amina Jan',
        email: '  ClientA@DTKS-Test.Studio  ',
        phone: '+91 99061 55501',
        city: 'Srinagar',
        businessName: 'Heritage Crafts',
        password: 'ClientA#2026!Strong',
        confirmPassword: 'ClientA#2026!Strong',
        acceptTerms: true,
      },
    });
    assert.equal(regRes.status, 201);
    assert.equal(regRes.json.data.verificationEmailSent, true);
    assert.equal(regRes.json.data.account.email, 'clienta@dtks-test.studio');
    assert.equal(regRes.json.data.account.isEmailVerified, false);
    assert.equal(regRes.json.data.account.termsAccepted, true);
    assert.ok(regRes.json.data.account.termsAcceptedAt);
    assert.equal(regRes.json.data.account.termsVersion, '2026-01');
    assert.equal(regRes.json.data.account.privacyAccepted, true);
    assert.equal(regRes.json.data.account.customerId, null, 'Must not link customer before email verification');

    // Duplicate registration rejected
    const dupRegRes = await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '10.2.0.6',
      body: {
        fullName: 'Duplicate Amina',
        email: 'clienta@dtks-test.studio',
        phone: '+91 99061 55501',
        password: 'ClientA#2026!Strong',
        confirmPassword: 'ClientA#2026!Strong',
        acceptTerms: true,
      },
    });
    assert.equal(dupRegRes.status, 409);
    assert.equal(dupRegRes.json.error.code, 'REGISTRATION_CONFLICT');

    // Login before verification rejected
    const unverifiedLoginRes = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '10.2.0.7',
      body: { email: 'clienta@dtks-test.studio', password: 'ClientA#2026!Strong' },
    });
    assert.equal(unverifiedLoginRes.status, 403);
    assert.equal(unverifiedLoginRes.json.error.code, 'EMAIL_NOT_VERIFIED');

    // Verify token is stored hashed in D1
    const rawVerifyToken = extractTokenFromLatestEmail('clienta@dtks-test.studio');
    const tokRow = await env.DB.prepare(
      'SELECT id, token_hash FROM customer_auth_tokens WHERE customer_account_id = ?'
    )
      .bind(regRes.json.data.account.id)
      .first();
    assert.equal(tokRow.token_hash, await sha256Hex(rawVerifyToken));

    // Verify email -> links to existing guest customer & historical order!
    const verifyRes = await apiRequest('/api/v1/client/auth/verify-email', {
      method: 'POST',
      body: { token: rawVerifyToken },
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.json.data.verified, true);
    assert.equal(verifyRes.json.data.customerLinked, true);
    assert.ok(verifyRes.json.data.account.customerId);
    clientACustomerId = verifyRes.json.data.account.customerId;

    // Verification token reuse rejected
    const reuseVerifyRes = await apiRequest('/api/v1/client/auth/verify-email', {
      method: 'POST',
      body: { token: rawVerifyToken },
    });
    assert.equal(reuseVerifyRes.status, 400);
    assert.equal(reuseVerifyRes.json.error.code, 'VERIFICATION_TOKEN_USED');

    // Expired verification token rejected
    const expiredRaw = 'a'.repeat(64);
    await env.DB.prepare(
      `INSERT INTO customer_auth_tokens (id, customer_account_id, purpose, token_hash, expires_at, created_at)
       VALUES ('ctok-exp-1', ?, 'email_verification', ?, '2020-01-01T00:00:00.000Z', datetime('now'))`
    )
      .bind(regRes.json.data.account.id, await sha256Hex(expiredRaw))
      .run();
    const expiredVerifyRes = await apiRequest('/api/v1/client/auth/verify-email', {
      method: 'POST',
      body: { token: expiredRaw },
    });
    assert.equal(expiredVerifyRes.status, 400);
    assert.equal(expiredVerifyRes.json.error.code, 'VERIFICATION_TOKEN_EXPIRED');
  });

  it('C1. Client Login, Refresh Rotation, Logout, Profile Update, and Guest Overwrite Protection', async () => {
    const badLogin = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '10.2.1.1',
      body: { email: 'clienta@dtks-test.studio', password: 'WrongPassword#2026' },
    });
    assert.equal(badLogin.status, 401);

    const loginRes = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '10.2.1.2',
      body: { email: 'clienta@dtks-test.studio', password: 'ClientA#2026!Strong' },
    });
    assert.equal(loginRes.status, 200);
    clientAToken = loginRes.json.data.accessToken;
    clientARefresh = loginRes.json.data.refreshToken;
    assert.ok(clientAToken);
    assert.ok(clientARefresh);

    // /client/auth/me works
    const meRes = await apiRequest('/api/v1/client/auth/me', { token: clientAToken });
    assert.equal(meRes.status, 200);
    assert.equal(meRes.json.data.client.email, 'clienta@dtks-test.studio');

    // Profile update updates allowed fields and rejects immutable fields
    const badProfileRes = await apiRequest('/api/v1/client/auth/profile', {
      method: 'PATCH',
      token: clientAToken,
      body: { email: 'hijack@dtks-test.studio' },
    });
    assert.equal(badProfileRes.status, 400);

    const profileRes = await apiRequest('/api/v1/client/auth/profile', {
      method: 'PATCH',
      token: clientAToken,
      body: { fullName: 'Amina Jan Updated', city: 'Baramulla' },
    });
    assert.equal(profileRes.status, 200);
    assert.equal(profileRes.json.data.client.fullName, 'Amina Jan Updated');
    assert.equal(profileRes.json.data.client.city, 'Baramulla');

    // Guest order with Client A's email MUST NOT overwrite verified customer profile
    const guestSpoofOrder = await apiRequest('/api/v1/orders', {
      method: 'POST',
      body: {
        project_name: 'Spoofed Name Attempt',
        project_description: 'Testing that unauthenticated guest cannot overwrite verified customer.',
        budget: '₹15,000 – ₹30,000',
        customer_name: 'Hijacked Guest Name',
        customer_email: 'clienta@dtks-test.studio',
        customer_phone: '+91 90000 00000',
        customer_city: 'Nowhere',
      },
    });
    assert.equal(guestSpoofOrder.status, 201);
    const customerRow = await env.DB.prepare('SELECT full_name, city FROM customers WHERE id = ?')
      .bind(clientACustomerId)
      .first();
    assert.equal(customerRow.full_name, 'Amina Jan Updated');
    assert.equal(customerRow.city, 'Baramulla');

    // Refresh token rotation
    const refreshRes = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      body: { refreshToken: clientARefresh },
    });
    assert.equal(refreshRes.status, 200);
    assert.notEqual(refreshRes.json.data.refreshToken, clientARefresh);

    // Reusing old rotated refresh token triggers replay detection -> revokes all sessions
    const reuseRefresh = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      body: { refreshToken: clientARefresh },
    });
    assert.equal(reuseRefresh.status, 401);
    assert.equal(reuseRefresh.json.error.code, 'REFRESH_TOKEN_REPLAY_DETECTED');

    // Re-login Client A after replay cascade revocation before subsequent tests
    const reloginA = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '10.2.1.9',
      body: { email: 'clienta@dtks-test.studio', password: 'ClientA#2026!Strong' },
    });
    assert.equal(reloginA.status, 200);
    clientAToken = reloginA.json.data.accessToken;
    clientARefresh = reloginA.json.data.refreshToken;
  });

  it('D1. Client-Only Data Access, Cross-Token Isolation & IDOR Protection', async () => {
    // Register & verify Client B with their own order
    const regB = await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '10.2.2.1',
      body: {
        fullName: 'Bilal Ahmad',
        email: 'clientb@dtks-test.studio',
        phone: '+91 99061 77702',
        password: 'ClientB#2026!Strong',
        confirmPassword: 'ClientB#2026!Strong',
        acceptTerms: true,
      },
    });
    assert.equal(regB.status, 201);
    const verifyBToken = extractTokenFromLatestEmail('clientb@dtks-test.studio');
    await apiRequest('/api/v1/client/auth/verify-email', {
      method: 'POST',
      body: { token: verifyBToken },
    });
    const loginB = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '10.2.2.2',
      body: { email: 'clientb@dtks-test.studio', password: 'ClientB#2026!Strong' },
    });
    clientBToken = loginB.json.data.accessToken;

    // Client B submits an authenticated order and admin moves it to InProgress
    const orderBRes = await apiRequest('/api/v1/orders', {
      method: 'POST',
      token: clientBToken,
      body: {
        project_name: 'Bilal E-Commerce Portal',
        project_description: 'E-commerce storefront for Kashmiri Saffron.',
        budget: '₹30,000 – ₹60,000',
        customer_name: 'Bilal Ahmad',
        customer_email: 'clientb@dtks-test.studio',
        customer_phone: '+91 99061 77702',
      },
    });
    assert.equal(orderBRes.status, 201);
    clientBOrderId = orderBRes.json.data.order.id;

    await apiRequest(`/api/v1/orders/${clientBOrderId}`, {
      method: 'PATCH',
      token: superToken,
      body: {
        status: 'InProgress',
        quotation_amount: 42000,
        admin_notes: 'SECRET CLIENT B ADMIN NOTE',
        customer_update: 'Development sprint 1 started.',
      },
    });

    // Client A can read their own orders & quotations without admin_notes
    const clientAOrders = await apiRequest('/api/v1/client/orders', { token: clientAToken });
    assert.equal(clientAOrders.status, 200);
    assert.ok(clientAOrders.json.data.orders.length >= 1);
    assert.ok(!clientAOrders.json.data.orders.some((o) => o.id === clientBOrderId));
    for (const ord of clientAOrders.json.data.orders) {
      assert.equal(ord.admin_notes, undefined);
      assert.equal(ord.adminNotes, undefined);
      assert.equal(ord.internalNotes, undefined);
    }

    const clientAQuotes = await apiRequest('/api/v1/client/quotations', { token: clientAToken });
    assert.equal(clientAQuotes.status, 200);
    assert.ok(clientAQuotes.json.data.quotations.some((q) => q.quotationAmount === 24000));
    assert.ok(!clientAQuotes.json.data.quotations.some((q) => q.orderId === clientBOrderId));

    // Client B sees their InProgress project without admin_notes
    const clientBProjects = await apiRequest('/api/v1/client/projects', { token: clientBToken });
    assert.equal(clientBProjects.status, 200);
    assert.ok(clientBProjects.json.data.projects.some((p) => p.orderId === clientBOrderId));
    assert.equal(clientBProjects.json.data.projects[0].admin_notes, undefined);

    // IDOR check: Client A CANNOT access Client B's order by ID
    const idorAttempt = await apiRequest(`/api/v1/client/orders/${clientBOrderId}`, {
      token: clientAToken,
    });
    assert.equal(idorAttempt.status, 404);

    // Cross-authentication check: Client token CANNOT access Admin endpoints
    const clientToAdminStats = await apiRequest('/api/v1/admin/dashboard/stats', {
      token: clientAToken,
    });
    assert.equal(clientToAdminStats.status, 401);

    const clientToAdminMe = await apiRequest('/api/v1/auth/me', { token: clientAToken });
    assert.equal(clientToAdminMe.status, 401);

    const clientToAllOrders = await apiRequest('/api/v1/orders', { token: clientAToken });
    assert.equal(clientToAllOrders.status, 401);

    // Cross-authentication check: Admin token CANNOT access Client endpoints
    const adminToClientMe = await apiRequest('/api/v1/client/auth/me', { token: superToken });
    assert.equal(adminToClientMe.status, 401);

    const adminToClientOrders = await apiRequest('/api/v1/client/orders', { token: superToken });
    assert.equal(adminToClientOrders.status, 401);

    // Unauthenticated requests rejected
    const unauthClientOrders = await apiRequest('/api/v1/client/orders');
    assert.equal(unauthClientOrders.status, 401);
  });

  it('C2. Client Logout, Password Reset & Account Deactivation Lifecycle', async () => {
    // 1. Forgot password returns uniform 200 for nonexistent & existent emails
    const forgotNonExistent = await apiRequest('/api/v1/client/auth/forgot-password', {
      method: 'POST',
      ip: '10.2.3.1',
      body: { email: 'does-not-exist@dtks-test.studio' },
    });
    assert.equal(forgotNonExistent.status, 200);

    const forgotExistent = await apiRequest('/api/v1/client/auth/forgot-password', {
      method: 'POST',
      ip: '10.2.3.2',
      body: { email: 'clienta@dtks-test.studio' },
    });
    assert.equal(forgotExistent.status, 200);

    const rawResetToken = extractTokenFromLatestEmail('clienta@dtks-test.studio');
    const newClientAPassword = 'ClientA#2026!ResetNew';

    // Reset password revokes existing sessions
    const resetRes = await apiRequest('/api/v1/client/auth/reset-password', {
      method: 'POST',
      ip: '10.2.3.3',
      body: {
        token: rawResetToken,
        password: newClientAPassword,
        confirmPassword: newClientAPassword,
      },
    });
    assert.equal(resetRes.status, 200);
    assert.equal(resetRes.json.data.reset, true);

    // Token reuse rejected
    const reuseResetRes = await apiRequest('/api/v1/client/auth/reset-password', {
      method: 'POST',
      ip: '10.2.3.4',
      body: {
        token: rawResetToken,
        password: newClientAPassword,
        confirmPassword: newClientAPassword,
      },
    });
    assert.equal(reuseResetRes.status, 400);

    // Old access & refresh tokens are immediately invalid after password reset
    const oldAccessAfterReset = await apiRequest('/api/v1/client/auth/me', { token: clientAToken });
    assert.equal(oldAccessAfterReset.status, 401);

    const oldRefreshAfterReset = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      body: { refreshToken: clientARefresh },
    });
    assert.equal(oldRefreshAfterReset.status, 401);

    // Log in with new password
    const newLoginRes = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '10.2.3.5',
      body: { email: 'clienta@dtks-test.studio', password: newClientAPassword },
    });
    assert.equal(newLoginRes.status, 200);
    const freshToken = newLoginRes.json.data.accessToken;
    const freshRefresh = newLoginRes.json.data.refreshToken;

    // Logout revokes refresh token
    const logoutRes = await apiRequest('/api/v1/client/auth/logout', {
      method: 'POST',
      token: freshToken,
      body: { refreshToken: freshRefresh },
    });
    assert.equal(logoutRes.status, 200);

    const refreshAfterLogout = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      body: { refreshToken: freshRefresh },
    });
    assert.equal(refreshAfterLogout.status, 401);

    // Log in again and deactivate Client A account
    const loginBeforeDeact = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '10.2.3.6',
      body: { email: 'clienta@dtks-test.studio', password: newClientAPassword },
    });
    const activeTokenBeforeDeact = loginBeforeDeact.json.data.accessToken;

    const deactRes = await apiRequest('/api/v1/client/auth/deactivate', {
      method: 'POST',
      token: activeTokenBeforeDeact,
      body: { password: newClientAPassword },
    });
    assert.equal(deactRes.status, 200);
    assert.equal(deactRes.json.data.deactivated, true);

    // Subsequent API call and login rejected for deactivated client
    const postDeactMe = await apiRequest('/api/v1/client/auth/me', {
      token: activeTokenBeforeDeact,
    });
    assert.equal(postDeactMe.status, 403);
    assert.equal(postDeactMe.json.error.code, 'ACCOUNT_DEACTIVATED');

    const postDeactLogin = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '10.2.3.7',
      body: { email: 'clienta@dtks-test.studio', password: newClientAPassword },
    });
    assert.equal(postDeactLogin.status, 403);
    assert.equal(postDeactLogin.json.error.code, 'ACCOUNT_DEACTIVATED');

    // Audit log sanity check: sensitive operations logged without raw tokens or passwords
    const logsRes = await apiRequest('/api/v1/admin/activity-logs?limit=100', {
      token: superToken,
    });
    assert.equal(logsRes.status, 200);
    const serializedLogs = JSON.stringify(logsRes.json.data.logs);
    assert.ok(serializedLogs.includes('ADMIN_ACCOUNT_CREATED'));
    assert.ok(serializedLogs.includes('ADMIN_ACCOUNT_DEACTIVATED'));
    assert.ok(serializedLogs.includes('ADMIN_SESSIONS_REVOKED'));
    assert.ok(serializedLogs.includes('CLIENT_EMAIL_VERIFIED'));
    assert.ok(serializedLogs.includes('CLIENT_PASSWORD_RESET_COMPLETED'));
    assert.ok(serializedLogs.includes('CLIENT_ACCOUNT_DEACTIVATED'));
    assert.ok(!serializedLogs.includes(rawResetToken));
    assert.ok(!serializedLogs.includes(newClientAPassword));
  });

  it('A6. Admin Account Listing Filtering, Search, Legacy Compatibility & Pagination Normalization', async () => {
    // Filter by status=active vs status=inactive vs status=all
    const activeRes = await apiRequest('/api/v1/admin/accounts?status=active', { token: superToken });
    assert.equal(activeRes.status, 200);
    assert.ok(activeRes.json.data.accounts.every((a) => a.isActive === true));
    assert.equal(
      activeRes.json.data.pagination.total,
      activeRes.json.data.accounts.length
    );

    const inactiveRes = await apiRequest('/api/v1/admin/accounts?status=inactive', {
      token: superToken,
    });
    assert.equal(inactiveRes.status, 200);
    assert.ok(inactiveRes.json.data.accounts.length >= 2);
    assert.ok(inactiveRes.json.data.accounts.every((a) => a.isActive === false));

    // Legacy isActive / is_active compatibility
    const legacyInactive = await apiRequest('/api/v1/admin/accounts?isActive=false', {
      token: superToken,
    });
    assert.equal(legacyInactive.status, 200);
    assert.equal(legacyInactive.json.data.pagination.total, inactiveRes.json.data.pagination.total);

    // Search + role combination
    const roleSearchRes = await apiRequest(
      '/api/v1/admin/accounts?role=editor&search=editor&status=all',
      { token: superToken }
    );
    assert.equal(roleSearchRes.status, 200);
    assert.equal(roleSearchRes.json.data.pagination.total, 1);
    assert.equal(roleSearchRes.json.data.accounts[0].email, 'editor@dtks-test.studio');

    // Invalid page & limit normalization
    const normalizedRes = await apiRequest('/api/v1/admin/accounts?page=-5&limit=abc', {
      token: superToken,
    });
    assert.equal(normalizedRes.status, 200);
    assert.equal(normalizedRes.json.data.pagination.page, 1);
    assert.equal(normalizedRes.json.data.pagination.limit, 20);

    // Multi-page pagination totals match filtered counts
    const page1 = await apiRequest('/api/v1/admin/accounts?status=all&page=1&limit=2', {
      token: superToken,
    });
    const page2 = await apiRequest('/api/v1/admin/accounts?status=all&page=2&limit=2', {
      token: superToken,
    });
    assert.equal(page1.status, 200);
    assert.equal(page2.status, 200);
    assert.equal(page1.json.data.accounts.length, 2);
    assert.ok(page1.json.data.pagination.total >= 4);
    assert.equal(page1.json.data.pagination.hasNextPage, true);
    assert.equal(page1.json.data.pagination.hasPrevPage, false);
    assert.equal(page2.json.data.pagination.hasPrevPage, true);
    assert.notEqual(page1.json.data.accounts[0].id, page2.json.data.accounts[0].id);
  });

  it('A7. Concurrent Invite Acceptance, Deactivated Pending Account, Admin Change Password & Multi-Device Logout', async () => {
    // 1. Custom invite expiry via env override & missing confirmPassword validation
    const createCustomExpiry = await apiRequest('/api/v1/admin/accounts', {
      method: 'POST',
      token: superToken,
      customEnv: { ...env, ADMIN_INVITE_EXPIRY_SECONDS: '7200' },
      body: {
        name: 'Concurrent Invite Admin',
        email: 'concurrent.admin@dtks-test.studio',
        role: 'admin',
      },
    });
    assert.equal(createCustomExpiry.status, 201);
    const expiresDeltaMs =
      new Date(createCustomExpiry.json.data.invitationExpiresAt).getTime() - Date.now();
    assert.ok(expiresDeltaMs > 3600 * 1000 && expiresDeltaMs <= 7200 * 1000 + 5000);

    const raceToken = extractTokenFromLatestEmail('concurrent.admin@dtks-test.studio');

    // Missing confirmPassword produces distinct validation error
    const missingConfirm = await apiRequest('/api/v1/auth/accept-invite', {
      method: 'POST',
      body: { token: raceToken, password: 'RaceAdmin#2026!Strong' },
    });
    assert.equal(missingConfirm.status, 400);
    assert.equal(missingConfirm.json.error.details.confirmPassword, 'Password confirmation is required.');

    // Concurrent invite acceptance: strictly one succeeds, one fails with INVITE_TOKEN_ALREADY_USED
    const [raceA, raceB] = await Promise.all([
      apiRequest('/api/v1/auth/accept-invite', {
        method: 'POST',
        body: {
          token: raceToken,
          password: 'RaceAdmin#2026!Strong',
          confirmPassword: 'RaceAdmin#2026!Strong',
        },
      }),
      apiRequest('/api/v1/auth/accept-invite', {
        method: 'POST',
        body: {
          token: raceToken,
          password: 'RaceAdmin#2026!Strong',
          confirmPassword: 'RaceAdmin#2026!Strong',
        },
      }),
    ]);
    const raceStatuses = [raceA.status, raceB.status].sort();
    assert.deepEqual(raceStatuses, [200, 400]);

    // 2. Deactivated pending admin cannot resend or accept invite
    const pendingDeactCreate = await apiRequest('/api/v1/admin/accounts', {
      method: 'POST',
      token: superToken,
      body: {
        name: 'Deactivated Pending',
        email: 'deactivated.pending@dtks-test.studio',
        role: 'editor',
      },
    });
    assert.equal(pendingDeactCreate.status, 201);
    const pendingDeactId = pendingDeactCreate.json.data.account.id;
    const pendingDeactToken = extractTokenFromLatestEmail('deactivated.pending@dtks-test.studio');

    const deactPendingRes = await apiRequest(`/api/v1/admin/accounts/${pendingDeactId}/status`, {
      method: 'PATCH',
      token: superToken,
      body: { isActive: false },
    });
    assert.equal(deactPendingRes.status, 200);

    const resendDeact = await apiRequest(`/api/v1/admin/accounts/${pendingDeactId}/resend-invite`, {
      method: 'POST',
      token: superToken,
    });
    assert.equal(resendDeact.status, 403);
    assert.equal(resendDeact.json.error.code, 'ACCOUNT_DEACTIVATED');

    const acceptDeact = await apiRequest('/api/v1/auth/accept-invite', {
      method: 'POST',
      body: {
        token: pendingDeactToken,
        password: 'DeactAdmin#2026!Strong',
        confirmPassword: 'DeactAdmin#2026!Strong',
      },
    });
    assert.equal(acceptDeact.status, 403);
    assert.equal(acceptDeact.json.error.code, 'ACCOUNT_DEACTIVATED');

    // 3. Admin single-device vs allDevices logout + change-password session invalidation
    const dev1Login = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '10.3.0.1',
      body: { email: 'concurrent.admin@dtks-test.studio', password: 'RaceAdmin#2026!Strong' },
    });
    const dev2Login = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '10.3.0.2',
      body: { email: 'concurrent.admin@dtks-test.studio', password: 'RaceAdmin#2026!Strong' },
    });
    assert.equal(dev1Login.status, 200);
    assert.equal(dev2Login.status, 200);

    // Single-device logout revokes only dev1 refresh token, leaving dev2 working
    const singleLogout = await apiRequest('/api/v1/auth/logout', {
      method: 'POST',
      token: dev1Login.json.data.accessToken,
      body: { refreshToken: dev1Login.json.data.refreshToken },
    });
    assert.equal(singleLogout.status, 200);
    assert.equal(singleLogout.json.data.allDevices, false);
    assert.equal(singleLogout.json.data.scope, 'single_device');

    const dev1RefreshAfter = await apiRequest('/api/v1/auth/refresh', {
      method: 'POST',
      body: { refreshToken: dev1Login.json.data.refreshToken },
    });
    assert.equal(dev1RefreshAfter.status, 401);

    const dev2MeStillWorks = await apiRequest('/api/v1/auth/me', {
      token: dev2Login.json.data.accessToken,
    });
    assert.equal(dev2MeStillWorks.status, 200);

    // Change password invalidates dev2 access & refresh tokens
    const changeAdminPw = await apiRequest('/api/v1/auth/change-password', {
      method: 'POST',
      token: dev2Login.json.data.accessToken,
      body: {
        currentPassword: 'RaceAdmin#2026!Strong',
        newPassword: 'RaceAdmin#2026!Changed',
        confirmPassword: 'RaceAdmin#2026!Changed',
      },
    });
    assert.equal(changeAdminPw.status, 200);

    const dev2MeAfterPwChange = await apiRequest('/api/v1/auth/me', {
      token: dev2Login.json.data.accessToken,
    });
    assert.equal(dev2MeAfterPwChange.status, 401);
    assert.equal(dev2MeAfterPwChange.json.error.code, 'SESSION_REVOKED');

    const dev2RefreshAfterPwChange = await apiRequest('/api/v1/auth/refresh', {
      method: 'POST',
      body: { refreshToken: dev2Login.json.data.refreshToken },
    });
    assert.equal(dev2RefreshAfterPwChange.status, 401);
  });

  it('B2. Client Legal Acceptance Enforcement, Email Failure Propagation & Malformed JSON Handling', async () => {
    // Missing acceptTerms, false acceptTerms, and string 'false' must all fail validation
    for (const badTermsPayload of [
      {},
      { acceptTerms: false },
      { acceptTerms: 'false' },
      { acceptTerms: true, acceptPrivacy: false },
    ]) {
      const res = await apiRequest('/api/v1/client/auth/register', {
        method: 'POST',
        ip: '10.4.0.1',
        body: {
          fullName: 'Legal Reject User',
          email: 'legal-reject@dtks-test.studio',
          phone: '+91 99061 88801',
          password: 'Client#2026!Strong',
          confirmPassword: 'Client#2026!Strong',
          ...badTermsPayload,
        },
      });
      assert.equal(res.status, 400);
      assert.equal(res.json.error.code, 'VALIDATION_ERROR');
    }

    // Malformed JSON body returns structured 400 MALFORMED_JSON
    const malformedRes = await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '10.4.0.2',
      headers: { 'Content-Type': 'application/json' },
      body: '{"fullName": "Broken JSON',
    });
    assert.equal(malformedRes.status, 400);
    assert.equal(malformedRes.json.error.code, 'MALFORMED_JSON');

    // Valid client registration persists legal acceptance columns in D1
    const regClientC = await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '10.4.0.3',
      body: {
        fullName: 'Tariq Lone',
        email: 'clientc@dtks-test.studio',
        phone: '+91 99061 88803',
        password: 'ClientC#2026!Strong',
        confirmPassword: 'ClientC#2026!Strong',
        acceptTerms: true,
        acceptPrivacy: true,
        termsVersion: '2026-02',
        privacyVersion: '2026-02',
      },
    });
    assert.equal(regClientC.status, 201);
    const clientCId = regClientC.json.data.account.id;

    const dbRow = await env.DB.prepare(
      `SELECT terms_accepted, terms_accepted_at, terms_version,
              privacy_accepted, privacy_accepted_at, privacy_version, legal_accepted_ip
       FROM customer_accounts WHERE id = ?`
    )
      .bind(clientCId)
      .first();
    assert.equal(dbRow.terms_accepted, 1);
    assert.ok(dbRow.terms_accepted_at);
    assert.equal(dbRow.terms_version, '2026-02');
    assert.equal(dbRow.privacy_accepted, 1);
    assert.ok(dbRow.privacy_accepted_at);
    assert.equal(dbRow.privacy_version, '2026-02');
    assert.equal(dbRow.legal_accepted_ip, '10.4.0.3');

    // Resend verification failure returns uniform 200 OK (anti-enumeration), revokes ONLY failed token,
    // keeps prior unused verification token valid, and logs an internal audit event
    const oldTokenC = extractTokenFromLatestEmail('clientc@dtks-test.studio');
    emailShouldFail = true;
    const resendFail = await apiRequest('/api/v1/client/auth/resend-verification', {
      method: 'POST',
      ip: '10.4.0.4',
      body: { email: 'clientc@dtks-test.studio' },
    });
    emailShouldFail = false;
    assert.equal(resendFail.status, 200);
    assert.deepEqual(resendFail.json.data, { requested: true });

    // Resend verification recovery succeeds and revokes older token
    const resendOk = await apiRequest('/api/v1/client/auth/resend-verification', {
      method: 'POST',
      ip: '10.4.0.5',
      body: { email: 'clientc@dtks-test.studio' },
    });
    assert.equal(resendOk.status, 200);
    const newTokenC = extractTokenFromLatestEmail('clientc@dtks-test.studio');
    assert.notEqual(newTokenC, oldTokenC);

    const oldVerifyAttempt = await apiRequest('/api/v1/client/auth/verify-email', {
      method: 'POST',
      body: { token: oldTokenC },
    });
    assert.equal(oldVerifyAttempt.status, 400);

    const verifyOk = await apiRequest('/api/v1/client/auth/verify-email', {
      method: 'POST',
      body: { token: newTokenC },
    });
    assert.equal(verifyOk.status, 200);

    // Forgot password failure for verified client returns uniform 200 OK (anti-enumeration)
    emailShouldFail = true;
    const forgotFail = await apiRequest('/api/v1/client/auth/forgot-password', {
      method: 'POST',
      ip: '10.4.0.6',
      body: { email: 'clientc@dtks-test.studio' },
    });
    emailShouldFail = false;
    assert.equal(forgotFail.status, 200);
    assert.deepEqual(forgotFail.json.data, { requested: true });
  });

  it('C3. Client Reset Password (newPassword/Concurrency), Change Password Invalidation & Single vs All-Devices Logout', async () => {
    // 1. Trigger password reset for Client C
    const forgotOk = await apiRequest('/api/v1/client/auth/forgot-password', {
      method: 'POST',
      ip: '10.5.0.1',
      body: { email: 'clientc@dtks-test.studio' },
    });
    assert.equal(forgotOk.status, 200);
    const resetTok = extractTokenFromLatestEmail('clientc@dtks-test.studio');

    // Validation with newPassword key + missing confirmPassword returns distinct field errors
    const missingConfirmReset = await apiRequest('/api/v1/client/auth/reset-password', {
      method: 'POST',
      ip: '10.5.0.2',
      body: { token: resetTok, newPassword: 'weak' },
    });
    assert.equal(missingConfirmReset.status, 400);
    assert.ok(missingConfirmReset.json.error.details.newPassword);
    assert.equal(
      missingConfirmReset.json.error.details.confirmPassword,
      'Password confirmation is required.'
    );

    // Concurrent reset-password requests with newPassword + confirmPassword: strictly one succeeds
    const nextPass = 'ClientC#2026!ResetStrong';
    const [r1, r2] = await Promise.all([
      apiRequest('/api/v1/client/auth/reset-password', {
        method: 'POST',
        ip: '10.5.0.3',
        body: { token: resetTok, newPassword: nextPass, confirmPassword: nextPass },
      }),
      apiRequest('/api/v1/client/auth/reset-password', {
        method: 'POST',
        ip: '10.5.0.4',
        body: { token: resetTok, newPassword: nextPass, confirmPassword: nextPass },
      }),
    ]);
    assert.deepEqual([r1.status, r2.status].sort(), [200, 400]);

    // 2. Log Client C in on Device 1 and Device 2
    const dev1 = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '10.5.0.5',
      body: { email: 'clientc@dtks-test.studio', password: nextPass },
    });
    const dev2 = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '10.5.0.6',
      body: { email: 'clientc@dtks-test.studio', password: nextPass },
    });
    assert.equal(dev1.status, 200);
    assert.equal(dev2.status, 200);

    // Check /client/auth/me exposes persisted legal acceptance metadata
    const meC = await apiRequest('/api/v1/client/auth/me', {
      token: dev1.json.data.accessToken,
    });
    assert.equal(meC.status, 200);
    assert.equal(meC.json.data.client.termsAccepted, true);
    assert.equal(meC.json.data.client.termsVersion, '2026-02');
    assert.equal(meC.json.data.client.privacyAccepted, true);

    // Unauthenticated allDevices: true logout must be rejected with 401
    const unauthAllLogout = await apiRequest('/api/v1/client/auth/logout', {
      method: 'POST',
      body: { refreshToken: dev1.json.data.refreshToken, allDevices: true },
    });
    assert.equal(unauthAllLogout.status, 401);

    // Non-boolean allDevices rejected with 400
    const badAllDevicesType = await apiRequest('/api/v1/client/auth/logout', {
      method: 'POST',
      token: dev1.json.data.accessToken,
      body: { allDevices: 'yes' },
    });
    assert.equal(badAllDevicesType.status, 400);

    // Single-device logout on Device 1 leaves Device 2 working
    const singleLogoutC = await apiRequest('/api/v1/client/auth/logout', {
      method: 'POST',
      token: dev1.json.data.accessToken,
      body: { refreshToken: dev1.json.data.refreshToken },
    });
    assert.equal(singleLogoutC.status, 200);
    assert.equal(singleLogoutC.json.data.allDevices, false);
    assert.equal(singleLogoutC.json.data.scope, 'single_device');
    assert.equal(singleLogoutC.json.data.sessionsRevoked, 1);

    const dev1RefreshFail = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      body: { refreshToken: dev1.json.data.refreshToken },
    });
    assert.equal(dev1RefreshFail.status, 401);

    const dev2MeOk = await apiRequest('/api/v1/client/auth/me', {
      token: dev2.json.data.accessToken,
    });
    assert.equal(dev2MeOk.status, 200);

    // All-devices logout on Device 2 invalidates Device 2 access & refresh tokens
    const allLogoutC = await apiRequest('/api/v1/client/auth/logout', {
      method: 'POST',
      token: dev2.json.data.accessToken,
      body: { refreshToken: dev2.json.data.refreshToken, allDevices: true },
    });
    assert.equal(allLogoutC.status, 200);
    assert.equal(allLogoutC.json.data.allDevices, true);
    assert.equal(allLogoutC.json.data.scope, 'all_devices');

    const dev2MeRevoked = await apiRequest('/api/v1/client/auth/me', {
      token: dev2.json.data.accessToken,
    });
    assert.equal(dev2MeRevoked.status, 401);
    assert.equal(dev2MeRevoked.json.error.code, 'SESSION_REVOKED');

    const dev2RefreshRevoked = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      body: { refreshToken: dev2.json.data.refreshToken },
    });
    assert.equal(dev2RefreshRevoked.status, 401);

    // 3. Change-password revokes active client access & refresh tokens
    const loginBeforeChange = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '10.5.0.7',
      body: { email: 'clientc@dtks-test.studio', password: nextPass },
    });
    assert.equal(loginBeforeChange.status, 200);

    const changedPass = 'ClientC#2026!ChangedStrong';
    const changeClientPw = await apiRequest('/api/v1/client/auth/change-password', {
      method: 'POST',
      token: loginBeforeChange.json.data.accessToken,
      body: {
        currentPassword: nextPass,
        newPassword: changedPass,
        confirmPassword: changedPass,
      },
    });
    assert.equal(changeClientPw.status, 200);

    const oldClientMe = await apiRequest('/api/v1/client/auth/me', {
      token: loginBeforeChange.json.data.accessToken,
    });
    assert.equal(oldClientMe.status, 401);
    assert.equal(oldClientMe.json.error.code, 'SESSION_REVOKED');

    const oldClientRefresh = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      body: { refreshToken: loginBeforeChange.json.data.refreshToken },
    });
    assert.equal(oldClientRefresh.status, 401);
  });

  it('E1. Migration 0004 Re-Open Idempotency on Existing SQLite Database', async () => {
    env?.DB?.close?.();
    env = createNodeWorkerEnv({
      dbPath,
      r2Dir,
      overrides: {
        ENVIRONMENT: 'development',
        APP_URL: 'https://dreamtechkashmirsolutions.studio',
        JWT_SECRET: TEST_JWT_SECRET,
        INITIAL_ADMIN_NAME: 'Principal Super Admin',
        INITIAL_ADMIN_EMAIL: TEST_SUPER_EMAIL,
        INITIAL_ADMIN_PASSWORD: TEST_SUPER_PASSWORD,
        RESEND_API_KEY: 're_test_live_mock_key_123456',
      },
    });
    const checkCol = await env.DB.prepare(
      'SELECT terms_accepted, privacy_version FROM customer_accounts LIMIT 1'
    ).first();
    assert.ok(checkCol !== undefined);
  });
});


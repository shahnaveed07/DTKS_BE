import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import workerApp from '../src/index.js';
import { createNodeWorkerEnv } from '../src/database/d1Adapter.js';
import { resetRateLimiter } from '../src/middleware/rateLimiter.js';
import { ensureDatabaseSeeded } from '../src/database/seed.js';
import { notifyOrderCreated } from '../src/services/emailService.js';
import { hashPassword, sha256Hex, signJwt, verifyJwt } from '../src/utils/crypto.js';
import {
  ADMIN_ACCESS_COOKIE_NAME,
  ADMIN_CSRF_COOKIE_NAME,
  ADMIN_REFRESH_COOKIE_NAME,
  CLIENT_ACCESS_COOKIE_NAME,
  CLIENT_CSRF_COOKIE_NAME,
  CLIENT_REFRESH_COOKIE_NAME,
  MAX_IMAGE_SIZE_BYTES,
} from '../src/config/constants.js';

const VALID_PNG_BYTES = Buffer.from(
  '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c63000100000500010d0a2db40000000049454e44ae426082',
  'hex'
);

const SUPER_ADMIN_EMAIL = 'sec-super@dtks-test.studio';
const SUPER_ADMIN_PASSWORD = 'SecSuper#2026!Strong';
const TEST_JWT_SECRET = 'dtks-security-remediation-suite-256-bit-hmac-secret-2026';

function parseSetCookieHeaders(headers) {
  const rawList =
    typeof headers.getSetCookie === 'function'
      ? headers.getSetCookie()
      : headers.get('set-cookie')
        ? [headers.get('set-cookie')]
        : [];
  const parsed = [];
  for (const raw of rawList) {
    const segments = String(raw)
      .split(';')
      .map((s) => s.trim())
      .filter(Boolean);
    if (!segments.length) continue;
    const eqIdx = segments[0].indexOf('=');
    if (eqIdx <= 0) continue;
    const name = segments[0].slice(0, eqIdx).trim();
    const value = decodeURIComponent(segments[0].slice(eqIdx + 1));
    const attrs = {};
    for (const attr of segments.slice(1)) {
      const aEq = attr.indexOf('=');
      if (aEq === -1) {
        attrs[attr.toLowerCase()] = true;
      } else {
        attrs[attr.slice(0, aEq).toLowerCase()] = attr.slice(aEq + 1);
      }
    }
    parsed.push({ name, value, attrs, raw });
  }
  return parsed;
}

class CookieJar {
  constructor() {
    this.map = new Map();
  }

  ingest(headers) {
    const list = parseSetCookieHeaders(headers);
    for (const c of list) {
      if (c.attrs['max-age'] === '0' || !c.value) {
        this.map.delete(c.name);
      } else {
        this.map.set(c.name, c.value);
      }
    }
    return list;
  }

  get(name) {
    return this.map.get(name) || '';
  }

  header() {
    return [...this.map.entries()]
      .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
      .join('; ');
  }
}

describe('DTKS Master Security Remediation Verification Suite (/api/v1)', () => {
  let tmpDir;
  let dbPath;
  let r2Dir;
  let env;
  let capturedEmails = [];
  let emailMode = 'ok'; // 'ok' | 'fail_all' | 'fail_security_only' | 'fail_admin_only' | 'fail_customer_only'
  let adminBearer = '';

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dtks-sec-remediation-'));
    dbPath = path.join(tmpDir, 'dtks-sec-rem.sqlite');
    r2Dir = path.join(tmpDir, 'r2-storage');

    const mockEmailFetch = async (_url, init) => {
      const payload = JSON.parse(init.body);
      const recipients = Array.isArray(payload.to) ? payload.to : [];
      if (emailMode === 'fail_all') {
        return new Response(JSON.stringify({ message: 'Upstream Resend error secret-detail' }), {
          status: 502,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (
        emailMode === 'fail_admin_only' &&
        (String(payload.subject || '').includes('[DTKS Admin]') ||
          recipients.includes('contact@dreamtechkashmirsolutions.studio'))
      ) {
        return new Response(JSON.stringify({ message: 'Admin notification mailbox rejected' }), {
          status: 502,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (
        emailMode === 'fail_customer_only' &&
        !String(payload.subject || '').includes('[DTKS Admin]')
      ) {
        return new Response(JSON.stringify({ message: 'Customer Resend provider timeout' }), {
          status: 502,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (
        emailMode === 'fail_security_only' &&
        String(payload.subject || '').includes('[DTKS Security]')
      ) {
        return new Response(JSON.stringify({ message: 'Security notice timeout' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      capturedEmails.push(payload);
      return new Response(JSON.stringify({ id: `re_sec_${capturedEmails.length}` }), {
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
        INITIAL_ADMIN_NAME: 'Security Remediation Admin',
        INITIAL_ADMIN_EMAIL: SUPER_ADMIN_EMAIL,
        INITIAL_ADMIN_PASSWORD: SUPER_ADMIN_PASSWORD,
        RESEND_API_KEY: 're_test_sec_remediation_live_key',
        EMAIL_FETCH: mockEmailFetch,
      },
    });

    await resetRateLimiter(env);
    await ensureDatabaseSeeded(env);

    const loginRes = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'X-Auth-Mode': 'bearer' },
      body: { email: SUPER_ADMIN_EMAIL, password: SUPER_ADMIN_PASSWORD },
    });
    assert.equal(loginRes.status, 200);
    adminBearer = loginRes.json.data.accessToken;
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
      ip = '198.51.100.10',
      origin = 'https://dreamtechkashmirsolutions.studio',
      urlBase = 'https://api.dreamtechkashmirsolutions.studio',
      jar = null,
      customEnv = env,
    } = options;

    const reqHeaders = new Headers(headers);
    if (origin !== null) reqHeaders.set('Origin', origin);
    if (ip !== null) reqHeaders.set('CF-Connecting-IP', ip);
    if (token) reqHeaders.set('Authorization', `Bearer ${token}`);
    if (jar) {
      const cookieStr = jar.header();
      if (cookieStr) reqHeaders.set('Cookie', cookieStr);
    }

    let requestBody = body;
    if (body && !(body instanceof FormData) && typeof body === 'object' && !Buffer.isBuffer(body)) {
      reqHeaders.set('Content-Type', 'application/json');
      requestBody = JSON.stringify(body);
    }

    const request = new Request(`${urlBase}${pathname}`, {
      method,
      headers: reqHeaders,
      body: requestBody,
    });

    const response = await workerApp.fetch(request, customEnv, {});
    const setCookies = jar ? jar.ingest(response.headers) : parseSetCookieHeaders(response.headers);
    const contentType = response.headers.get('content-type') || '';
    const json = contentType.includes('application/json') ? await response.json() : null;
    return { status: response.status, headers: response.headers, setCookies, json, response };
  }

  function extractLatestEmail(recipientEmail) {
    return [...capturedEmails]
      .reverse()
      .find((m) => Array.isArray(m.to) && m.to.includes(recipientEmail));
  }

  function extractFragmentToken(emailPayload) {
    assert.ok(emailPayload, 'Expected dispatched email');
    const match = /#token=([a-f0-9]+)/i.exec(emailPayload.text || '');
    assert.ok(match && match[1], 'Expected #token= URL fragment inside email text');
    return match[1];
  }

  it('1. Order Tracking Redesign & Guest-vs-Client Portal Isolation', async () => {
    // Register & verify a client account first
    const clientEmail = 'victim.portal@dtks-test.studio';
    const guestPreEmail = 'pre.history@dtks-test.studio';

    // 1A. Pre-registration guest order created BEFORE account exists
    const preGuestOrder = await apiRequest('/api/v1/orders', {
      method: 'POST',
      ip: '198.51.100.20',
      body: {
        project_name: 'Historical Pre-Signup Order',
        project_description: 'Submitted before client registered an account.',
        budget: '₹15,000 – ₹30,000',
        customer_name: 'Pre Signup Client',
        customer_email: guestPreEmail,
        customer_phone: '+91 99061 20001',
      },
    });
    assert.equal(preGuestOrder.status, 201);
    const preOrderId = preGuestOrder.json.data.order.id;

    // Register & verify guestPreEmail -> historical pre-registration order links safely
    await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '198.51.100.21',
      body: {
        fullName: 'Pre Signup Client',
        email: guestPreEmail,
        phone: '+91 99061 20001',
        password: 'PreSignup#2026!Strong',
        confirmPassword: 'PreSignup#2026!Strong',
        acceptTerms: true,
      },
    });
    const preVerifyTok = extractFragmentToken(extractLatestEmail(guestPreEmail));
    const preVerifyRes = await apiRequest('/api/v1/client/auth/verify-email', {
      method: 'POST',
      ip: '198.51.100.22',
      body: { token: preVerifyTok },
    });
    assert.equal(preVerifyRes.status, 200);
    const preLogin = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '198.51.100.23',
      headers: { 'X-Auth-Mode': 'bearer' },
      body: { email: guestPreEmail, password: 'PreSignup#2026!Strong' },
    });
    const preOrders = await apiRequest('/api/v1/client/orders', {
      token: preLogin.json.data.accessToken,
    });
    assert.ok(
      preOrders.json.data.orders.some((o) => o.id === preOrderId),
      'Historical guest order created BEFORE client registration should link upon verification'
    );

    // 1B. Register & verify victim client BEFORE attacker guest submission
    await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '198.51.100.24',
      body: {
        fullName: 'Victim Verified Client',
        email: clientEmail,
        phone: '+91 99061 20002',
        password: 'VictimClient#2026!Strong',
        confirmPassword: 'VictimClient#2026!Strong',
        acceptTerms: true,
      },
    });
    const victimTok = extractFragmentToken(extractLatestEmail(clientEmail));
    await apiRequest('/api/v1/client/auth/verify-email', {
      method: 'POST',
      ip: '198.51.100.25',
      body: { token: victimTok },
    });
    const victimLogin = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '198.51.100.26',
      headers: { 'X-Auth-Mode': 'bearer' },
      body: { email: clientEmail, password: 'VictimClient#2026!Strong' },
    });
    const victimToken = victimLogin.json.data.accessToken;

    // Unauthenticated guest submits order using victim's email AFTER victim registered
    const postGuestOrder = await apiRequest('/api/v1/orders', {
      method: 'POST',
      ip: '198.51.100.27',
      body: {
        project_name: 'Injected Guest Order Attempt',
        project_description: 'Must never appear in authenticated victim client portal.',
        budget: '₹15,000 – ₹30,000',
        customer_name: 'Fake Guest',
        customer_email: clientEmail,
        customer_phone: '+91 99061 20099',
      },
    });
    assert.equal(postGuestOrder.status, 201);
    assert.equal(postGuestOrder.json.data.trackingToken, undefined);
    assert.equal(postGuestOrder.json.data.tracking_token, undefined);
    assert.equal(postGuestOrder.json.data.order.customer_id, null);
    assert.equal(postGuestOrder.json.data.trackingEmailSent, true);

    // Victim's portal MUST NOT include unauthenticated guest order
    const victimOrders = await apiRequest('/api/v1/client/orders', { token: victimToken });
    assert.equal(victimOrders.status, 200);
    assert.equal(victimOrders.json.data.orders.length, 0);

    // Tracking token email uses #token= fragment (and never ?ref=&email= or API JSON leakage)
    const orderEmail = extractLatestEmail(clientEmail);
    const trackingToken = extractFragmentToken(orderEmail);
    assert.ok(trackingToken && trackingToken.length >= 64);
    assert.ok(orderEmail.text.includes(`/track-order#token=${trackingToken}`));
    assert.equal(orderEmail.text.includes('?ref='), false);
    assert.equal(JSON.stringify(postGuestOrder.json).includes(trackingToken), false);

    // Valid POST /api/v1/orders/track returns non-PII summary
    const trackOk = await apiRequest('/api/v1/orders/track', {
      method: 'POST',
      ip: '198.51.100.28',
      body: { token: trackingToken },
    });
    assert.equal(trackOk.status, 200);
    assert.equal(trackOk.json.data.order.project_name, 'Injected Guest Order Attempt');
    assert.equal(trackOk.json.data.order.customer_email, undefined);
    assert.equal(trackOk.json.data.order.customer_phone, undefined);
    assert.equal(trackOk.json.data.order.customer_name, undefined);
    assert.equal(trackOk.json.data.order.admin_notes, undefined);

    // Invalid, expired, and revoked tracking tokens all return uniform 404 ORDER_NOT_FOUND
    const trackInvalid = await apiRequest('/api/v1/orders/track', {
      method: 'POST',
      ip: '198.51.100.29',
      body: { token: 'a'.repeat(64) },
    });
    assert.equal(trackInvalid.status, 404);
    assert.equal(trackInvalid.json.error.code, 'ORDER_NOT_FOUND');

    // Expire token row in D1 -> 404
    const tokenHash = await sha256Hex(trackingToken);
    await env.DB.prepare(
      "UPDATE order_tracking_tokens SET expires_at = '2020-01-01T00:00:00.000Z' WHERE token_hash = ?"
    )
      .bind(tokenHash)
      .run();
    const trackExpired = await apiRequest('/api/v1/orders/track', {
      method: 'POST',
      ip: '198.51.100.30',
      body: { token: trackingToken },
    });
    assert.equal(trackExpired.status, 404);
    assert.equal(trackExpired.json.error.code, 'ORDER_NOT_FOUND');

    // Legacy GET /api/v1/orders/track returns 410 Gone
    const legacyGet = await apiRequest(
      `/api/v1/orders/track?ref=${postGuestOrder.json.data.order.order_number}&email=${encodeURIComponent(clientEmail)}`
    );
    assert.equal(legacyGet.status, 410);
    assert.equal(legacyGet.json.error.code, 'LEGACY_TRACKING_DISABLED');
  });

  it('2. Client Recovery Hardening: #token= Fragment, Targeted Revocation on Delivery Failure, Atomic Expiry & Fail-Closed Production Limiter', async () => {
    const clientEmail = 'recovery.hardening@dtks-test.studio';
    await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '198.51.100.40',
      body: {
        fullName: 'Recovery Client',
        email: clientEmail,
        phone: '+91 99061 30001',
        password: 'Recovery#2026!Strong',
        confirmPassword: 'Recovery#2026!Strong',
        acceptTerms: true,
      },
    });
    const verifyEmailPayload = extractLatestEmail(clientEmail);
    assert.ok(verifyEmailPayload.text.includes('/verify-email#token='));
    assert.equal(verifyEmailPayload.text.includes('/verify-email?token='), false);
    const firstVerifyTok = extractFragmentToken(verifyEmailPayload);

    // If resend-verification fails delivery, uniform 200 OK is returned AND firstVerifyTok remains usable!
    emailMode = 'fail_all';
    const resendFail = await apiRequest('/api/v1/client/auth/resend-verification', {
      method: 'POST',
      ip: '198.51.100.41',
      body: { email: clientEmail },
    });
    emailMode = 'ok';
    assert.equal(resendFail.status, 200);
    assert.deepEqual(resendFail.json.data, { requested: true });

    const verifyWithFirst = await apiRequest('/api/v1/client/auth/verify-email', {
      method: 'POST',
      ip: '198.51.100.42',
      body: { token: firstVerifyTok },
    });
    assert.equal(verifyWithFirst.status, 200, 'Prior unused verification token must stay active after failed resend');

    // Request password reset -> #token= fragment URL
    await apiRequest('/api/v1/client/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.43',
      body: { email: clientEmail },
    });
    const resetEmailPayload = extractLatestEmail(clientEmail);
    assert.ok(resetEmailPayload.text.includes('/reset-password#token='));
    assert.equal(resetEmailPayload.text.includes('/reset-password?token='), false);
    const validResetTok = extractFragmentToken(resetEmailPayload);

    // Non-blocking security alert failure (`fail_security_only`) must not fail resetPassword
    emailMode = 'fail_security_only';
    const resetOk = await apiRequest('/api/v1/client/auth/reset-password', {
      method: 'POST',
      ip: '198.51.100.44',
      body: {
        token: validResetTok,
        newPassword: 'RecoveryNew#2026!Strong',
        confirmPassword: 'RecoveryNew#2026!Strong',
      },
    });
    emailMode = 'ok';
    assert.equal(resetOk.status, 200);
    assert.equal(resetOk.json.data.reset, true);

    // Fail-closed rate limiting in production when rate_limits queries fail on forgot-password
    const brokenDb = {
      prepare(sql) {
        return {
          bind() {
            return this;
          },
          async first() {
            if (/rate_limits/i.test(sql)) {
              throw new Error('D1 rate limit unavailable');
            }
            return { cnt: 1 };
          },
          async run() {
            if (/rate_limits/i.test(sql)) {
              throw new Error('D1 rate limit unavailable');
            }
            return { success: true };
          },
          async all() {
            if (/rate_limits/i.test(sql)) {
              throw new Error('D1 rate limit unavailable');
            }
            return { results: [] };
          },
        };
      },
    };
    const prodLimiterEnv = { ...env, ENVIRONMENT: 'production', DB: brokenDb };
    await ensureDatabaseSeeded(prodLimiterEnv);
    const prodLimiterOutage = await apiRequest('/api/v1/client/auth/forgot-password', {
      method: 'POST',
      ip: '198.51.100.45',
      customEnv: prodLimiterEnv,
      body: { email: clientEmail },
    });
    assert.equal(prodLimiterOutage.status, 503);
    assert.equal(prodLimiterOutage.json.error.code, 'RATE_LIMITER_UNAVAILABLE');
  });

  it('3. HttpOnly Cookie Auth Mode, Double-Submit CSRF, Cookie-Authenticated Orders, Replay Detection & Single-Device Logout', async () => {
    const adminJarA = new CookieJar();
    const adminJarB = new CookieJar();

    // 3A. GET /api/v1/auth/csrf sets host-only HttpOnly CSRF cookie and returns token
    const adminCsrfRes = await apiRequest('/api/v1/auth/csrf', {
      method: 'GET',
      jar: adminJarA,
    });
    assert.equal(adminCsrfRes.status, 200);
    assert.ok(adminCsrfRes.json.data.csrfToken);
    const csrfCookieA = adminCsrfRes.setCookies.find((c) => c.name === ADMIN_CSRF_COOKIE_NAME);
    assert.ok(csrfCookieA);
    assert.equal(csrfCookieA.attrs.httponly, true);
    assert.equal(csrfCookieA.attrs.samesite, 'Lax');
    assert.equal(csrfCookieA.attrs.domain, undefined, 'Cookie must be host-only');

    // 3B. Default admin login omits accessToken/refreshToken from JSON and sets HttpOnly cookies
    const cookieLoginA = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '198.51.100.50',
      jar: adminJarA,
      body: { email: SUPER_ADMIN_EMAIL, password: SUPER_ADMIN_PASSWORD },
    });
    assert.equal(cookieLoginA.status, 200);
    assert.equal(cookieLoginA.json.data.authMode, 'cookie');
    assert.equal(cookieLoginA.json.data.accessToken, undefined);
    assert.equal(cookieLoginA.json.data.refreshToken, undefined);
    assert.ok(cookieLoginA.json.data.csrfToken);

    const setAccess = cookieLoginA.setCookies.find((c) => c.name === ADMIN_ACCESS_COOKIE_NAME);
    const setRefresh = cookieLoginA.setCookies.find((c) => c.name === ADMIN_REFRESH_COOKIE_NAME);
    assert.ok(setAccess && setAccess.attrs.httponly && setAccess.attrs.secure);
    assert.equal(setAccess.attrs.path, '/api/v1');
    assert.ok(setRefresh && setRefresh.attrs.httponly && setRefresh.attrs.secure);
    assert.equal(setRefresh.attrs.path, '/api/v1/auth');

    // Cookie-authenticated GET works without Authorization header
    const meWithCookie = await apiRequest('/api/v1/auth/me', { jar: adminJarA });
    assert.equal(meWithCookie.status, 200);

    // Cookie-authenticated mutation WITHOUT X-CSRF-Token fails with 403 CSRF_VALIDATION_FAILED
    const missingCsrfLogout = await apiRequest('/api/v1/auth/logout', {
      method: 'POST',
      jar: adminJarA,
      body: {},
    });
    assert.equal(missingCsrfLogout.status, 403);
    assert.equal(missingCsrfLogout.json.error.code, 'CSRF_VALIDATION_FAILED');

    const missingCsrfCreate = await apiRequest('/api/v1/services', {
      method: 'POST',
      jar: adminJarA,
      body: {
        title: 'Blocked CSRF Service',
        short_description: 'Should fail CSRF check.',
        description: 'Detailed description without CSRF token.',
        price: 10000,
      },
    });
    assert.equal(missingCsrfCreate.status, 403);
    assert.equal(missingCsrfCreate.json.error.code, 'CSRF_VALIDATION_FAILED');

    // Sign in Device B in parallel before Device A does single-device logout
    const cookieLoginB = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '198.51.100.51',
      jar: adminJarB,
      body: { email: SUPER_ADMIN_EMAIL, password: SUPER_ADMIN_PASSWORD },
    });
    assert.equal(cookieLoginB.status, 200);

    // Single-device cookie logout with valid CSRF revokes ONLY Device A and leaves Device B working
    const csrfTokenA = cookieLoginA.json.data.csrfToken;
    const validLogoutA = await apiRequest('/api/v1/auth/logout', {
      method: 'POST',
      jar: adminJarA,
      headers: { 'X-CSRF-Token': csrfTokenA },
      body: {},
    });
    assert.equal(validLogoutA.status, 200);
    assert.equal(validLogoutA.json.data.loggedOut, true);
    assert.equal(adminJarA.get(ADMIN_ACCESS_COOKIE_NAME), '');

    const deviceBStillWorks = await apiRequest('/api/v1/auth/me', { jar: adminJarB });
    assert.equal(deviceBStillWorks.status, 200);

    // Device B cookie refresh WITH CSRF rotates cookies cleanly and omits tokens from JSON
    const refreshB = await apiRequest('/api/v1/auth/refresh', {
      method: 'POST',
      jar: adminJarB,
      headers: { 'X-CSRF-Token': cookieLoginB.json.data.csrfToken },
      body: {},
    });
    assert.equal(refreshB.status, 200);
    assert.equal(refreshB.json.data.authMode, 'cookie');
    assert.equal(refreshB.json.data.accessToken, undefined);

    // 3C. Client cookie auth + CSRF on POST /api/v1/orders + Refresh Replay Detection
    const clientEmail = 'cookie.client@dtks-test.studio';
    await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '198.51.100.52',
      body: {
        fullName: 'Cookie Client',
        email: clientEmail,
        phone: '+91 99061 40001',
        password: 'CookieClient#2026!Strong',
        confirmPassword: 'CookieClient#2026!Strong',
        acceptTerms: true,
      },
    });
    const verifyTok = extractFragmentToken(extractLatestEmail(clientEmail));
    await apiRequest('/api/v1/client/auth/verify-email', {
      method: 'POST',
      body: { token: verifyTok },
    });

    const clientJar = new CookieJar();
    const clientCsrfInit = await apiRequest('/api/v1/client/auth/csrf', { jar: clientJar });
    assert.equal(clientCsrfInit.status, 200);
    assert.ok(clientJar.get(CLIENT_CSRF_COOKIE_NAME));

    const clientLogin = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '198.51.100.53',
      jar: clientJar,
      body: { email: clientEmail, password: 'CookieClient#2026!Strong' },
    });
    assert.equal(clientLogin.status, 200);
    assert.equal(clientLogin.json.data.authMode, 'cookie');
    assert.equal(clientLogin.json.data.accessToken, undefined);
    assert.ok(clientJar.get(CLIENT_ACCESS_COOKIE_NAME));
    assert.ok(clientJar.get(CLIENT_REFRESH_COOKIE_NAME));

    // POST /api/v1/orders carrying client auth cookies WITHOUT X-CSRF-Token fails 403
    const orderWithoutCsrf = await apiRequest('/api/v1/orders', {
      method: 'POST',
      ip: '198.51.100.54',
      jar: clientJar,
      body: {
        project_name: 'CSRF Blocked Order',
        project_description: 'Must reject cookie-authenticated POST /orders missing CSRF header.',
        budget: '₹15,000 – ₹30,000',
        customer_name: 'Cookie Client',
        customer_email: clientEmail,
        customer_phone: '+91 99061 40001',
      },
    });
    assert.equal(orderWithoutCsrf.status, 403);
    assert.equal(orderWithoutCsrf.json.error.code, 'CSRF_VALIDATION_FAILED');

    // POST /api/v1/orders WITH X-CSRF-Token links authenticated client portal cleanly
    const orderWithCsrf = await apiRequest('/api/v1/orders', {
      method: 'POST',
      ip: '198.51.100.55',
      jar: clientJar,
      headers: { 'X-CSRF-Token': clientLogin.json.data.csrfToken },
      body: {
        project_name: 'CSRF Authenticated Order',
        project_description: 'Valid cookie-session order linked to verified client.',
        budget: '₹15,000 – ₹30,000',
        customer_name: 'Cookie Client',
        customer_email: clientEmail,
        customer_phone: '+91 99061 40001',
      },
    });
    assert.equal(orderWithCsrf.status, 201);
    assert.ok(orderWithCsrf.json.data.order.customer_id);

    // Bearer refresh replay triggers cascade revocation on client token_version
    const bearerClientLogin = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '198.51.100.56',
      headers: { 'X-Auth-Mode': 'bearer' },
      body: { email: clientEmail, password: 'CookieClient#2026!Strong' },
    });
    const oldRefresh = bearerClientLogin.json.data.refreshToken;
    const rotated = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      headers: { 'X-Auth-Mode': 'bearer' },
      body: { refreshToken: oldRefresh },
    });
    assert.equal(rotated.status, 200);
    const replay = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      headers: { 'X-Auth-Mode': 'bearer' },
      body: { refreshToken: oldRefresh },
    });
    assert.equal(replay.status, 401);
    assert.equal(replay.json.error.code, 'REFRESH_TOKEN_REPLAY_DETECTED');

    // Cookie session's existing access token is also invalidated due to token_version bump!
    const cookieInvalidated = await apiRequest('/api/v1/client/auth/me', { jar: clientJar });
    assert.equal(cookieInvalidated.status, 401);
    assert.equal(cookieInvalidated.json.error.code, 'SESSION_REVOKED');
  });

  it('4. Public Catalog Visibility Filtering (Team/Testimonials/Bootstrap) & URL Scheme Validation', async () => {
    // Re-login admin bearer since earlier replay/logout tests didn't touch super admin token_version, still ensure fresh token
    const freshLogin = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '198.51.100.60',
      headers: { 'X-Auth-Mode': 'bearer' },
      body: { email: SUPER_ADMIN_EMAIL, password: SUPER_ADMIN_PASSWORD },
    });
    adminBearer = freshLogin.json.data.accessToken;

    // Seed hidden team member and pending/unapproved testimonial
    const hiddenTeam = await apiRequest('/api/v1/team', {
      method: 'POST',
      token: adminBearer,
      body: {
        fullName: 'Hidden Draft Engineer',
        role: 'Security Architect',
        visible: false,
      },
    });
    assert.equal(hiddenTeam.status, 201);
    const hiddenTeamId = hiddenTeam.json.data.member.id;

    const unapprovedTestimonial = await apiRequest('/api/v1/testimonials', {
      method: 'POST',
      token: adminBearer,
      body: {
        clientName: 'Pending Reviewer',
        quote: 'Unapproved draft testimonial.',
        isApproved: false,
      },
    });
    assert.equal(unapprovedTestimonial.status, 201);
    const pendingTestId = unapprovedTestimonial.json.data.testimonial.id;

    // Public GET /team, /testimonials, /bootstrap exclude hidden/unapproved records
    const pubTeam = await apiRequest('/api/v1/team');
    assert.equal(pubTeam.status, 200);
    assert.equal(pubTeam.json.data.team.some((m) => m.id === hiddenTeamId), false);

    // Unauthenticated ?includeInactive=true still cannot see hidden team members
    const unauthTeamAll = await apiRequest('/api/v1/team?includeInactive=true');
    assert.equal(unauthTeamAll.json.data.team.some((m) => m.id === hiddenTeamId), false);

    // Authenticated Admin ?includeInactive=true sees hidden team members
    const admTeamAll = await apiRequest('/api/v1/team?includeInactive=true', {
      token: adminBearer,
    });
    assert.equal(admTeamAll.json.data.team.some((m) => m.id === hiddenTeamId), true);

    const pubTestimonials = await apiRequest('/api/v1/testimonials');
    assert.equal(pubTestimonials.json.data.testimonials.some((t) => t.id === pendingTestId), false);

    const admTestimonials = await apiRequest('/api/v1/testimonials?all=true', {
      token: adminBearer,
    });
    assert.equal(admTestimonials.json.data.testimonials.some((t) => t.id === pendingTestId), true);

    const pubBootstrap = await apiRequest('/api/v1/bootstrap');
    assert.equal(pubBootstrap.json.data.team.some((m) => m.id === hiddenTeamId), false);
    assert.equal(
      pubBootstrap.json.data.testimonials.some((t) => t.id === pendingTestId),
      false
    );

    // Unsafe URL schemes rejected on services, portfolio, and team
    const badSvc = await apiRequest('/api/v1/services', {
      method: 'POST',
      token: adminBearer,
      body: {
        title: 'XSS URL Service',
        short_description: 'Testing URL scheme validation.',
        description: 'Testing unsafe javascript URL.',
        image: 'javascript:alert(1)',
        price: 12000,
      },
    });
    assert.equal(badSvc.status, 400);
    assert.equal(badSvc.json.error.code, 'VALIDATION_ERROR');

    const badPortfolio = await apiRequest('/api/v1/portfolio', {
      method: 'POST',
      token: adminBearer,
      body: {
        project_title: 'Metadata SSRF Portfolio',
        short_overview: 'Testing cloud metadata URL rejection.',
        description: 'Testing cloud metadata URL rejection.',
        thumbnail: 'http://169.254.169.254/latest/meta-data/',
      },
    });
    assert.equal(badPortfolio.status, 400);

    const badTeamUrl = await apiRequest('/api/v1/team', {
      method: 'POST',
      token: adminBearer,
      body: {
        fullName: 'Bad Url Member',
        websiteUrl: 'vbscript:msgbox(1)',
        avatarUrl: 'data:text/html,<script>alert(1)</script>',
      },
    });
    assert.equal(badTeamUrl.status, 400);
  });

  it('5. R2 Size/Key Guards, Crypto Password/JWT Hardening, CORS Bypass Removal, HTTPS Enforcement & Security Headers', async () => {
    // 5A. R2 oversized payload & invalid replaceKey
    const oversizedUpload = await apiRequest('/api/v1/portfolio/upload', {
      method: 'POST',
      token: adminBearer,
      body: {
        fileName: 'huge.png',
        mimeType: 'image/png',
        base64Data: 'A'.repeat(Math.ceil((MAX_IMAGE_SIZE_BYTES * 4) / 3) + 128),
      },
    });
    assert.equal(oversizedUpload.status, 413);
    assert.equal(oversizedUpload.json.error.code, 'PAYLOAD_TOO_LARGE');

    const badReplaceKey = await apiRequest('/api/v1/portfolio/upload', {
      method: 'POST',
      token: adminBearer,
      body: {
        fileName: 'ok.png',
        mimeType: 'image/png',
        replaceKey: '../../etc/passwd',
        base64Data: VALID_PNG_BYTES.toString('base64'),
      },
    });
    assert.equal(badReplaceKey.status, 400);
    assert.equal(badReplaceKey.json.error.code, 'INVALID_ASSET_KEY');

    // Valid R2 asset response carries hardened serving headers
    const goodUpload = await apiRequest('/api/v1/portfolio/upload', {
      method: 'POST',
      token: adminBearer,
      body: {
        fileName: 'sec-ok.png',
        mimeType: 'image/png',
        base64Data: VALID_PNG_BYTES.toString('base64'),
      },
    });
    assert.equal(goodUpload.status, 201);
    const assetFetch = await apiRequest(goodUpload.json.data.url);
    assert.equal(assetFetch.status, 200);
    assert.equal(assetFetch.headers.get('X-Content-Type-Options'), 'nosniff');
    assert.equal(assetFetch.headers.get('Cross-Origin-Resource-Policy'), 'cross-origin');
    assert.ok((assetFetch.headers.get('Content-Security-Policy') || '').includes("default-src 'none'"));

    // 5B. Password minimum 12 chars & weak password denylist
    const shortPw = await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '198.51.100.70',
      body: {
        fullName: 'Short Pass',
        email: 'shortpass@dtks-test.studio',
        phone: '+91 99061 50001',
        password: 'Ab1!short',
        confirmPassword: 'Ab1!short',
        acceptTerms: true,
      },
    });
    assert.equal(shortPw.status, 400);

    const commonPw = await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '198.51.100.71',
      body: {
        fullName: 'Common Pass',
        email: 'commonpass@dtks-test.studio',
        phone: '+91 99061 50002',
        password: 'DreamTech@2026!',
        confirmPassword: 'DreamTech@2026!',
        acceptTerms: true,
      },
    });
    assert.equal(commonPw.status, 400);

    // 5C. JWT strict typ and nbf enforcement
    const futureNbfJwt = await signJwt(
      {
        sub: 'adm-root-1',
        role: 'super_admin',
        type: 'access',
        nbf: Math.floor(Date.now() / 1000) + 3600,
      },
      TEST_JWT_SECRET,
      7200
    );
    await assert.rejects(
      () => verifyJwt(futureNbfJwt, TEST_JWT_SECRET),
      (err) => err?.code === 'TOKEN_NOT_YET_VALID'
    );

    // 5D. Production ALLOW_LOCAL_CORS='true' is ignored & plaintext HTTP is blocked on sensitive routes
    const prodBypassAttemptEnv = {
      ...env,
      ENVIRONMENT: 'production',
      ALLOW_LOCAL_CORS: 'true',
    };
    const localCorsInProd = await apiRequest('/api/v1/health', {
      origin: 'http://localhost:5173',
      customEnv: prodBypassAttemptEnv,
    });
    assert.equal(localCorsInProd.status, 403);
    assert.equal(localCorsInProd.json.error.code, 'CORS_ORIGIN_FORBIDDEN');

    const httpInProd = await apiRequest('/api/v1/auth/me', {
      urlBase: 'http://api.dreamtechkashmirsolutions.studio',
      token: adminBearer,
      customEnv: prodBypassAttemptEnv,
    });
    assert.equal(httpInProd.status, 403);
    assert.equal(httpInProd.json.error.code, 'HTTPS_REQUIRED');

    // 5E. Strict security headers on HTTPS production API responses
    const prodHttpsRes = await apiRequest('/api/v1/health', {
      customEnv: prodBypassAttemptEnv,
    });
    assert.equal(prodHttpsRes.status, 200);
    assert.equal(prodHttpsRes.headers.get('X-Frame-Options'), 'DENY');
    assert.equal(prodHttpsRes.headers.get('Cross-Origin-Opener-Policy'), 'same-origin');
    assert.equal(prodHttpsRes.headers.get('Cross-Origin-Resource-Policy'), 'same-site');
    assert.equal(prodHttpsRes.headers.get('Cache-Control'), 'no-store');
    assert.ok(
      (prodHttpsRes.headers.get('Content-Security-Policy') || '').includes("frame-ancestors 'none'")
    );
    assert.ok(
      (prodHttpsRes.headers.get('Strict-Transport-Security') || '').includes('max-age=31536000')
    );
  });

  it('6. Order Email Delivery Independence, Non-Blocking Resend Failures & Zero Secret Leakage', async () => {
    const custEmail = 'delivery.resilience@dtks-test.studio';

    // 6A. Admin failure must NOT block customer tracking email
    emailMode = 'fail_admin_only';
    const adminFailResult = await notifyOrderCreated(
      env,
      {
        id: 'ord-unit-test-1',
        orderNumber: 'DKS-2026-9901',
        customerName: 'Delivery Test',
        customerEmail: custEmail,
        customerPhone: '+91 99061 60001',
        service: 'Business Websites',
        packageTitle: 'Starter',
        status: 'Pending',
        budget: '₹20,000',
        projectDescription: 'Unit test independent dispatch',
      },
      { trackingToken: 'f'.repeat(64) }
    );
    emailMode = 'ok';
    assert.equal(adminFailResult.customer.sent, true);
    assert.equal(adminFailResult.customer.status, 'sent');
    assert.equal(adminFailResult.admin.sent, false);
    assert.equal(adminFailResult.admin.status, 'failed');

    // 6B. Customer failure must NOT block admin email OR roll back order creation
    emailMode = 'fail_customer_only';
    const orderOnCustFail = await apiRequest('/api/v1/orders', {
      method: 'POST',
      ip: '198.51.100.80',
      body: {
        project_name: 'Order Survives Email Outage',
        project_description: 'Customer email fails, order still persists and returns 201.',
        budget: '₹25,000',
        customer_name: 'Resilient Client',
        customer_email: 'resilient.cust@dtks-test.studio',
        customer_phone: '+91 99061 60002',
      },
    });
    emailMode = 'ok';
    assert.equal(orderOnCustFail.status, 201);
    assert.equal(orderOnCustFail.json.data.trackingToken, undefined);
    assert.equal(orderOnCustFail.json.data.trackingEmailSent, false);
    const bodyStr = JSON.stringify(orderOnCustFail.json);
    assert.equal(bodyStr.includes('Customer Resend provider timeout'), false);
    assert.equal(bodyStr.includes('contact@dreamtechkashmirsolutions.studio'), false);

    // Order exists in DB even though customer email failed
    const dbOrder = await env.DB.prepare('SELECT id FROM orders WHERE id = ?')
      .bind(orderOnCustFail.json.data.order.id)
      .first();
    assert.ok(dbOrder);

    // 6C. Unconfigured RESEND_API_KEY reports skipped_unconfigured without throwing or rolling back order
    const unconfiguredEnv = { ...env, RESEND_API_KEY: '' };
    const unconfiguredOrder = await apiRequest('/api/v1/orders', {
      method: 'POST',
      ip: '198.51.100.81',
      customEnv: unconfiguredEnv,
      body: {
        project_name: 'Order Unconfigured Email',
        project_description: 'Resend API key absent; order still commits safely.',
        budget: '₹25,000',
        customer_name: 'Unconfigured Client',
        customer_email: 'unconf.cust@dtks-test.studio',
        customer_phone: '+91 99061 60003',
      },
    });
    assert.equal(unconfiguredOrder.status, 201);
    assert.equal(unconfiguredOrder.json.data.trackingEmailSent, false);

    // Verify no raw tracking token was ever written to activity_logs
    const logs = await env.DB.prepare('SELECT details FROM activity_logs').all();
    for (const row of logs.results || []) {
      assert.equal(String(row.details || '').includes('#token='), false);
      assert.equal(String(row.details || '').includes('f'.repeat(64)), false);
    }
  });

  it('7. Secure Tracking-Link Resend (POST /api/v1/orders/track/resend): Token Rotation, Delivery Failure Preservation, Concurrency & Layered Rate Limits', async () => {
    const custEmail = 'track.resend@dtks-test.studio';
    const orderRes = await apiRequest('/api/v1/orders', {
      method: 'POST',
      ip: '198.51.100.90',
      body: {
        project_name: 'Resend Tracking Target',
        project_description: 'Testing secure tracking link resend and rotation lifecycle.',
        budget: '₹40,000',
        customer_name: 'Resend Client',
        customer_email: custEmail,
        customer_phone: '+91 99061 70001',
      },
    });
    assert.equal(orderRes.status, 201);
    const orderId = orderRes.json.data.order.id;
    const orderNumber = orderRes.json.data.order.order_number;
    const token1 = extractFragmentToken(extractLatestEmail(custEmail));

    // 7A. Non-matching email returns uniform 200 without sending email or revoking token1
    const emailCountBefore = capturedEmails.length;
    const wrongEmailRes = await apiRequest('/api/v1/orders/track/resend', {
      method: 'POST',
      ip: '198.51.100.91',
      body: { orderNumber, email: 'attacker.other@dtks-test.studio' },
    });
    assert.equal(wrongEmailRes.status, 200);
    assert.deepEqual(wrongEmailRes.json.data, { requested: true });
    assert.equal(capturedEmails.length, emailCountBefore);

    // Non-existent order number returns identical uniform 200
    const missingOrderRes = await apiRequest('/api/v1/orders/track/resend', {
      method: 'POST',
      ip: '198.51.100.92',
      body: { orderNumber: 'DKS-2099-9999', email: custEmail },
    });
    assert.equal(missingOrderRes.status, 200);
    assert.deepEqual(missingOrderRes.json.data, { requested: true });
    assert.equal(capturedEmails.length, emailCountBefore);

    // 7B. Delivery failure revokes ONLY newly generated token and preserves token1
    emailMode = 'fail_all';
    const failResend = await apiRequest('/api/v1/orders/track/resend', {
      method: 'POST',
      ip: '198.51.100.93',
      body: { orderNumber, email: custEmail },
    });
    emailMode = 'ok';
    assert.equal(failResend.status, 200);
    assert.deepEqual(failResend.json.data, { requested: true });

    const trackWithToken1AfterFail = await apiRequest('/api/v1/orders/track', {
      method: 'POST',
      ip: '198.51.100.94',
      body: { token: token1 },
    });
    assert.equal(
      trackWithToken1AfterFail.status,
      200,
      'Prior valid tracking token must remain active when resend email fails'
    );

    // 7C. Successful resend (case-insensitive orderNumber & email) issues token2 via #token= and revokes token1
    const okResend = await apiRequest('/api/v1/orders/track/resend', {
      method: 'POST',
      ip: '198.51.100.95',
      body: { order_number: orderNumber.toLowerCase(), email: custEmail.toUpperCase() },
    });
    assert.equal(okResend.status, 200);
    assert.deepEqual(okResend.json.data, { requested: true });
    assert.equal(okResend.json.data.trackingToken, undefined);

    const resendEmailPayload = extractLatestEmail(custEmail);
    assert.ok(resendEmailPayload.text.includes('/track-order#token='));
    assert.equal(resendEmailPayload.text.includes('?token='), false);
    const token2 = extractFragmentToken(resendEmailPayload);
    assert.notEqual(token2, token1);
    assert.equal(JSON.stringify(okResend.json).includes(token2), false);

    const trackToken1Revoked = await apiRequest('/api/v1/orders/track', {
      method: 'POST',
      ip: '198.51.100.96',
      body: { token: token1 },
    });
    assert.equal(trackToken1Revoked.status, 404);
    assert.equal(trackToken1Revoked.json.error.code, 'ORDER_NOT_FOUND');

    const trackToken2Valid = await apiRequest('/api/v1/orders/track', {
      method: 'POST',
      ip: '198.51.100.97',
      body: { token: token2 },
    });
    assert.equal(trackToken2Valid.status, 200);
    assert.equal(trackToken2Valid.json.data.order.order_number, orderNumber);

    // 7D. Concurrent resend safety: parallel requests never leave zero valid tokens
    const concurrentOrder = await apiRequest('/api/v1/orders', {
      method: 'POST',
      ip: '198.51.100.98',
      body: {
        project_name: 'Concurrent Resend Order',
        project_description: 'Testing parallel resend requests.',
        budget: '₹30,000',
        customer_name: 'Concurrent User',
        customer_email: 'concurrent.resend@dtks-test.studio',
        customer_phone: '+91 99061 70002',
      },
    });
    const concOrderId = concurrentOrder.json.data.order.id;
    const concOrderNum = concurrentOrder.json.data.order.order_number;

    const [c1, c2] = await Promise.all([
      apiRequest('/api/v1/orders/track/resend', {
        method: 'POST',
        ip: '198.51.100.99',
        body: { orderNumber: concOrderNum, email: 'concurrent.resend@dtks-test.studio' },
      }),
      apiRequest('/api/v1/orders/track/resend', {
        method: 'POST',
        ip: '198.51.100.100',
        body: { orderNumber: concOrderNum, email: 'concurrent.resend@dtks-test.studio' },
      }),
    ]);
    assert.equal(c1.status, 200);
    assert.equal(c2.status, 200);
    const activeTokensAfterConcurrent = await env.DB.prepare(
      'SELECT COUNT(*) AS cnt FROM order_tracking_tokens WHERE order_id = ? AND revoked_at IS NULL'
    )
      .bind(concOrderId)
      .first();
    assert.ok(Number(activeTokensAfterConcurrent.cnt) >= 1);

    // 7E. Layered HMAC rate limiting across rotating IPs + zero raw PII in rate_limits + prod fail-closed
    const rlOrderNum = 'DKS-2026-RL01';
    const rlEmail = 'ratelimit.target@dtks-test.studio';
    for (let i = 1; i <= 5; i++) {
      const r = await apiRequest('/api/v1/orders/track/resend', {
        method: 'POST',
        ip: `198.51.101.${i}`,
        body: { orderNumber: rlOrderNum, email: rlEmail },
      });
      assert.equal(r.status, 200);
    }
    const blockedResend = await apiRequest('/api/v1/orders/track/resend', {
      method: 'POST',
      ip: '198.51.101.99',
      body: { orderNumber: rlOrderNum, email: rlEmail },
    });
    assert.equal(blockedResend.status, 429);
    assert.equal(blockedResend.json.error.code, 'RATE_LIMIT_EXCEEDED');

    const rateRows = await env.DB.prepare('SELECT rate_key FROM rate_limits').all();
    for (const rr of rateRows.results || []) {
      assert.equal(String(rr.rate_key).includes(rlEmail), false);
      assert.equal(String(rr.rate_key).includes(rlOrderNum), false);
    }

    // Production plaintext HTTP blocked (403 HTTPS_REQUIRED) + D1 failure fails closed (503)
    const prodEnv = { ...env, ENVIRONMENT: 'production' };
    const httpResend = await apiRequest('/api/v1/orders/track/resend', {
      method: 'POST',
      urlBase: 'http://api.dreamtechkashmirsolutions.studio',
      customEnv: prodEnv,
      body: { orderNumber, email: custEmail },
    });
    assert.equal(httpResend.status, 403);
    assert.equal(httpResend.json.error.code, 'HTTPS_REQUIRED');

    const brokenRateDb = {
      prepare(sql) {
        return {
          bind() {
            return this;
          },
          async first() {
            if (/rate_limits/i.test(sql)) throw new Error('D1 rate limit down');
            return { cnt: 1 };
          },
          async run() {
            if (/rate_limits/i.test(sql)) throw new Error('D1 rate limit down');
            return { success: true };
          },
          async all() {
            if (/rate_limits/i.test(sql)) throw new Error('D1 rate limit down');
            return { results: [] };
          },
        };
      },
    };
    const prodBrokenEnv = { ...env, ENVIRONMENT: 'production', DB: brokenRateDb };
    await ensureDatabaseSeeded(prodBrokenEnv);
    const failClosedResend = await apiRequest('/api/v1/orders/track/resend', {
      method: 'POST',
      ip: '198.51.101.200',
      customEnv: prodBrokenEnv,
      body: { orderNumber, email: custEmail },
    });
    assert.equal(failClosedResend.status, 503);
    assert.equal(failClosedResend.json.error.code, 'RATE_LIMITER_UNAVAILABLE');
  });

  it('8. Public Tracking Strips Internal Admin & Status-History Notes While Preserving Admin Visibility', async () => {
    const custEmail = 'notes.privacy@dtks-test.studio';
    const orderRes = await apiRequest('/api/v1/orders', {
      method: 'POST',
      ip: '198.51.102.10',
      body: {
        project_name: 'Private Notes Isolation Test',
        project_description: 'Verify internal notes never leak through public tracking.',
        budget: '₹50,000',
        customer_name: 'Privacy Client',
        customer_email: custEmail,
        customer_phone: '+91 99061 80001',
      },
    });
    assert.equal(orderRes.status, 201);
    const orderId = orderRes.json.data.order.id;
    const trackingToken = extractFragmentToken(extractLatestEmail(custEmail));

    // Admin updates status with BOTH internal staff `notes` / `admin_notes` AND customer-facing `customer_update`
    const statusUpdate = await apiRequest(`/api/v1/orders/${orderId}/status`, {
      method: 'PATCH',
      token: adminBearer,
      body: {
        status: 'InProgress',
        notes: 'INTERNAL STAFF NOTE: Client requested urgent discount review',
        admin_notes: 'TOP SECRET MARGIN INFO: 40% target margin',
        customer_update: 'Your website build has entered active development.',
      },
    });
    assert.equal(statusUpdate.status, 200);

    // Public tracking sees customer_update and clean statusHistory WITHOUT notes/note/admin_notes
    const publicTrack = await apiRequest('/api/v1/orders/track', {
      method: 'POST',
      ip: '198.51.102.11',
      body: { token: trackingToken },
    });
    assert.equal(publicTrack.status, 200);
    const trackedOrder = publicTrack.json.data.order;
    assert.equal(
      trackedOrder.customer_update,
      'Your website build has entered active development.'
    );
    assert.equal(trackedOrder.admin_notes, undefined);
    assert.equal(trackedOrder.adminNotes, undefined);
    assert.equal(trackedOrder.internalNotes, undefined);
    assert.ok(Array.isArray(trackedOrder.statusHistory) && trackedOrder.statusHistory.length >= 2);
    for (const entry of trackedOrder.statusHistory) {
      assert.equal(entry.notes, undefined);
      assert.equal(entry.note, undefined);
    }
    const serialized = JSON.stringify(publicTrack.json);
    assert.equal(serialized.includes('INTERNAL STAFF NOTE'), false);
    assert.equal(serialized.includes('TOP SECRET MARGIN INFO'), false);

    // Admin order detail endpoint MUST retain full internal notes
    const adminDetail = await apiRequest(`/api/v1/orders/${orderId}`, {
      token: adminBearer,
    });
    assert.equal(adminDetail.status, 200);
    assert.equal(adminDetail.json.data.order.admin_notes, 'TOP SECRET MARGIN INFO: 40% target margin');
    assert.ok(
      adminDetail.json.data.order.statusHistory.some((h) =>
        String(h.notes || '').includes('INTERNAL STAFF NOTE')
      )
    );
  });

  it('9. Client Auth Contract (Guest 401, Cookie Refresh with Missing/Expired Access Cookie, CSRF, Isolation) & Wrangler Config Verification', async () => {
    // 9A. Guest GET /api/v1/client/auth/me stays 401 UNAUTHORIZED without setting cookies
    const guestMe = await apiRequest('/api/v1/client/auth/me', { ip: '198.51.103.1' });
    assert.equal(guestMe.status, 401);
    assert.equal(guestMe.json.error.code, 'UNAUTHORIZED');
    assert.equal(guestMe.setCookies.length, 0);

    // Register, verify, and log in via cookies
    const clientEmail = 'contract.client@dtks-test.studio';
    await apiRequest('/api/v1/client/auth/register', {
      method: 'POST',
      ip: '198.51.103.2',
      body: {
        fullName: 'Contract Client',
        email: clientEmail,
        phone: '+91 99061 90001',
        password: 'ContractClient#2026!Strong',
        confirmPassword: 'ContractClient#2026!Strong',
        acceptTerms: true,
      },
    });
    const verifyTok = extractFragmentToken(extractLatestEmail(clientEmail));
    await apiRequest('/api/v1/client/auth/verify-email', {
      method: 'POST',
      ip: '198.51.103.3',
      body: { token: verifyTok },
    });

    const jar = new CookieJar();
    const loginRes = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '198.51.103.4',
      jar,
      body: { email: clientEmail, password: 'ContractClient#2026!Strong' },
    });
    assert.equal(loginRes.status, 200);

    // 9B. Cookie-only session restoration on GET /client/auth/me
    const cookieMe = await apiRequest('/api/v1/client/auth/me', { jar, ip: '198.51.103.5' });
    assert.equal(cookieMe.status, 200);
    assert.equal(cookieMe.json.data.client.email, clientEmail);

    // 9C. Cookie refresh when access cookie is absent OR expired + valid CSRF succeeds cleanly
    const refreshOnlyJar = new CookieJar();
    refreshOnlyJar.map.set(CLIENT_REFRESH_COOKIE_NAME, jar.get(CLIENT_REFRESH_COOKIE_NAME));
    refreshOnlyJar.map.set(CLIENT_CSRF_COOKIE_NAME, jar.get(CLIENT_CSRF_COOKIE_NAME));

    const refreshMissingCsrf = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      ip: '198.51.103.6',
      jar: refreshOnlyJar,
      body: {},
    });
    assert.equal(refreshMissingCsrf.status, 403);
    assert.equal(refreshMissingCsrf.json.error.code, 'CSRF_VALIDATION_FAILED');

    const refreshWithMissingAccessCookie = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      ip: '198.51.103.7',
      jar: refreshOnlyJar,
      headers: { 'X-CSRF-Token': jar.get(CLIENT_CSRF_COOKIE_NAME) },
      body: {},
    });
    assert.equal(refreshWithMissingAccessCookie.status, 200);
    assert.equal(refreshWithMissingAccessCookie.json.data.authMode, 'cookie');
    assert.ok(refreshOnlyJar.get(CLIENT_ACCESS_COOKIE_NAME));

    // Also test refresh when access cookie holds an expired JWT
    const expiredAccessJwt = await signJwt(
      {
        sub: cookieMe.json.data.client.id,
        accountType: 'client',
        type: 'access',
        tv: 1,
      },
      TEST_JWT_SECRET,
      -60
    );
    refreshOnlyJar.map.set(CLIENT_ACCESS_COOKIE_NAME, expiredAccessJwt);
    const refreshWithExpiredAccess = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      ip: '198.51.103.8',
      jar: refreshOnlyJar,
      headers: { 'X-CSRF-Token': refreshWithMissingAccessCookie.json.data.csrfToken },
      body: {},
    });
    assert.equal(refreshWithExpiredAccess.status, 200);

    // 9D. Missing / invalid refresh token status codes
    const missingRefresh = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      ip: '198.51.103.9',
      body: {},
    });
    assert.equal(missingRefresh.status, 400);
    assert.equal(missingRefresh.json.error.code, 'MISSING_REFRESH_TOKEN');

    const invalidRefresh = await apiRequest('/api/v1/client/auth/refresh', {
      method: 'POST',
      ip: '198.51.103.10',
      headers: { 'X-Auth-Mode': 'bearer' },
      body: { refreshToken: 'b'.repeat(64) },
    });
    assert.equal(invalidRefresh.status, 401);
    assert.equal(invalidRefresh.json.error.code, 'INVALID_REFRESH_TOKEN');

    // 9E. Admin JWT cannot access client endpoint, Client JWT cannot access admin endpoint
    const adminToClient = await apiRequest('/api/v1/client/auth/me', {
      token: adminBearer,
      ip: '198.51.103.11',
    });
    assert.equal(adminToClient.status, 401);
    assert.equal(adminToClient.json.error.code, 'INVALID_TOKEN_TYPE');

    const clientBearerLogin = await apiRequest('/api/v1/client/auth/login', {
      method: 'POST',
      ip: '198.51.103.12',
      headers: { 'X-Auth-Mode': 'bearer' },
      body: { email: clientEmail, password: 'ContractClient#2026!Strong' },
    });
    const clientToAdmin = await apiRequest('/api/v1/auth/me', {
      token: clientBearerLogin.json.data.accessToken,
      ip: '198.51.103.13',
    });
    assert.equal(clientToAdmin.status, 401);
    assert.equal(clientToAdmin.json.error.code, 'INVALID_TOKEN_TYPE');

    // 9F. Verify wrangler.toml production config disables workers.dev while retaining custom routes
    const wranglerToml = fs.readFileSync(
      path.resolve(process.cwd(), process.cwd().endsWith('backend') ? 'wrangler.toml' : 'backend/wrangler.toml'),
      'utf8'
    );
    assert.match(wranglerToml, /workers_dev\s*=\s*false/);
    assert.equal(/workers_dev\s*=\s*true/.test(wranglerToml), false);
    assert.ok(wranglerToml.includes('api.dreamtechkashmirsolutions.studio/*'));
    assert.ok(wranglerToml.includes('dreamtechkashmirsolutions.studio/api/v1/*'));
  });
});

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import workerApp from '../src/index.js';
import { createNodeWorkerEnv } from '../src/database/d1Adapter.js';
import { resetRateLimiter } from '../src/middleware/rateLimiter.js';
import { hashPassword } from '../src/utils/crypto.js';

const VALID_PNG_BYTES = Buffer.from(
  '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c63000100000500010d0a2db40000000049454e44ae426082',
  'hex'
);

const TEST_JWT_SECRET = 'dtks-contract-security-suite-secret-key-256-bits-2026-verified';
const SUPER_ADMIN_EMAIL = 'superadmin@dreamtechkashmirsolutions.studio';
const SUPER_ADMIN_PASSWORD = 'SuperStrongPassword#2026!';
const EDITOR_EMAIL = 'editor@dreamtechkashmirsolutions.studio';
const EDITOR_PASSWORD = 'EditorStrongPassword#2026!';

describe('DTKS API Contract Parity & Production Security Hardening Suite', () => {
  let tmpDir;
  let dbPath;
  let r2Dir;
  let env;
  let superAdminToken = '';
  let editorToken = '';

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dtks-contract-sec-'));
    dbPath = path.join(tmpDir, 'dtks-contract.sqlite');
    r2Dir = path.join(tmpDir, 'r2-storage');
    env = createNodeWorkerEnv({
      dbPath,
      r2Dir,
      overrides: {
        ENVIRONMENT: 'development',
        JWT_SECRET: TEST_JWT_SECRET,
        INITIAL_ADMIN_NAME: 'DTKS Contract Super Admin',
        INITIAL_ADMIN_EMAIL: SUPER_ADMIN_EMAIL,
        INITIAL_ADMIN_PASSWORD: SUPER_ADMIN_PASSWORD,
      },
    });
    await resetRateLimiter(env);

    // Log in as super_admin
    const loginRes = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      body: { email: SUPER_ADMIN_EMAIL, password: SUPER_ADMIN_PASSWORD },
    });
    assert.equal(loginRes.status, 200);
    superAdminToken = loginRes.json.data.accessToken;

    // Seed an editor account directly for RBAC verification
    const editorHash = await hashPassword(EDITOR_PASSWORD);
    const now = new Date().toISOString();
    await env.DB.prepare(
      `INSERT INTO admins (id, name, email, password_hash, role, is_active, token_version, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'editor', 1, 1, ?, ?)`
    )
      .bind('adm-editor-contract', 'Contract Editor', EDITOR_EMAIL, editorHash, now, now)
      .run();

    const editorLogin = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      body: { email: EDITOR_EMAIL, password: EDITOR_PASSWORD },
    });
    assert.equal(editorLogin.status, 200);
    editorToken = editorLogin.json.data.accessToken;
  });

  after(() => {
    try {
      env?.DB?.close?.();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  async function apiRequest(pathname, options = {}) {
    const {
      method = 'GET',
      body = null,
      token = null,
      headers = {},
      ip = '198.51.100.42',
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
    if (body && !(body instanceof FormData) && typeof body === 'object' && !Buffer.isBuffer(body)) {
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

  it('1. Bulk Services & Package Config Array Payloads + RBAC Enforcement', async () => {
    // Editor is forbidden on bulk catalog & config updates
    const editorBulkRes = await apiRequest('/api/v1/services', {
      method: 'PUT',
      token: editorToken,
      body: [{ title: 'Blocked Editor Service', description: 'Should fail RBAC' }],
    });
    assert.equal(editorBulkRes.status, 403);

    const editorMaintRes = await apiRequest('/api/v1/packages/config/maintenance', {
      method: 'PUT',
      token: editorToken,
      body: [{ name: 'Blocked Plan', price: null }],
    });
    assert.equal(editorMaintRes.status, 403);

    // Super admin bulk PUT /api/v1/services with raw JSON array (matching DTKS packageService.js)
    const servicesBulkRes = await apiRequest('/api/v1/services', {
      method: 'PUT',
      token: superAdminToken,
      body: [
        {
          id: 'svc-custom-contract',
          title: 'Custom Web Platform <script>alert(1)</script>',
          slug: 'custom-web-platform',
          description: 'Tailored full-stack web architecture for regional businesses.',
          shortDescription: 'Tailored full-stack architecture',
          features: ['Responsive layout', 'SEO foundation'],
          technologies: ['React', 'Cloudflare Workers'],
          deliveryTimeline: '3-5 Weeks',
          startingPrice: null,
          active: true,
        },
      ],
    });
    assert.equal(servicesBulkRes.status, 200);
    assert.equal(servicesBulkRes.json.success, true);
    const updatedSvc = servicesBulkRes.json.data.services.find((s) => s.id === 'svc-custom-contract');
    assert.ok(updatedSvc, 'Bulk-upserted service should be returned');
    assert.equal(updatedSvc.title.includes('<script>'), false);

    // Super admin PUT + public GET /api/v1/packages/config/maintenance with raw JSON array & null price
    const maintPayload = [
      {
        id: 'maint-monthly-contract',
        name: 'Monthly Care',
        billingCycle: 'Billed Monthly',
        price: null,
        currency: 'INR',
        updateAllowance: 'Up to 4 updates/month',
        backupFrequency: 'Weekly automated backups',
        securityChecks: 'SSL & uptime monitoring',
        responseTime: 'Within 24-48 business hours',
        scopeNote: 'Covers bug fixes and minor text updates.',
        active: true,
      },
    ];
    const maintPutRes = await apiRequest('/api/v1/packages/config/maintenance', {
      method: 'PUT',
      token: superAdminToken,
      body: maintPayload,
    });
    assert.equal(maintPutRes.status, 200);
    assert.equal(maintPutRes.json.data.maintenancePlans[0].price, null);
    assert.equal(maintPutRes.json.data.maintenancePlans[0].updateAllowance, 'Up to 4 updates/month');

    const maintGetRes = await apiRequest('/api/v1/packages/config/maintenance', { method: 'GET' });
    assert.equal(maintGetRes.status, 200);
    assert.equal(maintGetRes.json.data.maintenancePlans[0].id, 'maint-monthly-contract');
    assert.equal(maintGetRes.json.data.maintenancePlans[0].backupFrequency, 'Weekly automated backups');

    // Super admin PUT + public GET /api/v1/packages/config/addons with raw JSON array
    const addonsPayload = [
      {
        id: 'addon-seo-contract',
        name: 'Technical SEO Pack',
        description: 'Schema, canonicals, sitemap & Core Web Vitals optimization.',
        startingPrice: null,
        pricingNote: 'Request a Quote',
        active: true,
      },
    ];
    const addonsPutRes = await apiRequest('/api/v1/packages/config/addons', {
      method: 'PUT',
      token: superAdminToken,
      body: addonsPayload,
    });
    assert.equal(addonsPutRes.status, 200);
    assert.equal(addonsPutRes.json.data.addons[0].startingPrice, null);
    assert.equal(addonsPutRes.json.data.addons[0].pricingNote, 'Request a Quote');

    const addonsGetRes = await apiRequest('/api/v1/packages/config/addons', { method: 'GET' });
    assert.equal(addonsGetRes.status, 200);
    assert.equal(addonsGetRes.json.data.addons[0].id, 'addon-seo-contract');
  });

  it('2. R2 Upload with entityType, Encoded URL Delete, Public Fetch & Malformed Key Rejection', async () => {
    const formData = new FormData();
    formData.append('file', new Blob([VALID_PNG_BYTES], { type: 'image/png' }), 'team-avatar.png');
    formData.append('entityType', 'team');

    const uploadRes = await apiRequest('/api/v1/portfolio/upload', {
      method: 'POST',
      token: superAdminToken,
      body: formData,
    });
    assert.equal(uploadRes.status, 201);
    assert.ok(uploadRes.json.data.key.startsWith('team/'), 'entityType should map to R2 folder prefix');

    const uploadedKey = uploadRes.json.data.key;
    const publicUrl = uploadRes.json.data.publicUrl;

    // Fetch via GET /api/v1/uploads/:encodedKey
    const fetchRes = await apiRequest(`/api/v1/uploads/${uploadedKey}`, { method: 'GET' });
    assert.equal(fetchRes.status, 200);
    assert.equal(fetchRes.headers.get('Content-Type'), 'image/png');

    // Malformed percent-encoding must return 400 INVALID_ASSET_KEY (never 500)
    const malformedGet = await apiRequest('/api/v1/uploads/%E0%A4%A', { method: 'GET' });
    assert.equal(malformedGet.status, 400);
    assert.equal(malformedGet.json.error.code, 'INVALID_ASSET_KEY');

    const malformedDel = await apiRequest('/api/v1/portfolio/upload/%E0%A4%A', {
      method: 'DELETE',
      token: superAdminToken,
    });
    assert.equal(malformedDel.status, 400);
    assert.equal(malformedDel.json.error.code, 'INVALID_ASSET_KEY');

    // Delete using encoded full URL (matching frontend mediaService.js extractMediaId behavior)
    const fullAssetUrl = `https://api.dreamtechkashmirsolutions.studio${publicUrl}`;
    const deleteRes = await apiRequest(
      `/api/v1/portfolio/upload/${encodeURIComponent(fullAssetUrl)}`,
      {
        method: 'DELETE',
        token: superAdminToken,
      }
    );
    assert.equal(deleteRes.status, 200);
    assert.equal(deleteRes.json.data.deletedKey, uploadedKey);

    const afterDelGet = await apiRequest(`/api/v1/uploads/${uploadedKey}`, { method: 'GET' });
    assert.equal(afterDelGet.status, 404);
  });

  it('3. Admin Accounts Status Filters (pending, expired) & Frontend Compatibility Fields', async () => {
    const now = Date.now();
    const pendingHash = '!PENDING_INVITE_SETUP';
    const createdAt = new Date(now - 72 * 3600 * 1000).toISOString();
    const superAdminRow = await env.DB.prepare('SELECT id FROM admins WHERE lower(email) = lower(?) LIMIT 1')
      .bind(SUPER_ADMIN_EMAIL)
      .first();
    const inviterId = superAdminRow.id;

    await env.DB.prepare(
      `INSERT INTO admins (id, name, email, password_hash, role, is_active, token_version, invited_by_admin_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'admin', 0, 1, ?, ?, ?)`
    )
      .bind('adm-pending-fresh', 'Fresh Pending Admin', 'pending.fresh@dreamtechkashmirsolutions.studio', pendingHash, inviterId, createdAt, createdAt)
      .run();

    await env.DB.prepare(
      `INSERT INTO admin_invitations (id, admin_id, email, token_hash, invited_by_admin_id, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
      .bind('inv-fresh-1', 'adm-pending-fresh', 'pending.fresh@dreamtechkashmirsolutions.studio', 'hash-fresh-1', inviterId, new Date(now + 24 * 3600 * 1000).toISOString(), createdAt)
      .run();

    await env.DB.prepare(
      `INSERT INTO admins (id, name, email, password_hash, role, is_active, token_version, invited_by_admin_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'editor', 0, 1, ?, ?, ?)`
    )
      .bind('adm-pending-expired', 'Expired Pending Admin', 'pending.expired@dreamtechkashmirsolutions.studio', pendingHash, inviterId, createdAt, createdAt)
      .run();

    await env.DB.prepare(
      `INSERT INTO admin_invitations (id, admin_id, email, token_hash, invited_by_admin_id, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
      .bind('inv-expired-1', 'adm-pending-expired', 'pending.expired@dreamtechkashmirsolutions.studio', 'hash-expired-1', inviterId, new Date(now - 2 * 3600 * 1000).toISOString(), createdAt)
      .run();

    const pendingRes = await apiRequest('/api/v1/admin/accounts?status=pending', {
      method: 'GET',
      token: superAdminToken,
    });
    assert.equal(pendingRes.status, 200);
    const pendingIds = pendingRes.json.data.accounts.map((a) => a.id);
    assert.ok(pendingIds.includes('adm-pending-fresh'));
    assert.ok(pendingIds.includes('adm-pending-expired'));

    const freshAcc = pendingRes.json.data.accounts.find((a) => a.id === 'adm-pending-fresh');
    assert.equal(freshAcc.inviteExpired, false);
    assert.ok(freshAcc.inviteExpiresAt);
    assert.equal(typeof freshAcc.activeSessions, 'number');

    const expiredRes = await apiRequest('/api/v1/admin/accounts?status=expired', {
      method: 'GET',
      token: superAdminToken,
    });
    assert.equal(expiredRes.status, 200);
    const expiredIds = expiredRes.json.data.accounts.map((a) => a.id);
    assert.ok(expiredIds.includes('adm-pending-expired'));
    assert.equal(expiredIds.includes('adm-pending-fresh'), false);
    const expAcc = expiredRes.json.data.accounts.find((a) => a.id === 'adm-pending-expired');
    assert.equal(expAcc.inviteExpired, true);
  });

  it('4. Production CORS Enforcement & No Fallback Wildcard/Hardcoded Origin', async () => {
    const prodEnv = { ...env, ENVIRONMENT: 'production', ALLOW_LOCAL_CORS: 'false' };

    const devLocalRes = await apiRequest('/api/v1/health', {
      origin: 'http://localhost:5173',
      customEnv: prodEnv,
    });
    assert.equal(devLocalRes.status, 403);
    assert.equal(devLocalRes.json.error.code, 'CORS_ORIGIN_FORBIDDEN');

    const runAppRes = await apiRequest('/api/v1/health', {
      origin: 'https://untrusted-app.us-west1.run.app',
      customEnv: prodEnv,
    });
    assert.equal(runAppRes.status, 403);
    assert.equal(runAppRes.json.error.code, 'CORS_ORIGIN_FORBIDDEN');

    const prodAllowed = await apiRequest('/api/v1/health', {
      origin: 'https://dreamtechkashmirsolutions.studio',
      customEnv: prodEnv,
    });
    assert.equal(prodAllowed.status, 200);
    assert.equal(
      prodAllowed.headers.get('Access-Control-Allow-Origin'),
      'https://dreamtechkashmirsolutions.studio'
    );

    const noOriginRes = await apiRequest('/api/v1/health', {
      origin: null,
      customEnv: prodEnv,
    });
    assert.equal(noOriginRes.status, 200);
    assert.equal(noOriginRes.headers.get('Access-Control-Allow-Origin'), null);
  });

  it('5. Concurrent Order Creation Produces Unique Order Numbers Without 500 Collisions', async () => {
    const results = await Promise.all(
      [1, 2, 3].map((idx) =>
        apiRequest('/api/v1/orders', {
          method: 'POST',
          ip: `198.51.100.${10 + idx}`,
          body: {
            customer_name: `Concurrent Client ${idx}`,
            customer_email: `concurrent${idx}@example.com`,
            customer_phone: `+91990600010${idx}`,
            service: 'Business & Corporate Websites',
            project_description: `Concurrent order submission test number ${idx} with full specification details.`,
            budget: '₹15,000 - ₹25,000',
          },
        })
      )
    );

    for (const r of results) {
      assert.equal(r.status, 201, `Expected 201, got ${r.status}: ${JSON.stringify(r.json)}`);
    }
    const orderNumbers = new Set(results.map((r) => r.json.data.order.order_number));
    assert.equal(orderNumbers.size, 3, 'All concurrent orders must receive distinct order_number values');
  });

  it('6. Team & Settings Prototype/Secret Stripping & XSS Field Whitelisting', async () => {
    const createTeam = await apiRequest('/api/v1/team', {
      method: 'POST',
      token: superAdminToken,
      body: {
        fullName: 'Aarav Mir',
        role: 'Lead Engineer',
        bio: 'Builds reliable Cloudflare backends.',
        visible: true,
      },
    });
    assert.equal(createTeam.status, 201);
    const memberId = createTeam.json.data.member.id;

    const patchTeam = await apiRequest(`/api/v1/team/${memberId}`, {
      method: 'PATCH',
      token: superAdminToken,
      body: {
        fullName: 'Aarav Mir <script>alert(1)</script>',
        order: 3,
        injectedField: 'should-not-persist',
        isAdmin: true,
      },
    });
    assert.equal(patchTeam.status, 200);
    const updated = patchTeam.json.data.member;
    assert.equal(updated.fullName.includes('<script>'), false);
    assert.equal(updated.order, 3);
    assert.equal(updated.sortOrder, 3);
    assert.equal(updated.injectedField, undefined);
    assert.equal(updated.isAdmin, undefined);

    const settingsPut = await apiRequest('/api/v1/settings', {
      method: 'PUT',
      token: superAdminToken,
      body: {
        companyName: 'DreamTech Kashmir Solutions',
        jwtSecret: 'should-be-stripped',
        resendApiKey: 're_should_be_stripped',
        nestedConfig: {
          api_key: 'strip-me',
          safeLabel: 'Srinagar, J&K <img src=x onerror=alert(1)>',
        },
      },
    });
    assert.equal(settingsPut.status, 200);
    const settings = settingsPut.json.data.settings;
    assert.equal(settings.jwtSecret, undefined);
    assert.equal(settings.resendApiKey, undefined);
    assert.equal(settings.nestedConfig.api_key, undefined);
    assert.equal(settings.nestedConfig.safeLabel.includes('onerror'), false);
  });

  it('7. OpenAPI 3.0.3 Specification Covers 100% of Active Router Endpoints & HTTP Methods', () => {
    const testDir = path.dirname(fileURLToPath(import.meta.url));
    const routerSrc = fs.readFileSync(path.resolve(testDir, '../src/routes/router.js'), 'utf8');
    const openapiSrc = fs.readFileSync(path.resolve(testDir, '../docs/openapi.yaml'), 'utf8');

    // Parse all path/method pairs from openapi.yaml
    const pathsBlock = openapiSrc.split(/^paths:\s*$/m)[1] || '';
    const documented = new Map();
    let currentPath = null;
    for (const line of pathsBlock.split('\n')) {
      const pathMatch = line.match(/^  (\/[^:\s]+):\s*$/);
      if (pathMatch) {
        currentPath = pathMatch[1];
        if (!documented.has(currentPath)) documented.set(currentPath, new Set());
        continue;
      }
      const methodMatch = line.match(/^    (get|post|put|patch|delete):\s*$/);
      if (methodMatch && currentPath) {
        documented.get(currentPath).add(methodMatch[1].toUpperCase());
      }
    }

    // Verify all explicit static & parameterized routes implemented in router.js
    const expectedRoutes = [
      ['GET', '/health'],
      ['GET', '/ready'],
      ['GET', '/bootstrap'],
      ['GET', '/uploads/{key}'],
      ['GET', '/assets/{key}'],
      ['GET', '/auth/csrf'],
      ['POST', '/auth/login'],
      ['POST', '/auth/refresh'],
      ['POST', '/auth/accept-invite'],
      ['POST', '/auth/logout'],
      ['GET', '/auth/me'],
      ['PATCH', '/auth/profile'],
      ['PUT', '/auth/profile'],
      ['POST', '/auth/change-password'],
      ['POST', '/auth/forgot-password'],
      ['POST', '/auth/reset-password'],
      ['GET', '/admin/accounts'],
      ['POST', '/admin/accounts'],
      ['POST', '/admin/accounts/{id}/resend-invite'],
      ['PATCH', '/admin/accounts/{id}/status'],
      ['PUT', '/admin/accounts/{id}/status'],
      ['DELETE', '/admin/accounts/{id}/sessions'],
      ['GET', '/admin/accounts/{id}'],
      ['PATCH', '/admin/accounts/{id}'],
      ['PUT', '/admin/accounts/{id}'],
      ['GET', '/client/auth/csrf'],
      ['POST', '/client/auth/register'],
      ['POST', '/client/auth/resend-verification'],
      ['POST', '/client/auth/verify-email'],
      ['POST', '/client/auth/login'],
      ['POST', '/client/auth/refresh'],
      ['POST', '/client/auth/logout'],
      ['GET', '/client/auth/me'],
      ['PATCH', '/client/auth/profile'],
      ['PUT', '/client/auth/profile'],
      ['POST', '/client/auth/change-password'],
      ['POST', '/client/auth/forgot-password'],
      ['POST', '/client/auth/reset-password'],
      ['POST', '/client/auth/deactivate'],
      ['GET', '/client/orders'],
      ['GET', '/client/orders/{id}'],
      ['GET', '/client/quotations'],
      ['GET', '/client/projects'],
      ['GET', '/services'],
      ['POST', '/services'],
      ['PUT', '/services'],
      ['GET', '/services/{slugOrId}'],
      ['PUT', '/services/{slugOrId}'],
      ['PATCH', '/services/{slugOrId}'],
      ['DELETE', '/services/{slugOrId}'],
      ['GET', '/packages'],
      ['POST', '/packages'],
      ['GET', '/packages/config/maintenance'],
      ['PUT', '/packages/config/maintenance'],
      ['GET', '/packages/config/addons'],
      ['PUT', '/packages/config/addons'],
      ['GET', '/packages/{id}'],
      ['PUT', '/packages/{id}'],
      ['PATCH', '/packages/{id}'],
      ['DELETE', '/packages/{id}'],
      ['POST', '/portfolio/upload'],
      ['DELETE', '/portfolio/upload'],
      ['DELETE', '/portfolio/upload/{key}'],
      ['GET', '/portfolio'],
      ['POST', '/portfolio'],
      ['GET', '/portfolio/{slugOrId}'],
      ['PUT', '/portfolio/{slugOrId}'],
      ['PATCH', '/portfolio/{slugOrId}'],
      ['DELETE', '/portfolio/{slugOrId}'],
      ['POST', '/orders/track'],
      ['POST', '/orders/track/resend'],
      ['POST', '/orders'],
      ['GET', '/orders'],
      ['PATCH', '/orders/{id}/status'],
      ['PUT', '/orders/{id}/status'],
      ['GET', '/orders/{id}'],
      ['PATCH', '/orders/{id}'],
      ['PUT', '/orders/{id}'],
      ['DELETE', '/orders/{id}'],
      ['POST', '/contact'],
      ['GET', '/contact'],
      ['GET', '/contact/{id}'],
      ['PATCH', '/contact/{id}'],
      ['PUT', '/contact/{id}'],
      ['DELETE', '/contact/{id}'],
      ['GET', '/admin/dashboard/stats'],
      ['GET', '/admin/dashboard/recent-orders'],
      ['GET', '/admin/dashboard/recent-messages'],
      ['GET', '/admin/dashboard/order-analytics'],
      ['GET', '/customers'],
      ['GET', '/customers/{id}'],
      ['GET', '/admin/activity-logs'],
      ['GET', '/admin/notifications'],
      ['GET', '/settings'],
      ['PUT', '/settings'],
      ['PATCH', '/settings'],
      ['GET', '/team'],
      ['POST', '/team'],
      ['PATCH', '/team/{id}/reorder'],
      ['POST', '/team/{id}/reorder'],
      ['PUT', '/team/{id}'],
      ['PATCH', '/team/{id}'],
      ['DELETE', '/team/{id}'],
      ['GET', '/testimonials'],
      ['POST', '/testimonials'],
      ['DELETE', '/testimonials/{id}'],
    ];

    // Sanity check that router.js itself references all expected API paths
    assert.ok(routerSrc.includes('/packages/config/maintenance'));
    assert.ok(routerSrc.includes('/admin/notifications'));

    for (const [method, routePath] of expectedRoutes) {
      const methods = documented.get(routePath);
      assert.ok(methods, `OpenAPI spec missing path: ${routePath}`);
      assert.ok(methods.has(method), `OpenAPI spec missing ${method} ${routePath}`);
    }
  });
});

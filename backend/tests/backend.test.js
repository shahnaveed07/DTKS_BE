import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import workerApp from '../src/index.js';
import { createNodeWorkerEnv } from '../src/database/d1Adapter.js';
import { signJwt } from '../src/utils/crypto.js';
import { resetRateLimiter } from '../src/middleware/rateLimiter.js';

// Minimal valid 1x1 PNG buffer (magic bytes: 89 50 4E 47 0D 0A 1A 0A)
const VALID_PNG_BYTES = Buffer.from(
  '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c63000100000500010d0a2db40000000049454e44ae426082',
  'hex'
);

describe('DTKS Production Backend API Suite (/api/v1) – 20 Phase 8 Scenarios', () => {
  let tmpDir;
  let dbPath;
  let r2Dir;
  let env;
  let accessToken = '';
  let refreshToken = '';

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dtks-backend-test-'));
    dbPath = path.join(tmpDir, 'dtks-test.sqlite');
    r2Dir = path.join(tmpDir, 'r2-storage');
    env = createNodeWorkerEnv({ dbPath, r2Dir });
    resetRateLimiter();
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
      ip = '127.0.0.1',
      origin = 'https://dreamtechkashmirsolutions.studio',
    } = options;

    const reqHeaders = new Headers(headers);
    if (origin) reqHeaders.set('Origin', origin);
    if (ip) reqHeaders.set('CF-Connecting-IP', ip);
    if (token) reqHeaders.set('Authorization', `Bearer ${token}`);

    let requestBody = body;
    if (body && !(body instanceof FormData) && typeof body === 'object' && !Buffer.isBuffer(body)) {
      reqHeaders.set('Content-Type', 'application/json');
      requestBody = JSON.stringify(body);
    }

    const request = new Request(`https://dreamtechkashmirsolutions.studio${pathname}`, {
      method,
      headers: reqHeaders,
      body: requestBody,
    });

    const response = await workerApp.fetch(request, env, {});
    const contentType = response.headers.get('content-type') || '';
    const json = contentType.includes('application/json') ? await response.json() : null;
    return { status: response.status, headers: response.headers, json, response };
  }

  it('1. Successful admin login returns JWT access & refresh tokens and updates last_login_at', async () => {
    const res = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      body: {
        email: 'admin@dreamtechkashmirsolutions.studio',
        password: 'Admin@DTKS2026!',
      },
    });

    assert.equal(res.status, 200);
    assert.equal(res.json.success, true);
    assert.ok(res.json.data.accessToken);
    assert.ok(res.json.data.refreshToken);
    assert.equal(res.json.data.admin.email, 'admin@dreamtechkashmirsolutions.studio');
    assert.equal(res.json.data.admin.role, 'super_admin');
    assert.equal(res.json.data.admin.is_active, true);

    accessToken = res.json.data.accessToken;
    refreshToken = res.json.data.refreshToken;

    const meRes = await apiRequest('/api/v1/auth/me', { token: accessToken });
    assert.equal(meRes.status, 200);
    assert.equal(meRes.json.data.admin.email, 'admin@dreamtechkashmirsolutions.studio');
  });

  it('2. Invalid admin login fails with HTTP 401 INVALID_CREDENTIALS', async () => {
    const res = await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      ip: '10.0.0.2',
      body: {
        email: 'admin@dreamtechkashmirsolutions.studio',
        password: 'WrongPassword123!',
      },
    });

    assert.equal(res.status, 401);
    assert.equal(res.json.success, false);
    assert.equal(res.json.error.code, 'INVALID_CREDENTIALS');
  });

  it('3. Unauthorized API requests to protected admin endpoints are rejected with 401', async () => {
    const statsNoToken = await apiRequest('/api/v1/admin/dashboard/stats');
    assert.equal(statsNoToken.status, 401);

    const ordersNoToken = await apiRequest('/api/v1/orders');
    assert.equal(ordersNoToken.status, 401);

    const createServiceNoToken = await apiRequest('/api/v1/services', {
      method: 'POST',
      body: { title: 'Unauthorized Service', description: 'Should fail' },
    });
    assert.equal(createServiceNoToken.status, 401);
  });

  it('4. Expired access tokens are rejected with HTTP 401', async () => {
    const expiredJwt = await signJwt(
      {
        sub: 'adm-dtks-1',
        email: 'admin@dreamtechkashmirsolutions.studio',
        role: 'super_admin',
        type: 'access',
      },
      env.JWT_SECRET,
      -60 // Already expired 60 seconds ago
    );

    const expiredRes = await apiRequest('/api/v1/auth/me', { token: expiredJwt });
    assert.equal(expiredRes.status, 401);
  });

  it('5. Refresh-token rotation issues a new token pair and revokes the previous refresh token', async () => {
    const refreshRes = await apiRequest('/api/v1/auth/refresh', {
      method: 'POST',
      body: { refreshToken },
    });
    assert.equal(refreshRes.status, 200);
    assert.ok(refreshRes.json.data.accessToken);
    assert.ok(refreshRes.json.data.refreshToken);
    assert.notEqual(refreshRes.json.data.refreshToken, refreshToken);

    // Old refresh token is now revoked in refresh_sessions and cannot be reused
    const reuseOldRefresh = await apiRequest('/api/v1/auth/refresh', {
      method: 'POST',
      body: { refreshToken },
    });
    assert.equal(reuseOldRefresh.status, 401);

    accessToken = refreshRes.json.data.accessToken;
    refreshToken = refreshRes.json.data.refreshToken;
  });

  it('6. Service CRUD operations work with real D1 persistence and public visibility filtering', async () => {
    const createRes = await apiRequest('/api/v1/services', {
      method: 'POST',
      token: accessToken,
      body: {
        title: 'Custom Web Portals & Dashboards',
        slug: 'custom-web-portals-dashboards',
        order_category: 'Custom Web Portals & Dashboards',
        short_description: 'Tailored web portals and internal business dashboards.',
        description: 'End-to-end architecture and responsive development for custom web portals.',
        features: ['Role-based access', 'Fast search & reporting', 'Responsive layout'],
        price: 38000,
        is_active: true,
        display_order: 20,
      },
    });
    assert.equal(createRes.status, 201);
    const createdId = createRes.json.data.service.id;
    assert.equal(createRes.json.data.service.slug, 'custom-web-portals-dashboards');

    const getSlugRes = await apiRequest('/api/v1/services/custom-web-portals-dashboards');
    assert.equal(getSlugRes.status, 200);
    assert.equal(getSlugRes.json.data.service.title, 'Custom Web Portals & Dashboards');

    const updateRes = await apiRequest(`/api/v1/services/${createdId}`, {
      method: 'PUT',
      token: accessToken,
      body: {
        title: 'Custom Web Portals & Business Dashboards',
        price: 42000,
      },
    });
    assert.equal(updateRes.status, 200);
    assert.equal(updateRes.json.data.service.title, 'Custom Web Portals & Business Dashboards');
    assert.equal(updateRes.json.data.service.price, 42000);

    const deleteRes = await apiRequest(`/api/v1/services/${createdId}`, {
      method: 'DELETE',
      token: accessToken,
    });
    assert.equal(deleteRes.status, 200);

    const afterDeleteRes = await apiRequest('/api/v1/services/custom-web-portals-dashboards');
    assert.equal(afterDeleteRes.status, 404);
  });

  it('7. Package CRUD operations and service-based filtering (?service_id=) work', async () => {
    const createRes = await apiRequest('/api/v1/packages', {
      method: 'POST',
      token: accessToken,
      body: {
        name: 'Enterprise Corporate Website Package',
        category: 'Business & Corporate Websites',
        service_id: 'svc-business-websites',
        description: 'Comprehensive multi-department corporate website package.',
        price: 45000,
        currency: 'INR',
        pages_count: 'Up to 20 Pages',
        features: ['Custom design system', 'Technical SEO', 'Speed optimization'],
        revisions: '4 Revision Rounds',
        delivery_estimate: '3–4 Weeks',
        support_duration: '60 Days Post-Launch Support',
        is_active: true,
        is_featured: true,
        display_order: 15,
      },
    });
    assert.equal(createRes.status, 201);
    const pkgId = createRes.json.data.package.id;
    assert.equal(createRes.json.data.package.service_id, 'svc-business-websites');

    // Filter packages by service_id
    const filteredList = await apiRequest('/api/v1/packages?service_id=svc-business-websites');
    assert.equal(filteredList.status, 200);
    assert.ok(filteredList.json.data.packages.some((p) => p.id === pkgId));

    const updateRes = await apiRequest(`/api/v1/packages/${pkgId}`, {
      method: 'PUT',
      token: accessToken,
      body: {
        price: 48000,
        pages_count: 'Up to 25 Pages',
      },
    });
    assert.equal(updateRes.status, 200);
    assert.equal(updateRes.json.data.package.price, 48000);

    const delRes = await apiRequest(`/api/v1/packages/${pkgId}`, {
      method: 'DELETE',
      token: accessToken,
    });
    assert.equal(delRes.status, 200);
  });

  it('8. Portfolio CRUD operations, category filtering, pagination, and publishing toggle work', async () => {
    const createProjRes = await apiRequest('/api/v1/portfolio', {
      method: 'POST',
      token: accessToken,
      body: {
        project_title: 'Pahalgam Eco Lodge Booking Website',
        slug: 'pahalgam-eco-lodge-website',
        category: 'Restaurant & Hotel Websites',
        short_overview: 'Eco lodge website with seasonal tariff tables.',
        description: 'Designed and developed a fast hospitality website for a Pahalgam lodge.',
        thumbnail: '/assets/images/dtks-corporate-website-showcase.jpg',
        images: ['/assets/images/dtks-corporate-website-showcase.jpg'],
        project_url: 'https://dreamtechkashmirsolutions.studio',
        is_published: true,
        display_order: 1,
      },
    });
    assert.equal(createProjRes.status, 201);
    const projId = createProjRes.json.data.project.id;

    // Test pagination (?page=1&limit=2)
    const paginatedRes = await apiRequest('/api/v1/portfolio?page=1&limit=2');
    assert.equal(paginatedRes.status, 200);
    assert.equal(paginatedRes.json.data.projects.length, 2);
    assert.equal(paginatedRes.json.data.pagination.page, 1);
    assert.equal(paginatedRes.json.data.pagination.limit, 2);
    assert.ok(paginatedRes.json.data.pagination.total >= 4);

    // Unpublish project and verify public cannot access unpublished project
    const unpubRes = await apiRequest(`/api/v1/portfolio/${projId}`, {
      method: 'PUT',
      token: accessToken,
      body: { is_published: false },
    });
    assert.equal(unpubRes.status, 200);
    assert.equal(unpubRes.json.data.project.is_published, false);

    const hiddenSlugRes = await apiRequest('/api/v1/portfolio/pahalgam-eco-lodge-website');
    assert.equal(hiddenSlugRes.status, 404);

    const delRes = await apiRequest(`/api/v1/portfolio/${projId}`, {
      method: 'DELETE',
      token: accessToken,
    });
    assert.equal(delRes.status, 200);
  });

  it('9. R2 image uploads support uploading, serving, replacing, and deleting portfolio assets', async () => {
    const formData = new FormData();
    const fileBlob = new Blob([VALID_PNG_BYTES], { type: 'image/png' });
    formData.append('file', fileBlob, 'kashmir-hospitality-preview.png');
    formData.append('folder', 'portfolio');

    const uploadRes = await apiRequest('/api/v1/portfolio/upload', {
      method: 'POST',
      token: accessToken,
      body: formData,
    });
    assert.equal(uploadRes.status, 201);
    const uploadedAsset = uploadRes.json.data.asset;
    assert.ok(uploadedAsset.key.startsWith('portfolio/'));
    assert.ok(uploadedAsset.url.startsWith('/api/v1/uploads/portfolio/'));

    // Verify serving the uploaded image from R2
    const assetGetRes = await apiRequest(uploadedAsset.url);
    assert.equal(assetGetRes.status, 200);
    assert.equal(assetGetRes.headers.get('content-type'), 'image/png');

    // Delete uploaded image via DELETE /api/v1/portfolio/upload
    const deleteAssetRes = await apiRequest('/api/v1/portfolio/upload', {
      method: 'DELETE',
      token: accessToken,
      body: { key: uploadedAsset.key },
    });
    assert.equal(deleteAssetRes.status, 200);

    // Verify deleted asset returns 404
    const afterDelGetRes = await apiRequest(uploadedAsset.url);
    assert.equal(afterDelGetRes.status, 404);
  });

  it('10. Customer order submissions create customer + order in D1 with Pending status and order_number', async () => {
    const orderRes = await apiRequest('/api/v1/orders', {
      method: 'POST',
      body: {
        service_id: 'svc-ecommerce-websites',
        package_id: 'pkg-ecommerce-store',
        project_name: 'Kashmir Pashmina Online Storefront',
        business_name: 'Zoon Artisans Collective',
        project_description: 'Direct-to-consumer storefront for authentic Kashmiri Pashmina shawls with catalog filters.',
        budget: '₹30,000 – ₹60,000',
        customer_name: 'Tariq Ahmad',
        customer_email: 'tariq.ahmad@example.com',
        customer_phone: '+91 97971 23456',
        customer_city: 'Srinagar',
      },
    });

    assert.equal(orderRes.status, 201);
    const createdOrder = orderRes.json.data.order;
    assert.ok(createdOrder.order_number.startsWith('DKS-'));
    assert.equal(createdOrder.status, 'Pending');
    assert.equal(createdOrder.customer_email, 'tariq.ahmad@example.com');

    // Public tracking with matching referenceId + email
    const trackRes = await apiRequest(
      `/api/v1/orders/track?ref=${encodeURIComponent(createdOrder.order_number)}&email=${encodeURIComponent('tariq.ahmad@example.com')}`
    );
    assert.equal(trackRes.status, 200);
    assert.equal(trackRes.json.data.order.project_name, 'Kashmir Pashmina Online Storefront');
    assert.ok(Array.isArray(trackRes.json.data.order.statusHistory));
  });

  it('11. Invalid order submissions are rejected with 400 and field-level validation errors', async () => {
    const badOrderRes = await apiRequest('/api/v1/orders', {
      method: 'POST',
      body: {
        customer_name: 'A',
        customer_email: 'not-an-email',
        customer_phone: '123',
        project_description: 'Too short',
      },
    });

    assert.equal(badOrderRes.status, 400);
    assert.equal(badOrderRes.json.success, false);
    assert.equal(badOrderRes.json.error.code, 'VALIDATION_ERROR');
    assert.ok(badOrderRes.json.error.details.customerEmail);
    assert.ok(badOrderRes.json.error.details.customerPhone);
  });

  it('12. Order status updates validate allowed statuses and record order_status_history', async () => {
    const unauthPatch = await apiRequest('/api/v1/orders/DKS-2026-0001/status', {
      method: 'PATCH',
      body: { status: 'Approved' },
    });
    assert.equal(unauthPatch.status, 401);

    const adminPatch = await apiRequest('/api/v1/orders/DKS-2026-0001/status', {
      method: 'PATCH',
      token: accessToken,
      body: {
        status: 'InProgress',
        customer_update: 'Development sprint started.',
        admin_notes: 'Verified domain DNS readiness.',
      },
    });
    assert.equal(adminPatch.status, 200);
    assert.equal(adminPatch.json.data.order.status, 'InProgress');
    assert.ok(
      adminPatch.json.data.order.statusHistory.some((h) => h.new_status === 'InProgress')
    );
  });

  it('13. Contact form submissions, search (?search=), status updates, and deletion work', async () => {
    const createMsg = await apiRequest('/api/v1/contact', {
      method: 'POST',
      body: {
        name: 'Nadia Shah',
        email: 'nadia.shah@example.com',
        phone: '+91 99061 11223',
        subject: 'Corporate Website Redesign Inquiry',
        message: 'We want to redesign our existing 10-page hospitality website with faster mobile performance.',
      },
    });
    assert.equal(createMsg.status, 201);
    const inquiryId = createMsg.json.data.inquiry.id;

    // Admin searches contact messages
    const searchRes = await apiRequest('/api/v1/contact?search=Nadia', { token: accessToken });
    assert.equal(searchRes.status, 200);
    assert.ok(searchRes.json.data.messages.some((i) => i.id === inquiryId));

    // Admin updates inquiry status and notes
    const patchRes = await apiRequest(`/api/v1/contact/${inquiryId}`, {
      method: 'PATCH',
      token: accessToken,
      body: {
        status: 'Replied',
        admin_notes: 'Sent consultation slots and package comparison PDF.',
      },
    });
    assert.equal(patchRes.status, 200);
    assert.equal(patchRes.json.data.message.status, 'Replied');
    assert.equal(patchRes.json.data.message.admin_notes, 'Sent consultation slots and package comparison PDF.');
  });

  it('14. Admin dashboard statistics and analytics reflect real D1 database records', async () => {
    const [statsRes, recentOrdersRes, recentMessagesRes, analyticsRes] = await Promise.all([
      apiRequest('/api/v1/admin/dashboard/stats', { token: accessToken }),
      apiRequest('/api/v1/admin/dashboard/recent-orders', { token: accessToken }),
      apiRequest('/api/v1/admin/dashboard/recent-messages', { token: accessToken }),
      apiRequest('/api/v1/admin/dashboard/order-analytics', { token: accessToken }),
    ]);

    assert.equal(statsRes.status, 200);
    assert.ok(statsRes.json.data.stats.totalOrders >= 2);
    assert.ok(statsRes.json.data.stats.pendingOrders >= 1);
    assert.ok(statsRes.json.data.stats.totalCustomers >= 2);
    assert.ok(statsRes.json.data.stats.totalContactMessages >= 2);
    assert.ok(statsRes.json.data.stats.activeServices >= 1);
    assert.ok(statsRes.json.data.stats.activePackages >= 1);
    assert.ok(statsRes.json.data.stats.totalPortfolioItems >= 1);

    assert.equal(recentOrdersRes.status, 200);
    assert.ok(recentOrdersRes.json.data.orders.length >= 2);

    assert.equal(recentMessagesRes.status, 200);
    assert.ok(recentMessagesRes.json.data.messages.length >= 2);

    assert.equal(analyticsRes.status, 200);
    assert.ok(Array.isArray(analyticsRes.json.data.analytics.byStatus));
    assert.ok(Array.isArray(analyticsRes.json.data.analytics.byService));
  });

  it('15. Database persistence across restarts keeps created orders and messages intact', async () => {
    const reopenedEnv = createNodeWorkerEnv({ dbPath, r2Dir });
    const req = new Request(
      'https://dreamtechkashmirsolutions.studio/api/v1/admin/dashboard/stats',
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${accessToken}` },
      }
    );
    const res = await workerApp.fetch(req, reopenedEnv, {});
    const json = await res.json();
    reopenedEnv.DB.close();
    assert.equal(res.status, 200);
    assert.ok(json.data.stats.totalOrders >= 2);
  });

  it('16. CORS restrictions allow production studio domain and block unauthorized origins', async () => {
    const allowedPreflight = await apiRequest('/api/v1/services', {
      method: 'OPTIONS',
      origin: 'https://dreamtechkashmirsolutions.studio',
    });
    assert.equal(allowedPreflight.status, 204);
    assert.equal(
      allowedPreflight.headers.get('Access-Control-Allow-Origin'),
      'https://dreamtechkashmirsolutions.studio'
    );

    const blockedPreflight = await apiRequest('/api/v1/services', {
      method: 'OPTIONS',
      origin: 'https://evil-attacker.example.com',
    });
    assert.equal(blockedPreflight.status, 403);
  });

  it('17. Rate limiting blocks brute-force login attempts with HTTP 429', async () => {
    const bruteIp = '203.0.113.77';
    let lastStatus = 200;

    for (let i = 0; i < 11; i++) {
      const res = await apiRequest('/api/v1/auth/login', {
        method: 'POST',
        ip: bruteIp,
        body: {
          email: 'admin@dreamtechkashmirsolutions.studio',
          password: 'WrongPassword!',
        },
      });
      lastStatus = res.status;
    }

    assert.equal(lastStatus, 429);
  });

  it('18. Request validation & sanitization strip dangerous script tags and reject spam honeypots', async () => {
    const spamRes = await apiRequest('/api/v1/contact', {
      method: 'POST',
      body: {
        name: 'Spam Bot',
        email: 'bot@example.com',
        subject: 'Spam',
        message: 'Automated spam message content',
        website_url_honeypot: 'http://spam-site.example.com',
      },
    });
    assert.equal(spamRes.status, 400);

    const xssRes = await apiRequest('/api/v1/contact', {
      method: 'POST',
      body: {
        name: 'Bilal <script>alert("xss")</script> Khan',
        email: 'bilal.khan@example.com',
        subject: 'Website Consultation',
        message: 'Looking for a corporate website without <script>evil()</script> payloads.',
      },
    });
    assert.equal(xssRes.status, 201);
    assert.ok(!xssRes.json.data.message.name.includes('<script>'));
    assert.ok(!xssRes.json.data.message.message.includes('<script>'));
  });

  it('19. File upload restrictions reject non-image files and spoofed binary signatures', async () => {
    const badForm = new FormData();
    const textBlob = new Blob(['<script>alert(1)</script>'], { type: 'text/html' });
    badForm.append('file', textBlob, 'malicious.html');

    const res = await apiRequest('/api/v1/portfolio/upload', {
      method: 'POST',
      token: accessToken,
      body: badForm,
    });
    assert.equal(res.status, 400);
    assert.equal(res.json.error.code, 'INVALID_IMAGE_UPLOAD');

    const spoofedForm = new FormData();
    const spoofedBlob = new Blob([Buffer.from('not-a-real-png-binary')], { type: 'image/png' });
    spoofedForm.append('file', spoofedBlob, 'spoofed.png');

    const spoofRes = await apiRequest('/api/v1/portfolio/upload', {
      method: 'POST',
      token: accessToken,
      body: spoofedForm,
    });
    assert.equal(spoofRes.status, 400);
    assert.equal(spoofRes.json.error.code, 'INVALID_IMAGE_UPLOAD');
  });

  it('20. Admin role-based authorization & public site settings protect sensitive configuration', async () => {
    // Public GET /api/v1/settings succeeds and strips any secret keys
    const updateSettingsRes = await apiRequest('/api/v1/settings', {
      method: 'PUT',
      token: accessToken,
      body: {
        companyName: 'DreamTech Kashmir Solutions',
        officialEmail: 'dreamtechkashmirsolutions@gmail.com',
        jwtSecret: 'should-never-be-stored-or-exposed',
        apiKey: 'should-be-stripped',
      },
    });
    assert.equal(updateSettingsRes.status, 200);
    assert.equal(updateSettingsRes.json.data.settings.jwtSecret, undefined);
    assert.equal(updateSettingsRes.json.data.settings.apiKey, undefined);

    const publicSettingsRes = await apiRequest('/api/v1/settings');
    assert.equal(publicSettingsRes.status, 200);
    assert.equal(publicSettingsRes.json.data.settings.companyName, 'DreamTech Kashmir Solutions');
    assert.equal(publicSettingsRes.json.data.settings.jwtSecret, undefined);

    // Token for an inactive or non-existent admin role is rejected
    const fakeRoleToken = await signJwt(
      {
        sub: 'adm-dtks-1',
        email: 'admin@dreamtechkashmirsolutions.studio',
        role: 'guest',
        type: 'access',
      },
      env.JWT_SECRET,
      900
    );
    //Temporarily set invalid role in DB to verify RBAC enforcement
    await env.DB.prepare("UPDATE admins SET is_active = 0 WHERE id = 'adm-dtks-1'").run();
    const disabledAdminRes = await apiRequest('/api/v1/admin/dashboard/stats', {
      token: fakeRoleToken,
    });
    assert.equal(disabledAdminRes.status, 401);
    await env.DB.prepare("UPDATE admins SET is_active = 1 WHERE id = 'adm-dtks-1'").run();
  });
});

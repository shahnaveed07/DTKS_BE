# DTKS_BE Security Architecture & Hardening Report

**Scope:** `backend/src/**` (Cloudflare Worker + D1 + R2 + WebCrypto + Resend)

---

## 1. Authentication & Cryptographic Isolation

1. **Zero Hardcoded Fallback Admin Credentials (`backend/src/database/seed.js`)**:
   - `ensureDatabaseSeeded()` creates an initial `super_admin` **only** when the `admins` table has 0 rows **and** both `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD` pass `isValidBootstrapPassword()` (`length >= 10`, rejecting `changeme`, `replace-with`, `placeholder`, `your-strong`, `admin123`, `12345678`, `<your`).
2. **Password Hashing (`backend/src/utils/crypto.js`)**:
   - Uses WebCrypto `PBKDF2-HMAC-SHA512` at `100,000` iterations with 16-byte random salt (`$pbkdf2-sha512$v=1$i=100000$<salt>$<hash>`) and constant-time comparison (`timingSafeEqual`).
   - Transparently verifies legacy `$argon2id$` hashes on login and upgrades them to `$pbkdf2-sha512$` in D1.
3. **Domain-Isolated JWTs & Session Revocation (`backend/src/middleware/authMiddleware.js`)**:
   - Admin JWTs include `accountType: 'admin'`; Client JWTs include `accountType: 'client'`.
   - `authenticateAdmin` rejects Client JWTs (`401`); `authenticateClient` rejects Admin JWTs (`401`).
   - Every access token embeds `tv` (`token_version`) checked live against `admins.token_version` or `customer_accounts.token_version`, enabling immediate token invalidation across all Worker isolates on password change/reset, role update, deactivation, or `DELETE /admin/accounts/:id/sessions`.
   - Refresh tokens are never stored in plaintext; SHA-256 hashes are persisted in `refresh_sessions` / `customer_refresh_sessions` and rotated single-use on `/refresh`.
4. **Admin Onboarding & Client Email Verification**:
   - Public admin registration does not exist. New admins are created disabled (`!PENDING_INVITE_SETUP`, `is_active = 0`) and activated solely via single-use, 48h SHA-256-hashed `admin_invitations` tokens.
   - Public client accounts require email verification via single-use 24h `customer_auth_tokens` before login and safely link existing `customers` + unlinked `orders` only after verification.

---

## 2. Role-Based Access Control (RBAC)

- **`super_admin`**: Full access including `/admin/accounts` creation, role edits, activation/deactivation, invite resends, and session revocation. Last active `super_admin` cannot be demoted or deactivated (`409 LAST_SUPER_ADMIN_PROTECTED`).
- **`admin`**: Full workspace access (`DELETE`, `PUT /services`, `PUT /packages/config/*`, `PUT /settings`, `/admin/activity-logs`, `/admin/notifications`) + read-only `GET /admin/accounts` & `GET /admin/accounts/:id`. Blocked (`403`) from admin account mutations.
- **`editor`**: Can create/update services, packages, portfolio items, R2 uploads, team members, testimonials, orders, and inquiries. Blocked (`403`) from all `DELETE` endpoints, bulk `PUT /services`, `PUT /packages/config/*`, `PUT /settings`, `/admin/activity-logs`, `/admin/notifications`, and `/admin/accounts*`.

---

## 3. Transport, CORS, CSRF & HTTP Security Headers

- **Strict Production CORS (`backend/src/config/cors.js`)**:
  - When `ENVIRONMENT === 'production'` (unless `ALLOW_LOCAL_CORS === 'true'`), `isOriginAllowed` strictly rejects `localhost`, `127.0.0.1`, `[::1]`, and `https://*.run.app` origins with `403 CORS_ORIGIN_FORBIDDEN` — even if development origins were left in `CORS_ALLOWED_ORIGINS`.
  - Requests without an `Origin` header do not receive an echoed hardcoded `Access-Control-Allow-Origin`.
- **CSRF Protection (`backend/src/middleware/authMiddleware.js`)**:
  - Whenever an Admin or Client authenticates via cookies (`dtks_access_token` / `dtks_client_access_token`) on state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`), a matching double-submit `X-CSRF-Token` header is mandatory (`403 CSRF_VALIDATION_FAILED`).
- **Response Security Headers (`backend/src/middleware/securityHeaders.js`)**:
  - Sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, and `Strict-Transport-Security` in production.

---

## 4. Rate Limiting & Abuse Controls (`backend/src/middleware/rateLimiter.js`)

- Uses atomic SQLite `INSERT INTO rate_limits ... ON CONFLICT(rate_key) DO UPDATE ... RETURNING window_start, request_count` inside D1 so concurrent requests cannot bypass counters via read-modify-write races, optionally paired with Cloudflare's native `ADMIN_RESET_RATE_LIMITER` binding (`8` req / `60s` edge burst guard).
- In `ENVIRONMENT === 'production'`, `getClientIp()` relies strictly on Cloudflare's trusted `CF-Connecting-IP` header rather than client-spoofable `X-Forwarded-For`.
- Dedicated thresholds protect `authLogin` (10/15m), `authRefresh` (30/15m), `clientRegister` (10/15m), `clientVerifyEmail` (15/15m), `passwordReset` (8/15m), `adminPasswordReset` (8/15m per IP), `adminPasswordResetEmail` (5/15m per normalized email HMAC across all IPs), `adminPasswordResetToken` (8/15m per token HMAC across all IPs), `adminInvite` (20/15m), `publicSubmission` (25/10m), and `generalApi` (240/1m).
- Target emails and reset tokens used as rate-limit keys are hashed using keyed HMAC-SHA256 (`RATE_LIMIT_HMAC_SECRET` / `JWT_SECRET`) so plaintext emails and tokens are never stored in `rate_limits`.
- Sensitive Admin password-recovery endpoints fail closed (`503 RATE_LIMITER_UNAVAILABLE`) in `ENVIRONMENT === 'production'` if distributed rate limiting fails or is unavailable rather than falling back to isolate-local memory.

---

## 5. Input Validation, Injection & R2 Asset Safety

- **SQL Injection**: 100% parameterized D1 prepared statements (`.prepare(...).bind(...)`) across every controller and service.
- **XSS & Mass Assignment**:
  - `sanitizeText()` strips null bytes, `<script>`, `<iframe>`, `<object>`, `<embed>`, inline `on*=` handlers, and `javascript:`/`vbscript:` URIs.
  - `updateTeamMember` uses an explicit field whitelist instead of spreading arbitrary request keys.
  - `updateSiteSettings` recursively strips `__proto__`, `constructor`, `prototype`, and secret-like keys (`jwtSecret`, `apiKey`, `resendApiKey`, `passwordHash`, `/secret|password|private_key|api_key/i`) and sanitizes nested string values.
- **R2 Storage Security (`backend/src/services/storageService.js`)**:
  - Validates MIME type (`image/jpeg`, `image/png`, `image/webp`), max size (5 MB), and binary magic bytes (JPEG `FF D8 FF`, PNG `89 50 4E 47`, WebP `RIFF....WEBP`).
  - `normalizeAssetKey()` safely decodes URI components, restricts uploads to allowlisted folders (`portfolio`, `services`, `team`, `general`), rejects null bytes / `..` / `\`, and returns `400 INVALID_ASSET_KEY` on malformed percent-encoding.
- **External Provider Timeouts (`backend/src/services/emailService.js`)**:
  - Enforces a 10-second `AbortSignal.timeout(10000)` on outbound Resend API calls.

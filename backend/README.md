# DTKS_BE – DreamTech Kashmir Solutions Backend

**Production Website:** `https://dreamtechkashmirsolutions.studio/`  
**Backend Repository:** `https://github.com/shahnaveed07/DTKS_BE.git`  
**Frontend Repository:** `https://github.com/shahnaveed07/DTKS.git`  
**Architecture:** Cloudflare Workers (JavaScript ES Modules) + Cloudflare D1 (SQLite) + Cloudflare R2 Object Storage

This repository contains **only** the production REST API backend for **DreamTech Kashmir Solutions (DTKS)**. It is independently deployable to Cloudflare Workers and serves the separate DTKS frontend application via `/api/v1/*`.

---

## 1. Directory Structure

```text
backend/
├── src/
│   ├── index.js                  # Cloudflare Worker fetch entry point
│   ├── routes/
│   │   └── router.js             # REST API router (/api/v1/*), HTTPS enforcement & granular RBAC
│   ├── controllers/
│   │   ├── authController.js          # Admin CSRF, login, logout, refresh replay detection, profile, password reset/change
│   │   ├── adminAccountsController.js # Super-admin account management, #token= invite creation/acceptance, status & revocation
│   │   ├── clientAuthController.js    # Client CSRF, registration, verification, historical linking, login, refresh, logout & reset
│   │   ├── clientPortalController.js  # Strictly client-scoped orders, quotations & active projects
│   │   ├── servicesController.js      # Services CRUD, URL validation & public catalog
│   │   ├── packagesController.js      # Packages CRUD, service filtering, add-ons & maintenance
│   │   ├── portfolioController.js     # Portfolio CRUD, URL validation, pagination, ordering, R2 image uploads
│   │   ├── ordersController.js        # Guest-isolated orders, hashed tracking tokens (POST /orders/track), admin status & history
│   │   ├── contactController.js       # Contact form submission, spam filtering, admin search & notes
│   │   ├── dashboardController.js     # Real-time D1 dashboard stats, recent items & analytics
│   │   └── settingsController.js      # Site settings (secret stripping), visibility-filtered team/testimonials & bootstrap
│   ├── services/
│   │   ├── auditService.js            # Admin & client security audit logging (activity_logs table)
│   │   ├── emailService.js            # Transactional Resend email delivery (#token= fragments & non-blocking security alerts)
│   │   └── storageService.js          # Cloudflare R2 object upload (pre-read size limits, strict key regex), serving & deletion
│   ├── middleware/
│   │   ├── authMiddleware.js          # Cookie-first & X-Auth-Mode: bearer JWT auth, token_version, RBAC & double-submit CSRF
│   │   ├── rateLimiter.js             # Distributed D1 sliding-window fail-closed rate limiter (+ HMAC email/token bucketing)
│   │   ├── securityHeaders.js         # Strict CORS, CSP, X-Frame-Options: DENY, CORP, COOP, no-store & HSTS
│   │   └── errorHandler.js            # Standardized error handling without internal stack leaks
│   ├── database/
│   │   ├── d1Adapter.js               # Node.js SQLite + filesystem R2 adapter for local dev/testing
│   │   └── seed.js                    # Non-destructive catalog seeder & 19-table schema verification
│   ├── validators/
│   │   └── schemas.js                 # Request validation, >=12-char password & denylist checks, isSafeUrl & magic-byte checks
│   ├── utils/
│   │   ├── crypto.js                  # WebCrypto PBKDF2-HMAC-SHA512 ($pbkdf2-sha512$), legacy migration, timingSafeEqual, strict JWT
│   │   └── response.js                # Standardized JSON response, XSS sanitizer & body size enforcement
│   └── config/
│       ├── constants.js               # Cookie names, token lifetimes, MIME types, R2 folders & body size limits
│       └── cors.js                    # Allowed origin validation & CORS header builder (including X-CSRF-Token & X-Auth-Mode)
├── migrations/
│   ├── 0001_initial_schema.sql                           # 13 core D1 tables, foreign keys, CHECK constraints & indexes
│   ├── 0002_seed_data.sql                                # Non-destructive initial site settings migration (INSERT OR IGNORE)
│   ├── 0003_admin_accounts_and_client_auth.sql           # Additive admin invite/revocation columns + 4 client/invite tables
│   ├── 0004_client_legal_acceptance_and_security_fixes.sql # Client legal acceptance persistence & composite security indexes
│   ├── 0005_admin_password_reset.sql                     # Admin password reset tokens (`admin_auth_tokens`) & indexes
│   └── 0006_security_remediation.sql                     # `order_tracking_tokens` table + `revoke_reason` session columns
├── tests/
│   ├── backend.test.js                # Core API security, RBAC, CRUD, R2 & fault-handling tests
│   ├── auth_and_accounts.test.js      # Admin account management, client auth, linking & isolation tests
│   ├── admin_password_reset.test.js   # Admin forgot/reset password, anti-enumeration, concurrency & isolation tests
│   ├── contract_and_security.test.js  # Frontend contract parity, CORS, atomic batch & OpenAPI parity tests
│   └── security_remediation.test.js   # Master security remediation suite (cookies, CSRF, replay, tracking tokens, headers, R2)
├── docs/                              # OpenAPI 3.0.3, Postman collection, API docs, audit, migration, security & test reports
├── wrangler.toml                      # Cloudflare Workers, D1, R2 & rate-limit configuration
├── .dev.vars.example                  # Example environment variables & secrets
└── package.json                       # Backend scripts & metadata
```

---

## 2. Security Architecture

1. **No Default or Fallback Administrator Credentials**:
   - An initial administrator is created **only** when `admins` is empty **and** explicit `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD` (`>= 12` chars, non-placeholder) are configured.
2. **WebCrypto PBKDF2-HMAC-SHA512 & Strict JWT Validation**:
   - Passwords enforce `>= 12` characters, mixed case, digit, symbol, weak denylist rejection, and `$pbkdf2-sha512$v=1$i=100000$...` hashing.
   - `verifyJwt` enforces `alg: HS256`, `typ: JWT`, valid `iat`, optional `nbf`, `exp`, `accountType` isolation, and live `token_version` (`tv`).
3. **Cookie-First Auth + Double-Submit CSRF + Replay Detection**:
   - Host-only `HttpOnly; SameSite=Lax; Secure` cookies by default (`authMode: "cookie"`) omitting JWTs from JSON; explicit `X-Auth-Mode: bearer` opt-in for non-cookie API clients.
   - `X-CSRF-Token` validated against HttpOnly CSRF cookie on all cookie-authenticated mutations (including `/logout`, `/refresh`, and authenticated `POST /orders`).
   - Reusing a rotated refresh token triggers cascade revocation of all sessions + `token_version` increment (`401 REFRESH_TOKEN_REPLAY_DETECTED`), while single-device logout preserves sibling devices.
4. **Private Order Tracking & Safe Client Linking**:
   - `POST /api/v1/orders/track` accepts private 256-bit tracking tokens (`#token=` email links), returns strictly non-PII status summaries (`404` otherwise), and guest `POST /orders` never links into existing verified client portals (`customer_id = NULL`).
5. **Fail-Closed Distributed Rate Limiting & Strict Production Transport**:
   - `failClosedInProd: true` D1 + HMAC rate limiters (`503 RATE_LIMITER_UNAVAILABLE` on DB outage in production), no `ALLOW_LOCAL_CORS` bypass in production, `403 HTTPS_REQUIRED` on plaintext HTTP auth/admin/client/tracking requests, and hardened R2/API headers.

---

## 3. Local Development & Testing

### 3.1 Environment Variables
```bash
cp backend/.dev.vars.example backend/.dev.vars
```

### 3.2 Run Automated Backend Test Suite
From either the repository root or `backend/` (across all 5 suites):
```bash
npm test
# or
cd backend && npm test
```

### 3.3 Production Deployment (`dtks-be`)
```bash
cd backend
npx wrangler d1 migrations apply dtks-production-db --remote
npx wrangler secret put JWT_SECRET
npx wrangler secret put INITIAL_ADMIN_EMAIL
npx wrangler secret put INITIAL_ADMIN_PASSWORD
npx wrangler secret put INITIAL_ADMIN_NAME
npx wrangler secret put RESEND_API_KEY
npx wrangler deploy --env production
```

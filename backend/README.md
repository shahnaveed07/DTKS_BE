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
│   │   └── router.js             # REST API router (/api/v1/*) with granular RBAC
│   ├── controllers/
│   │   ├── authController.js          # Admin login, logout, token refresh, profile, password change & hash migration
│   │   ├── adminAccountsController.js # Super-admin account management, invite creation/acceptance, status & session revocation
│   │   ├── clientAuthController.js    # Client registration, email verification, customer linking, login, refresh & password reset
│   │   ├── clientPortalController.js  # Strictly client-scoped orders, quotations & active projects
│   │   ├── servicesController.js      # Services CRUD & public catalog
│   │   ├── packagesController.js      # Packages CRUD, service filtering, add-ons & maintenance
│   │   ├── portfolioController.js     # Portfolio CRUD, pagination, ordering, R2 image uploads
│   │   ├── ordersController.js        # Customer order creation, tracking, admin status & history
│   │   ├── contactController.js       # Contact form submission, spam filtering, admin search & notes
│   │   ├── dashboardController.js     # Real-time D1 dashboard stats, recent items & analytics
│   │   └── settingsController.js      # Public & admin site settings (with secret stripping)
│   ├── services/
│   │   ├── auditService.js            # Admin & client security audit logging (activity_logs table)
│   │   ├── emailService.js            # Transactional Resend email delivery (verification, password reset, admin invites, alerts)
│   │   └── storageService.js          # Cloudflare R2 object upload, serving & deletion
│   ├── middleware/
│   │   ├── authMiddleware.js          # Isolated Admin & Client JWT verification, token_version checks, RBAC & CSRF validation
│   │   ├── rateLimiter.js             # Distributed D1 sliding-window rate limiter (+ native binding support)
│   │   ├── securityHeaders.js         # CORS origin enforcement & HTTP security headers
│   │   └── errorHandler.js            # Standardized error handling without internal stack leaks
│   ├── database/
│   │   ├── d1Adapter.js               # Node.js SQLite + filesystem R2 adapter for local dev/testing
│   │   └── seed.js                    # Non-destructive, idempotent catalog & explicit initial admin seeder
│   ├── validators/
│   │   └── schemas.js                 # Request payload validation, password strength, XSS sanitization & magic-byte checks
│   ├── utils/
│   │   ├── crypto.js                  # WebCrypto PBKDF2-HMAC-SHA512 ($pbkdf2-sha512$), legacy migration, JWT
│   │   └── response.js                # Standardized JSON response, XSS sanitizer & body size enforcement
│   └── config/
│       ├── constants.js               # Allowed statuses, roles, token lifetimes, MIME types & size limits
│       └── cors.js                    # Allowed origin validation & CORS header builder (including X-CSRF-Token)
├── migrations/
│   ├── 0001_initial_schema.sql                          # 13 core D1 tables, foreign keys, CHECK constraints & indexes
│   ├── 0002_seed_data.sql                               # Non-destructive initial site settings migration (INSERT OR IGNORE)
│   ├── 0003_admin_accounts_and_client_auth.sql          # Additive admin invite/revocation columns + 4 client/invite tables
│   └── 0004_client_legal_acceptance_and_security_fixes.sql # Client legal acceptance persistence & composite security indexes
├── tests/
│   ├── backend.test.js                # 19 core API security, RBAC, CRUD, R2 & fault-handling tests
│   ├── auth_and_accounts.test.js      # 14 admin account management, client auth, linking & isolation tests
│   └── contract_and_security.test.js  # 7 frontend contract parity, CORS, atomic batch & OpenAPI parity tests
├── docs/
│   ├── API_DOCUMENTATION.md           # Complete REST API reference & frontend integration guide
│   ├── openapi.yaml                   # OpenAPI 3.0.3 specification (100% route/method parity)
│   ├── dtks-postman-collection.json   # Postman Collection v2.1
│   ├── BACKEND_PRODUCTION_AUDIT.md    # Complete production-readiness audit findings & remediations
│   ├── BACKEND_API_CONTRACT_MATRIX.md # Frontend DTKS <-> DTKS_BE API contract alignment matrix
│   ├── BACKEND_SECURITY_REPORT.md     # Security architecture, auth, CORS, CSRF, rate-limit & R2 audit
│   ├── DATABASE_MIGRATION_REPORT.md   # D1 migration & 17-table schema verification report
│   └── BACKEND_TEST_REPORT.md         # Complete test & verification execution report
├── wrangler.toml                      # Cloudflare Workers, D1, and R2 configuration
├── .dev.vars.example                  # Example environment variables & secrets
└── package.json                       # Backend scripts & metadata
```

---

## 2. Security Architecture

1. **No Default or Fallback Administrator Credentials**:
   - An initial administrator is created **only** when the `admins` table is empty **and** both `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD` (minimum 10 characters, non-placeholder) are explicitly provided via environment secrets.
   - New administrators are onboarded strictly via expiring, single-use, SHA-256-hashed invitations (`POST /api/v1/admin/accounts` -> `POST /api/v1/auth/accept-invite`); public admin registration does not exist.
2. **WebCrypto PBKDF2-HMAC-SHA512 Password Hashing & Transparent Migration**:
   - New and updated admin & client passwords use canonical PHC format: `$pbkdf2-sha512$v=1$i=100000$<saltHex>$<hashHex>` with constant-time comparison.
   - Existing legacy `$argon2id$v=19$...` hashes are transparently verified on login and automatically re-hashed to `$pbkdf2-sha512$v=1$i=100000$...`.
3. **Strictly Isolated Admin & Client JWT Authentication + Session Revocation**:
   - Short-lived access tokens (`15m`) and rotated refresh tokens (`7d`) signed with HMAC-SHA256 (`JWT_SECRET` >= 32 characters in production).
   - Admin tokens carry `accountType: "admin"` and `tv` (`token_version`); Client tokens carry `accountType: "client"` and `tv`. `authenticateAdmin` and `authenticateClient` strictly reject cross-domain tokens.
   - Refresh tokens are stored as SHA-256 hashes in `refresh_sessions` / `customer_refresh_sessions`, rotated on every refresh, and immediately invalidated alongside `token_version` bumps on password change, reset, deactivation, or super-admin session revocation.
4. **Role-Based Access Control (RBAC)**:
   - `super_admin`: Full workspace access plus creating/inviting admins, changing roles, activating/deactivating admin accounts, and revoking sessions (with last-active-`super_admin` demotion/deactivation protection).
   - `admin`: Full workspace access (`DELETE`, `PUT /settings`, `PUT /services`, package configs, activity logs, notifications) plus read-only access to `/api/v1/admin/accounts`. Cannot create admins, alter roles/statuses, or revoke sessions.
   - `editor`: Create and update services, packages, portfolio items, R2 uploads, team members, testimonials, orders, and contact inquiries. Restricted (`403 Forbidden`) from deleting records/R2 objects, bulk catalog/config overwrites, modifying global settings, viewing audit logs, or accessing `/api/v1/admin/accounts`.
5. **Safe Client Verification & Guest Customer Linking**:
   - Public client registration stores credentials in `customer_accounts` (isolated from `customers`), requires email verification via single-use SHA-256-hashed tokens before sign-in, and links to existing `customers` rows + unlinked historical `orders` only after email ownership is verified.
   - Unauthenticated guest `POST /api/v1/orders` preserves guest submissions while preventing overwrite of `customers` records linked to verified `customer_accounts`.
6. **Atomic Distributed Rate Limiting & Production CORS/CSRF**:
   - Atomic `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` counters in the Cloudflare D1 `rate_limits` table across Worker isolates (and optional Cloudflare native `RATE_LIMITER` binding), trusting `CF-Connecting-IP` in production rather than spoofable `X-Forwarded-For` headers.
   - Strict production CORS blocks `localhost`, `127.0.0.1`, `[::1]`, and `*.run.app` origins when `ENVIRONMENT=production` (unless `ALLOW_LOCAL_CORS=true` is explicitly enabled), and allows `Authorization` + `X-CSRF-Token`.

---

## 3. Relational Database Schema (Cloudflare D1)

Defined across `migrations/0001_initial_schema.sql`, `migrations/0003_admin_accounts_and_client_auth.sql`, and `migrations/0004_client_legal_acceptance_and_security_fixes.sql` with 17 tables, foreign keys, `CHECK` constraints, and indexes:

1. `admins` – Administrator accounts (`id`, `name`, `email`, `password_hash`, `role`, `is_active`, `token_version`, `invited_by_admin_id`, `invite_accepted_at`, `deactivated_at`, `created_at`, `updated_at`, `last_login_at`)
2. `admin_invitations` – Single-use expiring SHA-256-hashed admin onboarding invitations (`id`, `admin_id`, `email`, `token_hash`, `invited_by_admin_id`, `expires_at`, `used_at`, `revoked_at`, `created_at`)
3. `refresh_sessions` – Hashed admin refresh token sessions (`id`, `admin_id`, `refresh_token_hash`, `user_agent`, `ip_address`, `expires_at`, `revoked_at`, `created_at`)
4. `customers` – Customer profile records (`id`, `full_name`, `email`, `phone`, `city`, `business_name`, `created_at`, `updated_at`)
5. `customer_accounts` – Client authentication accounts (`id`, `customer_id`, `full_name`, `email`, `phone`, `city`, `business_name`, `password_hash`, `is_email_verified`, `email_verified_at`, `is_active`, `deactivated_at`, `token_version`, `terms_accepted`, `terms_accepted_at`, `terms_version`, `privacy_accepted`, `privacy_accepted_at`, `privacy_version`, `legal_accepted_ip`, `last_login_at`, `created_at`, `updated_at`)
6. `customer_refresh_sessions` – Hashed client refresh token sessions (`id`, `customer_account_id`, `refresh_token_hash`, `user_agent`, `ip_address`, `expires_at`, `revoked_at`, `created_at`)
7. `customer_auth_tokens` – Single-use expiring SHA-256-hashed verification and password-reset tokens (`id`, `customer_account_id`, `purpose`, `token_hash`, `expires_at`, `used_at`, `revoked_at`, `created_at`)
8. `services` – Website services (`id`, `title`, `slug`, `description`, `features`, `image`, `price`, `is_active`, `display_order`, `created_at`, `updated_at`, plus metadata columns)
9. `packages` – Service pricing packages (`id`, `name`, `description`, `price`, `features`, `service_id`, `is_active`, `display_order`, `created_at`, `updated_at`, plus scope columns)
10. `portfolio` – Website showcase items (`id`, `project_title`, `slug`, `description`, `category`, `thumbnail`, `images`, `project_url`, `is_published`, `display_order`, `created_at`, `updated_at`)
11. `orders` – Customer website orders (`id`, `order_number`, `customer_id`, `service_id`, `package_id`, `customer_name`, `customer_email`, `customer_phone`, `project_description`, `budget`, `status`, `admin_notes`, `created_at`, `updated_at`, plus scope & quotation columns)
12. `order_items` – Order line items (`id`, `order_id`, `item_type`, `title`, `description`, `quantity`, `unit_price`, `currency`, `created_at`)
13. `order_status_history` – Audit trail of order status transitions (`id`, `order_id`, `previous_status`, `new_status`, `changed_by_admin_id`, `notes`, `created_at`)
14. `contact_messages` – Customer inquiries (`id`, `name`, `email`, `phone`, `subject`, `message`, `status`, `admin_notes`, `created_at`, `updated_at`)
15. `site_settings` – Key-value JSON site configuration (`setting_key`, `setting_value`, `updated_at`, `updated_by_admin_id`)
16. `activity_logs` – Admin & client security audit & email delivery logs (`id`, `admin_id`, `action`, `entity_type`, `entity_id`, `details`, `ip_address`, `timestamp`)
17. `rate_limits` – Distributed sliding-window rate limit counters (`rate_key`, `window_start`, `request_count`, `expires_at`)

---

## 4. Local Development & Testing

### 4.1 Environment Variables
Copy `backend/.dev.vars.example` to `backend/.dev.vars` (for Wrangler) or `.env.example` to `.env` (for the local Node.js adapter):
```bash
cp backend/.dev.vars.example backend/.dev.vars
```

### 4.2 Run Automated Backend Test Suite
From either the repository root or `backend/` (40 automated tests across 3 suites):
```bash
npm test
# or
cd backend && npm test
```

### 4.3 Run with Cloudflare Wrangler
```bash
cd backend
npx wrangler d1 migrations apply dtks-production-db --local
npx wrangler dev
```

---

## 5. Production Cloudflare Deployment (`dtks-be`)

- **Worker Name**: `dtks-be`
- **Production Worker URL**: `https://dtks-be.snave9401.workers.dev`
- **Custom API Domain**: `https://api.dreamtechkashmirsolutions.studio`
- **D1 Database**: `dtks-production-db` (`be0ce24a-0151-412f-b308-1271bb62abba`, Binding: `DB`)
- **R2 Bucket**: `dtks-portfolio-assets` (Binding: `ASSETS_BUCKET`)

### Step 1: Apply D1 Database Migrations (Non-Destructive)
```bash
cd backend
npx wrangler d1 migrations apply dtks-production-db --remote
```

### Step 2: Configure Production Secrets
```bash
cd backend
npx wrangler secret put JWT_SECRET
npx wrangler secret put INITIAL_ADMIN_EMAIL
npx wrangler secret put INITIAL_ADMIN_PASSWORD
npx wrangler secret put INITIAL_ADMIN_NAME
npx wrangler secret put RESEND_API_KEY
```

### Step 3: Deploy Worker
```bash
cd backend
npx wrangler deploy
```

### Step 4: Verify Liveness & Readiness
```bash
curl -i https://dtks-be.snave9401.workers.dev/api/v1/health
curl -i https://dtks-be.snave9401.workers.dev/api/v1/ready
curl -i https://api.dreamtechkashmirsolutions.studio/api/v1/health
curl -i https://api.dreamtechkashmirsolutions.studio/api/v1/ready
```

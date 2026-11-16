# DTKS_BE Production Deployment Guide (Cloudflare Workers + D1 + R2)

This guide covers deploying the **DreamTech Kashmir Solutions (DTKS)** standalone backend (`dtks-be`) to production on Cloudflare Workers (`https://dtks-be.snave9401.workers.dev` and `https://api.dreamtechkashmirsolutions.studio`) and connecting the separate DTKS frontend repository (`https://github.com/shahnaveed07/DTKS.git`).

---

## 1. Existing Production Cloudflare Infrastructure

- **Worker Name**: `dtks-be`
- **Worker URL**: `https://dtks-be.snave9401.workers.dev`
- **Custom API Domain**: `https://api.dreamtechkashmirsolutions.studio`
- **D1 Database**: `dtks-production-db` (Binding: `DB`, ID: `be0ce24a-0151-412f-b308-1271bb62abba`)
- **R2 Bucket**: `dtks-portfolio-assets` (Binding: `ASSETS_BUCKET`)

---

## 2. Apply D1 Database Migrations (Safe & Non-Destructive)

Apply the additive D1 migrations (`0001_initial_schema.sql` through `0006_security_remediation.sql` — 19 tables total including `admin_invitations`, `admin_auth_tokens`, `customer_accounts`, `customer_refresh_sessions`, `customer_auth_tokens`, and `order_tracking_tokens`) to the existing `dtks-production-db` (`be0ce24a-0151-412f-b308-1271bb62abba`):

```bash
cd backend

# 1. Authenticate Wrangler (if not already authenticated)
npx wrangler login

# 2. Apply migrations to the remote production D1 database
npx wrangler d1 migrations apply dtks-production-db --remote
```

> **Safety Guarantee:** All migrations are strictly additive (`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, `INSERT OR IGNORE`, and additive `ALTER TABLE ... ADD COLUMN ...`). Existing production tables, customer orders, inquiries, and administrator accounts are never dropped or overwritten.

---

## 3. Configure Production Secrets (`dtks-be`)

Set your production secrets on the existing `dtks-be` Worker using `wrangler secret put`:

```bash
cd backend

# Required: 256-bit random secret (minimum 32 characters) for signing HMAC-SHA256 JWT tokens
npx wrangler secret put JWT_SECRET

# Required for initial admin bootstrap (used ONLY when the `admins` table is empty)
npx wrangler secret put INITIAL_ADMIN_EMAIL
npx wrangler secret put INITIAL_ADMIN_PASSWORD   # Minimum 12 characters, mixed case, digit, symbol

# Required for live transactional emails (client email verification, password resets, security alerts, and admin invitations)
npx wrangler secret put RESEND_API_KEY

# Optional: dedicated HMAC key for rate-limit bucket hashing (defaults to JWT_SECRET if unset)
npx wrangler secret put RATE_LIMIT_HMAC_SECRET
```

> **Important:** Make sure the domain in `EMAIL_FROM_ADDRESS` (`notifications@dreamtechkashmirsolutions.studio`) is verified in your Resend account, and `APP_URL` is configured (`https://dreamtechkashmirsolutions.studio` in `wrangler.toml`) so verification, password reset, invite, and order tracking links resolve via URL fragments (`/verify-email#token=...`, `/reset-password#token=...`, `/admin/accept-invite#token=...`, `/admin/reset-password#token=...`, `/track-order#token=...`).

---

## 4. Pre-Deployment Verification & Worker Deploy (`dtks-be`)

Before deploying to production, verify tests, TypeScript checks, and Wrangler dry-run locally:

```bash
cd backend && npm test && npx wrangler deploy --dry-run --env production
```

Then deploy the updated Worker code to `dtks-be`:

```bash
cd backend
npx wrangler deploy --env production
```

### Custom Domain, HTTPS & Safe Route Configuration
In `backend/wrangler.toml`, `name = "dtks-be"` and `workers_dev = true` ensure deployment updates the existing `dtks-be` Worker (`https://dtks-be.snave9401.workers.dev`) and preserves the custom API domain (`https://api.dreamtechkashmirsolutions.studio`) without overriding the separate frontend website hosted at `https://dreamtechkashmirsolutions.studio/`. Under `ENVIRONMENT = "production"`, development origins (`localhost`, `127.0.0.1`, `*.run.app`) are unconditionally blocked (`ALLOW_LOCAL_CORS` cannot bypass production CORS), and cleartext `http://` requests to `/auth/*`, `/client/*`, `/admin/*`, and `/orders/track` are rejected with `403 HTTPS_REQUIRED`.

---

## 5. Post-Deployment Verification Commands

### 5.1 Liveness Check (`GET /api/v1/health`)
```bash
curl -i https://dtks-be.snave9401.workers.dev/api/v1/health
curl -i https://api.dreamtechkashmirsolutions.studio/api/v1/health
```

### 5.2 Readiness Check (`GET /api/v1/ready`)
Verifies D1 database binding, D1 connection, all 19 required schema tables, and R2 storage binding:
```bash
curl -i https://dtks-be.snave9401.workers.dev/api/v1/ready
curl -i https://api.dreamtechkashmirsolutions.studio/api/v1/ready
```

### 5.3 Public Bootstrap & Admin Login Verification
```bash
# Public catalog & settings bootstrap
curl -s https://api.dreamtechkashmirsolutions.studio/api/v1/bootstrap | jq .success

# Administrator login (Bearer opt-in header for CLI smoke check)
curl -X POST https://api.dreamtechkashmirsolutions.studio/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Auth-Mode: bearer" \
  -d '{"email":"<YOUR_INITIAL_ADMIN_EMAIL>","password":"<YOUR_INITIAL_ADMIN_PASSWORD>"}'
```

---

## 6. Connecting the Separate DTKS Frontend (`https://github.com/shahnaveed07/DTKS.git`)

In the separate frontend repository (`DTKS`), configure:

```env
VITE_API_BASE_URL=https://api.dreamtechkashmirsolutions.studio/api/v1
```
*(or `/api/v1` same-origin via `https://dreamtechkashmirsolutions.studio/api/v1`)*

Frontend integration requirements:
1. Send `credentials: 'include'` on all API requests and omit `sessionStorage`/`localStorage` JWT storage (`authMode: 'cookie'` is default).
2. Bootstrap CSRF via `GET /api/v1/auth/csrf` or `GET /api/v1/client/auth/csrf` (or use `csrfToken` returned on `/login` & `/refresh`) and attach `X-CSRF-Token` on all mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`, including `POST /api/v1/orders` when signed in).
3. Parse verification, reset, invite, and order-tracking tokens from `window.location.hash` (`#token=...`), clear browser history immediately with `history.replaceState`, and submit order tracking via `POST /api/v1/orders/track` (`{ token }`).

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

Apply the additive D1 migrations (`0001_initial_schema.sql`, `0002_seed_data.sql`, `0003_admin_accounts_and_client_auth.sql`, `0004_client_legal_acceptance_and_security_fixes.sql`, and `0005_admin_password_reset.sql` — 18 tables total including `admin_invitations`, `admin_auth_tokens`, `customer_accounts`, `customer_refresh_sessions`, and `customer_auth_tokens`) to the existing `dtks-production-db` (`be0ce24a-0151-412f-b308-1271bb62abba`):

```bash
cd backend

# 1. Authenticate Wrangler (if not already authenticated)
npx wrangler login

# 2. Apply migrations to the remote production D1 database
npx wrangler d1 migrations apply dtks-production-db --remote
```

> **Safety Guarantee:** All migrations are strictly additive (`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, `INSERT OR IGNORE`, and additive `ALTER TABLE admins ADD COLUMN ...`). Existing production tables, customer orders, inquiries, and administrator accounts are never dropped or overwritten.

---

## 3. Configure Production Secrets (`dtks-be`)

Set your production secrets on the existing `dtks-be` Worker using `wrangler secret put`:

```bash
cd backend

# Required: 256-bit random secret (minimum 32 characters) for signing HMAC-SHA256 JWT tokens
npx wrangler secret put JWT_SECRET

# Required for initial admin bootstrap (used ONLY when the `admins` table is empty)
npx wrangler secret put INITIAL_ADMIN_EMAIL
npx wrangler secret put INITIAL_ADMIN_PASSWORD

# Required for live transactional emails (client email verification, password resets, security alerts, and admin invitations)
npx wrangler secret put RESEND_API_KEY
```

> **Important:** Make sure the domain in `EMAIL_FROM_ADDRESS` (`notifications@dreamtechkashmirsolutions.studio`) is verified in your Resend account, and `APP_URL` is configured (`https://dreamtechkashmirsolutions.studio` in `wrangler.toml`) so verification, password reset, and admin invite links resolve to the correct frontend routes (`/verify-email?token=...`, `/reset-password?token=...`, `/admin/accept-invite?token=...`, and fragment-based `/admin/reset-password#token=...`). Also verify `backend/wrangler.toml` includes the native `[[ratelimits]]` binding (`ADMIN_RESET_RATE_LIMITER`) and `ADMIN_PASSWORD_RESET_*` rate-limit variables.

---

## 4. Pre-Deployment Verification & Worker Deploy (`dtks-be`)

Before deploying to production, verify tests, TypeScript checks, and Wrangler dry-run locally:

```bash
cd backend && npm test && npx wrangler deploy --dry-run --env production
```

Then deploy the updated Worker code to `dtks-be`:

```bash
cd backend
npx wrangler deploy
```

### Custom Domain & Safe Route Configuration
In `backend/wrangler.toml`, `name = "dtks-be"` and `workers_dev = true` ensure deployment updates the existing `dtks-be` Worker (`https://dtks-be.snave9401.workers.dev`) and preserves the custom API domain (`https://api.dreamtechkashmirsolutions.studio`) without overriding the separate frontend website hosted at `https://dreamtechkashmirsolutions.studio/`. Under `ENVIRONMENT = "production"`, development origins (`localhost`, `127.0.0.1`, `*.run.app`) are automatically blocked unless `ALLOW_LOCAL_CORS = "true"` is explicitly configured.

---

## 5. Post-Deployment Verification Commands

### 5.1 Liveness Check (`GET /api/v1/health`)
Verifies the Worker is running (independent of D1/R2):
```bash
curl -i https://dtks-be.snave9401.workers.dev/api/v1/health
curl -i https://api.dreamtechkashmirsolutions.studio/api/v1/health
```
Expected `200 OK`:
```json
{
  "success": true,
  "message": "DTKS API is operational.",
  "data": {
    "service": "DTKS Backend API",
    "status": "healthy",
    "version": "1.0.0"
  }
}
```

### 5.2 Readiness Check (`GET /api/v1/ready`)
Verifies D1 database binding, D1 connection, all 18 required schema tables, and R2 storage binding:
```bash
curl -i https://dtks-be.snave9401.workers.dev/api/v1/ready
curl -i https://api.dreamtechkashmirsolutions.studio/api/v1/ready
```
Expected `200 OK` (once Step 2 D1 migrations are applied):
```json
{
  "success": true,
  "message": "DTKS Backend API dependencies are ready.",
  "data": {
    "status": "ready",
    "database": "connected",
    "schema": "valid",
    "storage": "available"
  }
}
```
*(Returns HTTP `503` if D1 migrations have not yet been applied or if a binding is missing.)*

### 5.3 Public Bootstrap & Admin Login Verification
```bash
# Public catalog & settings bootstrap
curl -s https://api.dreamtechkashmirsolutions.studio/api/v1/bootstrap | jq .success

# Administrator login
curl -X POST https://api.dreamtechkashmirsolutions.studio/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"<YOUR_INITIAL_ADMIN_EMAIL>","password":"<YOUR_INITIAL_ADMIN_PASSWORD>"}'
```

---

## 6. Connecting the Separate DTKS Frontend (`https://github.com/shahnaveed07/DTKS.git`)

In the separate frontend repository (`DTKS`), configure:

```env
VITE_API_BASE_URL=https://api.dreamtechkashmirsolutions.studio/api/v1
```
`dtks-be` automatically allows CORS requests from `https://dreamtechkashmirsolutions.studio` and `https://www.dreamtechkashmirsolutions.studio`.

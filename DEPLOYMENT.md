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

Apply the non-destructive relational schema (`0001_initial_schema.sql` — 13 tables including `rate_limits`) and initial site settings migration (`0002_seed_data.sql`) to the existing `dtks-production-db` (`be0ce24a-0151-412f-b308-1271bb62abba`):

```bash
cd backend

# 1. Authenticate Wrangler (if not already authenticated)
npx wrangler login

# 2. Apply migrations to the remote production D1 database
npx wrangler d1 migrations apply dtks-production-db --remote
```

> **Safety Guarantee:** Both migrations use `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, and `INSERT OR IGNORE`. Existing production tables, customer orders, inquiries, and administrator accounts are never dropped or overwritten.

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

# Optional: Transactional email API key (Resend) for live email delivery
npx wrangler secret put RESEND_API_KEY
```

---

## 4. Deploy to the Existing `dtks-be` Cloudflare Worker

From `/backend`, deploy the updated Worker code to `dtks-be`:

```bash
cd backend
npx wrangler deploy
```

### Custom Domain & Safe Route Configuration
In `backend/wrangler.toml`, `name = "dtks-be"` and `workers_dev = true` ensure deployment updates the existing `dtks-be` Worker (`https://dtks-be.snave9401.workers.dev`) and preserves the custom API domain (`https://api.dreamtechkashmirsolutions.studio`) without overriding the separate frontend website hosted at `https://dreamtechkashmirsolutions.studio/`.

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
Verifies D1 database binding, D1 connection, all 13 required schema tables, and R2 storage binding:
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

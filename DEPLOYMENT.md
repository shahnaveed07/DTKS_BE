# DTKS_BE Production Deployment Guide (Cloudflare Workers + D1 + R2)

This guide covers deploying the **DreamTech Kashmir Solutions (DTKS)** standalone backend (`DTKS_BE`) to production on Cloudflare Workers (`https://api.dreamtechkashmirsolutions.studio` or `https://dreamtechkashmirsolutions.studio/api/v1/*`) and connecting the separate DTKS frontend repository (`https://github.com/shahnaveed07/DTKS.git`).

---

## 1. Prerequisites

1. A Cloudflare account with `dreamtechkashmirsolutions.studio` added as a zone.
2. Node.js 20+ and `npm` installed locally.
3. Cloudflare Wrangler CLI authenticated:
   ```bash
   npx wrangler login
   ```

---

## 2. Create the Cloudflare D1 Database

Run the following command from the `/backend` directory:

```bash
cd backend
npx wrangler d1 create dtks-production-db
```

Copy the returned `database_id` from the terminal output and replace `"REPLACE_WITH_CLOUDFLARE_D1_DATABASE_ID"` in `backend/wrangler.toml` under both the default and `[env.production]` sections:

```toml
[[d1_databases]]
binding = "DB"
database_name = "dtks-production-db"
database_id = "<YOUR_D1_DATABASE_ID>"
migrations_dir = "migrations"
```

---

## 3. Apply D1 Database Migrations

Apply the non-destructive relational schema (`0001_initial_schema.sql` — 13 tables including `rate_limits`) and initial site settings migration (`0002_seed_data.sql`) to local and remote D1 databases:

```bash
# Local D1 verification
npx wrangler d1 migrations apply dtks-production-db --local

# Production D1 deployment
npx wrangler d1 migrations apply dtks-production-db --remote
```

> **Note:** Migrations and runtime catalog seeding exclusively use `INSERT OR IGNORE` and `CREATE TABLE IF NOT EXISTS` so existing production records are never overwritten or erased.

---

## 4. Create the Cloudflare R2 Bucket

Create the R2 bucket for storing portfolio project images and uploaded assets:

```bash
npx wrangler r2 bucket create dtks-portfolio-assets
```

Verify the binding in `backend/wrangler.toml`:

```toml
[[r2_buckets]]
binding = "ASSETS_BUCKET"
bucket_name = "dtks-portfolio-assets"
```

---

## 5. Configure Production Secrets

Never commit secrets to `wrangler.toml` or Git. Configure all required production secrets using `wrangler secret put`:

```bash
# Required: 256-bit random secret (minimum 32 characters) for signing HMAC-SHA256 JWT tokens
npx wrangler secret put JWT_SECRET --env production

# Required for initial admin bootstrap (used only when the `admins` table is empty)
npx wrangler secret put INITIAL_ADMIN_EMAIL --env production
npx wrangler secret put INITIAL_ADMIN_PASSWORD --env production

# Optional: Initial administrator display name
npx wrangler secret put INITIAL_ADMIN_NAME --env production

# Optional: Transactional email API key (Resend) for live email delivery
npx wrangler secret put RESEND_API_KEY --env production
```

> **Security Policy:** The backend never creates a default administrator with a fallback password. If `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD` (minimum 10 characters) are not explicitly provided, no administrator account is created automatically. Once the first administrator exists in `admins`, initial admin bootstrap is a no-op.

---

## 6. Deploy the Backend Worker

From `/backend`, deploy the Worker to Cloudflare production:

```bash
cd backend
npx wrangler deploy --env production
```

### Safe Worker Route Configuration (Preserving the Frontend)
In `backend/wrangler.toml`, routes are scoped strictly to the API subdomain and `/api/v1/*` path so the Worker **never** intercepts or overrides the separate frontend website hosted at `https://dreamtechkashmirsolutions.studio/`:

- `api.dreamtechkashmirsolutions.studio/*`
- `dreamtechkashmirsolutions.studio/api/v1/*`
- `www.dreamtechkashmirsolutions.studio/api/v1/*`

---

## 7. Connecting the Separate DTKS Frontend (`https://github.com/shahnaveed07/DTKS.git`)

The DTKS frontend lives in its own repository (`https://github.com/shahnaveed07/DTKS.git`) and communicates with this backend exclusively via REST API calls.

### 7.1 Frontend Environment Variable Configuration
In the frontend repository (`DTKS`), configure the API base URL in `.env.production` (or in your Cloudflare Pages environment variables):

```env
# Option A: Using the dedicated API subdomain
VITE_API_BASE_URL=https://api.dreamtechkashmirsolutions.studio/api/v1

# Option B: Using the same-origin /api/v1/* Worker route
VITE_API_BASE_URL=https://dreamtechkashmirsolutions.studio/api/v1
```

### 7.2 Cross-Origin Resource Sharing (CORS)
`DTKS_BE` automatically permits requests from:
- `https://dreamtechkashmirsolutions.studio`
- `https://www.dreamtechkashmirsolutions.studio`
- Any additional origins listed in `CORS_ALLOWED_ORIGINS` (comma-separated) in `backend/wrangler.toml`.

### 7.3 Frontend API Consumption Flows
1. **Initial Website Bootstrap (`GET /api/v1/bootstrap`)**: Fetches active services, packages, published portfolio items, and public site settings in a single request.
2. **Customer Quote / Order Submission (`POST /api/v1/orders`)**: Creates or updates the customer record, generates a unique `DKS-YYYY-XXXX` order reference, stores line items and initial status history (`Pending`), and sends transactional email notifications via Resend.
3. **Public Order Tracker (`GET /api/v1/orders/track?ref=DKS-YYYY-XXXX&email=...`)**: Returns real-time order progress and status transition history.
4. **Contact & Consultation Form (`POST /api/v1/contact`)**: Validates and sanitizes customer inquiries, applies distributed rate limiting and honeypot checks, and records the inquiry in D1.
5. **Admin Portal Authentication (`POST /api/v1/auth/login`, `/refresh`, `/logout`, `/me`, `/change-password`)**: Authenticates via `Authorization: Bearer <accessToken>` (or `HttpOnly` cookies + `X-CSRF-Token`), rotates refresh tokens in `refresh_sessions`, and enforces role-based access control (`super_admin`, `admin`, `editor`).

---

## 8. Post-Deployment Verification Checklist

1. **Health Check**:
   ```bash
   curl -i https://api.dreamtechkashmirsolutions.studio/api/v1/health
   ```
2. **Public Bootstrap**:
   ```bash
   curl -s https://api.dreamtechkashmirsolutions.studio/api/v1/bootstrap | jq .success
   ```
3. **Admin Authentication**:
   ```bash
   curl -X POST https://api.dreamtechkashmirsolutions.studio/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"<YOUR_INITIAL_ADMIN_EMAIL>","password":"<YOUR_INITIAL_ADMIN_PASSWORD>"}'
   ```
4. **Automated Backend Test Suite**:
   ```bash
   npm test
   ```

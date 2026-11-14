# DTKS Production Deployment Guide (Cloudflare Workers + D1 + R2)

This guide covers deploying the **DreamTech Kashmir Solutions (DTKS)** backend and frontend to production on Cloudflare (`https://dreamtechkashmirsolutions.studio/`).

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

Copy the returned `database_id` from the terminal output and paste it into `backend/wrangler.toml`:

```toml
[[d1_databases]]
binding = "DB"
database_name = "dtks-production-db"
database_id = "<YOUR_D1_DATABASE_ID>"
migrations_dir = "migrations"
```

---

## 3. Apply D1 Database Migrations

Apply the schema and initial data migrations to both local and remote D1 databases:

```bash
# Local D1 verification
npx wrangler d1 migrations apply dtks-production-db --local

# Production D1 deployment
npx wrangler d1 migrations apply dtks-production-db --remote
```

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

Never commit secrets to `wrangler.toml` or Git. Set your production secrets using `wrangler secret put`:

```bash
# Required: 256-bit random secret for signing JWT access tokens
npx wrangler secret put JWT_SECRET

# Required: Initial administrator credentials (used only on first database bootstrap)
npx wrangler secret put INITIAL_ADMIN_EMAIL
npx wrangler secret put INITIAL_ADMIN_PASSWORD

# Optional: Transactional email API key (Resend) for live email delivery
npx wrangler secret put RESEND_API_KEY
```

---

## 6. Deploy the Backend Worker

From `/backend`, deploy the Worker to Cloudflare:

```bash
npx wrangler deploy
```

### Custom Route / Domain Binding
To serve the API directly under `https://dreamtechkashmirsolutions.studio/api/v1/*` and `/api/v1/assets/*`, add a route in the Cloudflare Dashboard (**Workers & Pages → dtks-backend-api → Settings → Domains & Routes**):
- **Route**: `dreamtechkashmirsolutions.studio/api/*`
- **Zone**: `dreamtechkashmirsolutions.studio`

Alternatively, if hosting the Worker on a subdomain (`https://api.dreamtechkashmirsolutions.studio`), set `VITE_API_BASE_URL=https://api.dreamtechkashmirsolutions.studio/api/v1` when building the frontend.

---

## 7. Build & Deploy the Frontend

From the repository root:

```bash
npm install
npm run build
```

This runs:
1. `vite build` (outputs optimized bundle to `dist/`)
2. `node scripts/prerender-seo.mjs` (prerenders all public routes with structured data & OpenGraph metadata)
3. `node scripts/validate-sitemap.mjs` (validates `dist/sitemap.xml` and `dist/robots.txt`)

Deploy the `dist/` directory to Cloudflare Pages:

```bash
npx wrangler pages deploy dist --project-name dtks-website
```

---

## 8. Post-Deployment Verification Checklist

1. **Health Check**:
   ```bash
   curl -i https://dreamtechkashmirsolutions.studio/api/v1/health
   ```
2. **Public Bootstrap**:
   ```bash
   curl -s https://dreamtechkashmirsolutions.studio/api/v1/bootstrap | jq .success
   ```
3. **Admin Login**:
   - Visit `https://dreamtechkashmirsolutions.studio/admin/login`
   - Sign in with your configured admin email and password
   - Immediately rotate the password under **Admin → Settings → Admin Profile & Security**
4. **Order & Inquiry Flow**:
   - Submit a test order on `/request-quote` and verify it appears in **Admin → Website Orders** and `/track-order`
   - Submit a test message on `/contact` and verify it appears in **Admin → Inquiries**

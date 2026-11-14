# DTKS – DreamTech Kashmir Solutions Backend

**Production Website:** `https://dreamtechkashmirsolutions.studio/`  
**Architecture:** Cloudflare Workers (JavaScript ES Modules) + Cloudflare D1 (SQLite) + Cloudflare R2 Object Storage

This directory (`/backend`) contains the standalone, production-ready REST API backend for **DreamTech Kashmir Solutions (DTKS)**. It is 100% independently deployable to Cloudflare Workers without requiring any frontend build.

---

## 1. Directory Structure

```text
backend/
├── src/
│   ├── index.js                 # Cloudflare Worker fetch entry point
│   ├── routes/
│   │   └── router.js            # REST API router (/api/v1/*)
│   ├── controllers/
│   │   ├── authController.js    # Login, logout, token refresh, profile, password change
│   │   ├── servicesController.js# Services CRUD & public catalog
│   │   ├── packagesController.js# Packages CRUD, service filtering, add-ons & maintenance
│   │   ├── portfolioController.js# Portfolio CRUD, pagination, ordering, R2 image uploads
│   │   ├── ordersController.js  # Customer order creation, tracking, admin status & history
│   │   ├── contactController.js # Contact form submission, spam filtering, admin search & notes
│   │   ├── dashboardController.js# Real-time D1 dashboard stats, recent items & analytics
│   │   └── settingsController.js# Public & admin site settings (with secret stripping)
│   ├── services/
│   │   ├── auditService.js      # Admin activity logging (activity_logs table)
│   │   ├── emailService.js      # Transactional email notifications (Resend API + audit log)
│   │   └── storageService.js    # Cloudflare R2 object upload, serving & deletion
│   ├── middleware/
│   │   ├── authMiddleware.js    # JWT verification, RBAC, is_active check, CSRF validation
│   │   ├── rateLimiter.js       # Sliding-window IP rate limiter (login, forms, general API)
│   │   ├── securityHeaders.js   # CORS origin enforcement & HTTP security headers
│   │   └── errorHandler.js      # Standardized error handling without internal stack leaks
│   ├── database/
│   │   ├── d1Adapter.js         # Node.js SQLite + filesystem R2 adapter for local dev/testing
│   │   └── seed.js              # Self-contained idempotent database seeder
│   ├── validators/
│   │   └── schemas.js           # Request payload validation, XSS sanitization & magic-byte checks
│   ├── utils/
│   │   ├── crypto.js            # Web Crypto PBKDF2-SHA256 hashing, HMAC-SHA256 JWT, SHA-256
│   │   └── response.js          # Standardized JSON response & body size enforcement
│   └── config/
│       ├── constants.js         # Allowed statuses, roles, MIME types & size limits
│       └── cors.js              # Allowed origin validation
├── migrations/
│   ├── 0001_initial_schema.sql  # 12 relational D1 tables, foreign keys, CHECK constraints & indexes
│   └── 0002_seed_data.sql       # Initial site settings seed migration
├── tests/
│   └── backend.test.js          # 20 automated integration & security test scenarios
├── docs/
│   ├── API_DOCUMENTATION.md     # Complete REST API reference documentation
│   ├── openapi.yaml             # OpenAPI 3.0.3 specification
│   └── dtks-postman-collection.json # Postman Collection v2.1
├── wrangler.toml                # Cloudflare Workers, D1, and R2 configuration
├── .dev.vars.example            # Example environment variables & secrets
└── package.json                 # Standalone backend scripts & metadata
```

---

## 2. Relational Database Schema (Cloudflare D1)

Defined in `migrations/0001_initial_schema.sql` with 12 tables, foreign keys, `CHECK` constraints, and indexes:

1. `admins` – Administrator accounts (`id`, `name`, `email`, `password_hash`, `role`, `is_active`, `created_at`, `updated_at`, `last_login_at`)
2. `refresh_sessions` – Hashed refresh token sessions (`id`, `admin_id`, `refresh_token_hash`, `user_agent`, `ip_address`, `expires_at`, `revoked_at`, `created_at`)
3. `customers` – Customer records (`id`, `full_name`, `email`, `phone`, `city`, `business_name`, `created_at`, `updated_at`)
4. `services` – Website services (`id`, `title`, `slug`, `description`, `features`, `image`, `price`, `is_active`, `display_order`, `created_at`, `updated_at`, plus metadata columns)
5. `packages` – Service pricing packages (`id`, `name`, `description`, `price`, `features`, `service_id`, `is_active`, `display_order`, `created_at`, `updated_at`, plus scope columns)
6. `portfolio` – Website showcase items (`id`, `project_title`, `slug`, `description`, `category`, `thumbnail`, `images`, `project_url`, `is_published`, `display_order`, `created_at`, `updated_at`)
7. `orders` – Customer website orders (`id`, `order_number`, `customer_id`, `service_id`, `package_id`, `customer_name`, `customer_email`, `customer_phone`, `project_description`, `budget`, `status`, `admin_notes`, `created_at`, `updated_at`, plus scope & quotation columns)
8. `order_items` – Order line items (`id`, `order_id`, `item_type`, `title`, `description`, `quantity`, `unit_price`, `currency`, `created_at`)
9. `order_status_history` – Audit trail of order status transitions (`id`, `order_id`, `previous_status`, `new_status`, `changed_by_admin_id`, `notes`, `created_at`)
10. `contact_messages` – Customer inquiries (`id`, `name`, `email`, `phone`, `subject`, `message`, `status`, `admin_notes`, `created_at`, `updated_at`)
11. `site_settings` – Key-value JSON site configuration (`setting_key`, `setting_value`, `updated_at`, `updated_by_admin_id`)
12. `activity_logs` – Admin audit & email delivery logs (`id`, `admin_id`, `action`, `entity_type`, `entity_id`, `details`, `ip_address`, `timestamp`)

---

## 3. Local Development & Testing

### 3.1 Environment Variables
Copy `.dev.vars.example` to `.dev.vars` inside `backend/`:
```bash
cp backend/.dev.vars.example backend/.dev.vars
```

### 3.2 Run Automated Backend Test Suite (20 Scenarios)
From the repository root or `backend/` directory:
```bash
npm test
```

### 3.3 Run with Cloudflare Wrangler
```bash
cd backend
npx wrangler d1 migrations apply dtks-production-db --local
npx wrangler dev
```

---

## 4. Production Cloudflare Deployment

### Step 1: Create D1 Database & R2 Bucket
```bash
cd backend
npx wrangler d1 create dtks-production-db
npx wrangler r2 bucket create dtks-portfolio-assets
```
Update `database_id` in `backend/wrangler.toml` with the ID output by Wrangler.

### Step 2: Apply D1 Database Migrations
```bash
npx wrangler d1 migrations apply dtks-production-db --remote
```

### Step 3: Configure Production Secrets
```bash
npx wrangler secret put JWT_SECRET
npx wrangler secret put ADMIN_INITIAL_EMAIL
npx wrangler secret put ADMIN_INITIAL_PASSWORD
npx wrangler secret put RESEND_API_KEY
```

### Step 4: Deploy Worker
```bash
npx wrangler deploy --env production
```

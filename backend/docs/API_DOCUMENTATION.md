# DTKS Backend REST API Documentation

**Project:** DreamTech Kashmir Solutions (DTKS)  
**Production Website:** `https://dreamtechkashmirsolutions.studio/`  
**API Base Path:** `/api/v1`  
**Architecture:** Cloudflare Workers (ES Modules) + Cloudflare D1 (SQLite) + Cloudflare R2 Object Storage

---

## 1. Base URLs

| Environment | Base URL |
| :--- | :--- |
| **Production Custom API Domain** | `https://api.dreamtechkashmirsolutions.studio/api/v1` |
| **Production Worker Direct URL** | `https://dtks-be.snave9401.workers.dev/api/v1` |
| **Same-Origin Production Route** | `https://dreamtechkashmirsolutions.studio/api/v1` |
| **Local Cloudflare Worker (`wrangler dev`)** | `http://localhost:8787/api/v1` |
| **Local Integrated Dev Server** | `http://localhost:3000/api/v1` |

---

## 1.1 Health & Readiness Probes

| Method | Endpoint | Purpose | Success Status | Failure Status |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | **Liveness Check** — Verifies the Worker is running without touching D1, R2, seeding, or DB rate limiting | `200 OK` (`status: "healthy"`) | N/A |
| `GET` | `/api/v1/ready` | **Readiness Check** — Verifies D1 binding, D1 connection, all 17 schema tables, and R2 `ASSETS_BUCKET` binding | `200 OK` (`status: "ready"`, `database: "connected"`, `schema: "valid"`, `storage: "available"`) | `503 Service Unavailable` (`status: "not_ready"`) |


---

## 2. Standard Response Envelope & Error Format

### Success Response
```json
{
  "success": true,
  "message": "Operation completed successfully.",
  "data": {},
  "timestamp": "2026-11-14T08:00:00.000Z"
}
```

### Error Response
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Order validation failed.",
    "details": {
      "customerEmail": "A valid customer email address is required."
    }
  },
  "timestamp": "2026-11-14T08:00:00.000Z"
}
```

### HTTP Status Codes
- `200 OK` – Request succeeded.
- `201 Created` – Resource created (`POST /services`, `POST /packages`, `POST /portfolio`, `POST /orders`, `POST /contact`, `POST /portfolio/upload`, `POST /admin/accounts`, `POST /client/auth/register`).
- `204 No Content` – CORS `OPTIONS` preflight succeeded.
- `400 Bad Request` – Input validation failed (`VALIDATION_ERROR`, `INVALID_STATUS`, `INVALID_IMAGE_UPLOAD`, `INVALID_INVITE_TOKEN`, `INVITE_TOKEN_EXPIRED`, `INVITE_TOKEN_ALREADY_USED`, `INVALID_VERIFICATION_TOKEN`, `VERIFICATION_TOKEN_USED`, `VERIFICATION_TOKEN_EXPIRED`, `INVALID_RESET_TOKEN`, `RESET_TOKEN_USED`, `RESET_TOKEN_EXPIRED`).
- `401 Unauthorized` – Missing, invalid, revoked, or expired JWT access/refresh token (`UNAUTHORIZED`, `INVALID_CREDENTIALS`, `INVALID_REFRESH_TOKEN`, `SESSION_REVOKED`).
- `403 Forbidden` – Origin blocked by CORS policy (`CORS_ORIGIN_FORBIDDEN`), CSRF check failed (`CSRF_VALIDATION_FAILED`), email not verified (`EMAIL_NOT_VERIFIED`), pending admin invite (`INVITE_PENDING`), account deactivated (`ACCOUNT_DEACTIVATED`), or insufficient role permissions (`FORBIDDEN`).
- `404 Not Found` – Resource or endpoint not found (`NOT_FOUND`, `ORDER_NOT_FOUND`, `ASSET_NOT_FOUND`).
- `409 Conflict` – Duplicate registration or protected last active super admin (`ADMIN_EMAIL_EXISTS`, `REGISTRATION_CONFLICT`, `LAST_SUPER_ADMIN_PROTECTED`).
- `429 Too Many Requests` – Rate limit exceeded (`RATE_LIMIT_EXCEEDED`, includes `Retry-After` header).
- `500 Internal Server Error` – Unexpected server error (`INTERNAL_SERVER_ERROR`, internal stack traces are never leaked).
- `503 Service Unavailable` – Dependency or transactional email provider unavailable (`SERVICE_NOT_READY`, `EMAIL_PROVIDER_UNCONFIGURED`, `EMAIL_DELIVERY_FAILED`).

---

## 3. CORS Configuration & Security Headers

### Allowed Origins
- `https://dreamtechkashmirsolutions.studio`
- `https://www.dreamtechkashmirsolutions.studio`
- `http://localhost:3000` (development)
- `http://localhost:5173` (development)
- `http://localhost:8787` (development)

Requests with an unauthorized `Origin` header receive `403 Forbidden` (`CORS_ORIGIN_FORBIDDEN`).

### CORS Headers & Authentication Transport
CORS preflight (`OPTIONS`) permits:
- `Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token, X-Requested-With, Accept`
- `Access-Control-Expose-Headers: X-Request-Id, X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After`
- `Access-Control-Allow-Credentials: true` (for allowlisted origins)

Protected endpoints accept either:
1. **Bearer Token Header (Recommended for SPA):**
   ```http
   Authorization: Bearer <accessToken>
   ```
   *(If the frontend also attaches `X-CSRF-Token` on authenticated requests, CORS allows it cleanly.)*
2. **HttpOnly Cookie + CSRF Token Header:**
   - **Admin:** `Cookie: dtks_access_token=<accessToken>; dtks_csrf_token=<csrfToken>` + `X-CSRF-Token: <csrfToken>`
   - **Client:** `Cookie: dtks_client_access_token=<accessToken>; dtks_client_csrf_token=<csrfToken>` + `X-CSRF-Token: <csrfToken>`

> **Strict Token Isolation:** Admin JWTs (`accountType: "admin"`) are rejected by all `/api/v1/client/*` routes (`401`), and Client JWTs (`accountType: "client"`) are rejected by all Admin routes (`401`).

---

## 4. Endpoints Reference

### 4.1 Authentication (`/api/v1/auth`)

#### `POST /api/v1/auth/login`
Authenticates an active administrator, verifies the WebCrypto PBKDF2-HMAC-SHA512 (`$pbkdf2-sha512$v=1$i=100000$...`) password hash in constant time (transparently migrating legacy `$argon2id$` hashes on login), updates `last_login_at`, creates a hashed session in `refresh_sessions`, and returns a short-lived access token (`15m`) + refresh token (`7d`).

- **Rate Limit:** 10 requests / 15 minutes per IP (distributed across isolates via D1 `rate_limits`).
- **Request Body:**
  ```json
  {
    "email": "admin@dreamtechkashmirsolutions.studio",
    "password": "<YOUR_ADMIN_PASSWORD>"
  }
  ```
- **Response (`200 OK`):**
  ```json
  {
    "success": true,
    "message": "Authentication successful.",
    "data": {
      "accessToken": "eyJhbGciOiJIUzI1NiIs...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
      "csrfToken": "c9f1...",
      "expiresIn": 900,
      "admin": {
        "id": "adm-dtks-initial",
        "name": "DreamTech Kashmir Admin",
        "email": "admin@dreamtechkashmirsolutions.studio",
        "role": "super_admin",
        "is_active": true,
        "last_login_at": "2026-11-14T08:00:00.000Z"
      }
    }
  }
  ```

#### `POST /api/v1/auth/refresh`
Validates a refresh token against `refresh_sessions`, revokes the old session (`revoked_at`), and issues a new access token + rotated refresh token.
- **Request Body:** `{ "refreshToken": "<refreshToken>" }`

#### `POST /api/v1/auth/logout`
Revokes the active refresh session in `refresh_sessions` and clears auth cookies.

#### `GET /api/v1/auth/me`
- **Auth Required:** Yes (`BearerAuth` - Admin)
- **Response (`200 OK`):** Current administrator profile.

#### `PATCH /api/v1/auth/profile`
- **Auth Required:** Yes (`BearerAuth` - Admin)
- **Request Body:** `{ "name": "Updated Admin Name" }`
- **Security:** Rejects `role`, `isActive`, `email`, `id`, `password`, or `password_hash` with `400 VALIDATION_ERROR`.

#### `POST /api/v1/auth/change-password`
- **Auth Required:** Yes (`BearerAuth` - Admin)
- **Request Body:**
  ```json
  {
    "currentPassword": "OldPassword123!",
    "newPassword": "NewSecurePassword2026!",
    "confirmPassword": "NewSecurePassword2026!"
  }
  ```
- **Behavior:** Re-hashes password, increments `token_version` (invalidating active tokens), and revokes all prior refresh sessions in `refresh_sessions`.

#### `POST /api/v1/auth/accept-invite`
- **Auth Required:** Public (Rate-limited: 20 req / 15 min per IP)
- **Request Body:**
  ```json
  {
    "token": "<rawInviteToken>",
    "password": "StrongAdminPassword#2026",
    "confirmPassword": "StrongAdminPassword#2026"
  }
  ```
- **Behavior:** Validates single-use SHA-256-hashed invitation token (48h expiry), hashes strong password, sets `is_active = 1` and `invite_accepted_at`, marks token used, and logs `ADMIN_INVITE_ACCEPTED`.

---

### 4.1B Admin Account Management (`/api/v1/admin/accounts`)

| Method | Endpoint | Auth / Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/admin/accounts` | `super_admin`, `admin` | List admin accounts with `activeSessionCount` and `invitePending` (supports `?role=`, `?isActive=`, `?search=`) |
| `GET` | `/api/v1/admin/accounts/:id` | `super_admin`, `admin` | Inspect admin account, recent refresh sessions, and latest invitation metadata |
| `POST` | `/api/v1/admin/accounts` | `super_admin` only | Create pending admin account (`isActive: false`) and dispatch 48h invitation email via Resend |
| `POST` | `/api/v1/admin/accounts/:id/resend-invite` | `super_admin` only | Revoke prior unused invite tokens and resend fresh invitation email for pending admins |
| `PATCH` | `/api/v1/admin/accounts/:id` | `super_admin` only | Update `name` and/or `role` (`super_admin`, `admin`, `editor`). Role changes revoke all sessions & bump `token_version`. Protects last active `super_admin` (`409 LAST_SUPER_ADMIN_PROTECTED`) |
| `PATCH` | `/api/v1/admin/accounts/:id/status` | `super_admin` only | Activate (`{ "isActive": true }`) or deactivate (`{ "isActive": false }`) an account. Deactivation sets `deactivated_at`, bumps `token_version`, and revokes sessions. Protects last active `super_admin` |
| `DELETE` | `/api/v1/admin/accounts/:id/sessions` | `super_admin` only | Revoke all active refresh sessions and bump `token_version` so existing access tokens fail immediately (`401 SESSION_REVOKED`) |

---

### 4.1C Client Registration & Authentication (`/api/v1/client/auth`)

| Method | Endpoint | Auth | Rate Limit | Description |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/client/auth/register` | Public | 10 / 15m | Register client account (`fullName`, `email`, `phone`, `password`, `confirmPassword`, optional `city`, `businessName`), send 24h verification email (`503` if email provider unconfigured/fails) |
| `POST` | `/api/v1/client/auth/resend-verification` | Public | 15 / 15m | Resend verification link (`{ "email" }`); returns uniform `200 OK` when provider is configured to prevent email enumeration |
| `POST` | `/api/v1/client/auth/verify-email` | Public | 15 / 15m | Verify single-use SHA-256-hashed token (`{ "token" }`), activate email verification, and safely link existing `customers` + historical unlinked `orders` matching verified email |
| `POST` | `/api/v1/client/auth/login` | Public | 10 / 15m | Authenticate verified, active client; returns `accessToken`, rotated `refreshToken`, `csrfToken`, `expiresIn`, and `client` profile |
| `POST` | `/api/v1/client/auth/refresh` | Public | 30 / 15m | Rotate `customer_refresh_sessions` token and issue new access + refresh token pair |
| `POST` | `/api/v1/client/auth/logout` | Client or Refresh Token | General | Revoke current refresh token (or all sessions + bump `token_version` when authenticated without body token) |
| `GET` | `/api/v1/client/auth/me` | Client (`BearerAuth`) | General | Get current authenticated client profile |
| `PATCH` | `/api/v1/client/auth/profile` | Client (`BearerAuth`) | General | Update `fullName`, `phone`, `city`, `businessName` (synced to linked `customers` row; rejects `email`, `role`, `isActive`, etc.) |
| `POST` | `/api/v1/client/auth/change-password` | Client (`BearerAuth`) | General | Verify `currentPassword`, set strong `newPassword`, revoke all sessions, bump `token_version`, and send security notification email |
| `POST` | `/api/v1/client/auth/forgot-password` | Public | 8 / 15m | Issue 1h single-use SHA-256-hashed password reset token via Resend (`503` if unconfigured; otherwise uniform `200 OK`) |
| `POST` | `/api/v1/client/auth/reset-password` | Public | 8 / 15m | Consume single-use reset token (`token`, `password`, `confirmPassword`), revoke all sessions, bump `token_version`, and send security notification email |
| `POST` | `/api/v1/client/auth/deactivate` | Client (`BearerAuth`) | General | Confirm `password`, deactivate account (`isActive: false`), revoke all sessions, bump `token_version`, and send security alert email |

---

### 4.1D Client-Only Data Access (`/api/v1/client`)

All endpoints require a valid **Client** JWT (`authenticateClient`) and strictly scope records to `client.customerId`. Internal fields (`admin_notes`, `changed_by_admin_id`) are never returned.

| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/client/orders` | Client | List authenticated client's orders (supports `?status=` and `?search=`) |
| `GET` | `/api/v1/client/orders/:id` | Client | Get single client order by ID or `order_number`, including line items and sanitized `statusHistory` (`404` if not owned by client) |
| `GET` | `/api/v1/client/quotations` | Client | List client orders with quotations (`quotationAmount`, `quotationCurrency`, `quotationNotes`, `expectedDeliveryDate`, `expectedTimeline`, `customerUpdate`) |
| `GET` | `/api/v1/client/projects` | Client | List client active/completed project records (`Approved`, `InProgress`, `Development`, `Completed`, plus technical scope & `customerUpdate`) |

---

### 4.2 Services Management (`/api/v1/services`)

| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/services` | Public (Admin sees inactive with `?includeInactive=true`) | List website services ordered by `display_order ASC` |
| `GET` | `/api/v1/services/:slug` | Public | Get single service by `slug` or `id` |
| `POST` | `/api/v1/services` | Admin | Create a new website service |
| `PUT` | `/api/v1/services/:id` | Admin | Update an existing service |
| `DELETE` | `/api/v1/services/:id` | Admin | Delete a service |

- **Create/Update Request Body Example:**
  ```json
  {
    "title": "Custom Web Portals & Dashboards",
    "slug": "custom-web-portals-dashboards",
    "description": "End-to-end architecture and responsive development for custom web portals.",
    "features": ["Role-based access", "Fast search & reporting", "Responsive layout"],
    "image": "/assets/images/dtks-corporate-website-showcase.jpg",
    "price": 38000,
    "is_active": true,
    "display_order": 11
  }
  ```

---

### 4.3 Packages Management (`/api/v1/packages`)

| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/packages` | Public | List packages (supports `?service_id=`, `?category=`, `?includeInactive=true`) |
| `GET` | `/api/v1/packages/:id` | Public | Get package details by ID |
| `POST` | `/api/v1/packages` | Admin | Create a website package |
| `PUT` | `/api/v1/packages/:id` | Admin | Update a website package |
| `DELETE` | `/api/v1/packages/:id` | Admin | Delete a website package |

- **Create/Update Request Body Example:**
  ```json
  {
    "name": "Business Website Package",
    "service_id": "svc-business-websites",
    "category": "Business & Corporate Websites",
    "description": "Complete multi-page website for established companies.",
    "price": 16500,
    "features": ["Up to 10 Custom Pages", "Technical SEO Setup", "Lead Capture Forms"],
    "is_active": true,
    "display_order": 2
  }
  ```

---

### 4.4 Portfolio & Cloudflare R2 Uploads (`/api/v1/portfolio`)

| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/portfolio` | Public | List published portfolio items (supports `?category=`, `?page=1&limit=10`, `?includeUnpublished=true`) |
| `GET` | `/api/v1/portfolio/:slug` | Public | Get portfolio project by `slug` or `id` |
| `POST` | `/api/v1/portfolio` | Admin | Create portfolio project |
| `PUT` | `/api/v1/portfolio/:id` | Admin | Update portfolio project (replaces old R2 thumbnail if changed) |
| `DELETE` | `/api/v1/portfolio/:id` | Admin | Delete portfolio project and clean up R2 images |
| `POST` | `/api/v1/portfolio/upload` | Admin | Upload JPEG/PNG/WebP image (max 5MB, magic-byte verified) to R2 |
| `DELETE` | `/api/v1/portfolio/upload` | Admin | Delete image from R2 by `{ "key": "portfolio/..." }` or `/portfolio/upload/:key` |

---

### 4.5 Website Order Management (`/api/v1/orders`)

| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/orders` | Public (Rate-limited) | Submit website order request; creates/updates customer, generates `DKS-YYYY-XXXX`, sets status `Pending` |
| `GET` | `/api/v1/orders/track` | Public | Track order by `?ref=DKS-2026-0001&email=customer@example.com` |
| `GET` | `/api/v1/orders` | Admin | List orders (supports `?status=`, `?service=`, `?search=`) |
| `GET` | `/api/v1/orders/:id` | Admin | Get full order details, line items, and status history |
| `PATCH` | `/api/v1/orders/:id/status` | Admin | Update order status (`Pending`, `Reviewed`, `Approved`, `InProgress`, `Completed`, `Rejected`, `Cancelled`) |
| `PATCH` | `/api/v1/orders/:id` | Admin | Update order status, quotation amount, timeline, and admin notes |
| `DELETE` | `/api/v1/orders/:id` | Admin | Delete an order |

- **Public Order Submission (`POST /api/v1/orders`) Example:**
  ```json
  {
    "service_id": "svc-ecommerce-websites",
    "package_id": "pkg-ecommerce-store",
    "customer_name": "Tariq Ahmad",
    "customer_email": "tariq.ahmad@example.com",
    "customer_phone": "+91 97971 23456",
    "project_name": "Kashmir Pashmina Online Storefront",
    "project_description": "Direct-to-consumer storefront for authentic Kashmiri Pashmina shawls with catalog filters.",
    "budget": "₹30,000 – ₹60,000"
  }
  ```

---

### 4.6 Contact & Inquiry Management (`/api/v1/contact`)

| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/contact` | Public (Rate-limited) | Submit contact message (validates fields, sanitizes XSS, checks honeypot) |
| `GET` | `/api/v1/contact` | Admin | List & search contact messages (`?status=`, `?search=`) |
| `GET` | `/api/v1/contact/:id` | Admin | View single contact message |
| `PATCH` | `/api/v1/contact/:id` | Admin | Update message status (`New`, `In Review`, `Replied`, `Archived`) and `admin_notes` |
| `DELETE` | `/api/v1/contact/:id` | Admin | Delete contact message |

---

### 4.7 Admin Dashboard & Analytics (`/api/v1/admin/dashboard/*`)

| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/admin/dashboard/stats` | Admin | Real-time counts from D1 (`totalOrders`, `pendingOrders`, `completedOrders`, `totalCustomers`, `totalContactMessages`, `activeServices`, `activePackages`, `totalPortfolioItems`) |
| `GET` | `/api/v1/admin/dashboard/recent-orders` | Admin | Latest orders (`?limit=5`) |
| `GET` | `/api/v1/admin/dashboard/recent-messages` | Admin | Latest contact inquiries (`?limit=5`) |
| `GET` | `/api/v1/admin/dashboard/order-analytics` | Admin | Aggregated order counts & quoted values grouped by status, service, hosting preference, and month |

---

### 4.8 Site Settings (`/api/v1/settings`)

| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/settings` | Public | Returns public site settings (company name, email, phone, social links, business hours, hero content, SEO metadata) with sensitive keys stripped |
| `PUT` | `/api/v1/settings` | Admin (`super_admin`, `admin`) | Updates site settings in `site_settings` and logs admin activity |

---

### 4.9 Admin Activity Logs (`/api/v1/admin/activity-logs`)

| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/admin/activity-logs` | Admin (`super_admin`, `admin`) | Returns audit trail of admin actions, logins, password hash migrations, and transactional email delivery logs (`?limit=50`) |

---

## 5. Role-Based Access Control (RBAC)

| Actor / Role | Permitted Actions | Restricted Actions |
| :--- | :--- | :--- |
| `super_admin` | Full access to all admin & workspace endpoints **plus** `/api/v1/admin/accounts` creation (invite), role changes, activation/deactivation, resend invites, and session revocation | Cannot demote or deactivate the last active `super_admin` (`409 LAST_SUPER_ADMIN_PROTECTED`); cannot access `/api/v1/client/*` (`401`) |
| `admin` | Full workspace access (`DELETE`, `PUT /settings`, package configs, activity logs, notifications) and **read-only** `GET /api/v1/admin/accounts` & `GET /api/v1/admin/accounts/:id` | Cannot create admins (`POST /admin/accounts`), edit roles/statuses (`PATCH`), resend invites, or revoke sessions (`403 FORBIDDEN`); cannot access `/api/v1/client/*` (`401`) |
| `editor` | Create and update services, packages, portfolio items, R2 uploads, order status/quotations, and contact inquiry statuses | Cannot `DELETE` services, packages, portfolio items, R2 objects, orders, or inquiries; cannot `PUT /api/v1/settings` or `PUT /api/v1/packages/config/*`; cannot view `/api/v1/admin/activity-logs`, `/api/v1/admin/notifications`, or `/api/v1/admin/accounts*` (`403 FORBIDDEN`) |
| `client` | Self-service `/api/v1/client/auth/*` (profile, change-password, deactivate, refresh, logout) and client-scoped `/api/v1/client/orders*`, `/quotations`, `/projects`, plus authenticated `POST /api/v1/orders` | Completely isolated from all Admin endpoints (`/api/v1/auth/*`, `/api/v1/admin/*`, admin mutations on services/packages/portfolio/orders/contact/settings -> `401`); cannot access another client's orders (`404`) |

---

## 6. How the Separate Frontend (`DTKS`) Consumes the API

The standalone frontend repository (`https://github.com/shahnaveed07/DTKS.git`) connects to this backend by setting:

```env
VITE_API_BASE_URL=https://api.dreamtechkashmirsolutions.studio/api/v1
```
(or `https://dreamtechkashmirsolutions.studio/api/v1` when using the same-origin Cloudflare Worker route).

- **Public Pages** (`Home`, `Services`, `Packages`, `Portfolio`, `Order Form`, `Track Order`, `Contact`) call `GET /api/v1/bootstrap` (or individual `GET /services`, `GET /packages`, `GET /portfolio`, `GET /settings`), `POST /api/v1/orders`, `GET /api/v1/orders/track`, and `POST /api/v1/contact`.
- **Admin Dashboard & Management Screens** authenticate via `POST /api/v1/auth/login`, attach `Authorization: Bearer <accessToken>` on protected requests, automatically refresh short-lived access tokens via `POST /api/v1/auth/refresh`, and manage services, packages, portfolio items (with `multipart/form-data` R2 image uploads to `POST /api/v1/portfolio/upload`), customer orders, inquiries, and site settings.


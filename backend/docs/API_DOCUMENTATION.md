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
| **Same-Origin Production Route** | `https://dreamtechkashmirsolutions.studio/api/v1` *(and `https://www.dreamtechkashmirsolutions.studio/api/v1`)* |
| **Production `workers.dev` Subdomain** | Disabled (`workers_dev = false` in `backend/wrangler.toml`) |
| **Local Cloudflare Worker (`wrangler dev`)** | `http://localhost:8787/api/v1` |
| **Local Integrated Dev Server** | `http://localhost:3000/api/v1` |

---

## 1.1 Health & Readiness Probes

| Method | Endpoint | Purpose | Success Status | Failure Status |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | **Liveness Check** — Verifies the Worker is running without touching D1, R2, seeding, or DB rate limiting | `200 OK` (`status: "healthy"`) | N/A |
| `GET` | `/api/v1/ready` | **Readiness Check** — Verifies D1 binding, D1 connection, all 19 schema tables, and R2 `ASSETS_BUCKET` binding | `200 OK` (`status: "ready"`, `database: "connected"`, `schema: "valid"`, `storage: "available"`) | `503 Service Unavailable` (`status: "not_ready"`) |

---

## 2. Standard Response Envelope & Error Format

### Success Response
```json
{
  "success": true,
  "message": "Operation completed successfully.",
  "data": {},
  "timestamp": "2026-11-16T08:00:00.000Z"
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
  "timestamp": "2026-11-16T08:00:00.000Z"
}
```

### HTTP Status Codes
- `200 OK` – Request succeeded.
- `201 Created` – Resource created (`POST /services`, `POST /packages`, `POST /portfolio`, `POST /orders`, `POST /contact`, `POST /portfolio/upload`, `POST /admin/accounts`, `POST /client/auth/register`).
- `204 No Content` – CORS `OPTIONS` preflight succeeded.
- `400 Bad Request` – Input validation failed (`VALIDATION_ERROR`, `MISSING_REFRESH_TOKEN`, `INVALID_STATUS`, `INVALID_IMAGE_UPLOAD`, `INVALID_ASSET_KEY`, `INVALID_INVITE_TOKEN`, `INVITE_TOKEN_EXPIRED`, `INVITE_TOKEN_ALREADY_USED`, `INVALID_VERIFICATION_TOKEN`, `VERIFICATION_TOKEN_USED`, `VERIFICATION_TOKEN_EXPIRED`, `INVALID_RESET_TOKEN`, `RESET_TOKEN_USED`, `RESET_TOKEN_EXPIRED`).
- `401 Unauthorized` – Missing, invalid, revoked, replayed, mismatched-type, or expired JWT access/refresh token (`UNAUTHORIZED`, `TOKEN_EXPIRED`, `INVALID_TOKEN`, `INVALID_TOKEN_TYPE`, `INVALID_CREDENTIALS`, `INVALID_REFRESH_TOKEN`, `REFRESH_TOKEN_EXPIRED`, `REFRESH_TOKEN_REPLAY_DETECTED`, `SESSION_REVOKED`).
- `403 Forbidden` – Plaintext HTTP blocked in production (`HTTPS_REQUIRED`), origin blocked by CORS policy (`CORS_ORIGIN_FORBIDDEN`), CSRF check failed (`CSRF_VALIDATION_FAILED`), email not verified (`EMAIL_NOT_VERIFIED`), pending admin invite (`INVITE_PENDING`), account deactivated (`ACCOUNT_DEACTIVATED`), or insufficient role permissions (`FORBIDDEN`).
- `404 Not Found` – Resource or endpoint not found (`NOT_FOUND`, `ORDER_NOT_FOUND`, `ASSET_NOT_FOUND`).
- `409 Conflict` – Duplicate registration or protected last active super admin (`ADMIN_EMAIL_EXISTS`, `REGISTRATION_CONFLICT`, `LAST_SUPER_ADMIN_PROTECTED`).
- `410 Gone` – Deprecated legacy GET order tracking endpoint (`LEGACY_TRACKING_DISABLED`).
- `413 Payload Too Large` – Oversized R2 upload payload (`PAYLOAD_TOO_LARGE`).
- `429 Too Many Requests` – Rate limit exceeded (`RATE_LIMIT_EXCEEDED`, includes `Retry-After` header).
- `500 Internal Server Error` – Unexpected server error (`INTERNAL_SERVER_ERROR`, internal stack traces are never leaked).
- `502 Bad Gateway` – Upstream R2 storage failure (`R2_STORAGE_ERROR`).
- `503 Service Unavailable` – Dependency, distributed rate limiter (`RATE_LIMITER_UNAVAILABLE`), or transactional email provider unavailable (`SERVICE_NOT_READY`, `EMAIL_PROVIDER_UNCONFIGURED`, `EMAIL_DELIVERY_FAILED`).

---

## 3. Transport Security, CORS, Cookies, CSRF & HTTP Security Headers

### HTTPS Enforcement & Security Headers
- In `ENVIRONMENT === 'production'`, plaintext `http://` requests to `/api/v1/auth/*`, `/api/v1/client/*`, `/api/v1/admin/*`, and `/api/v1/orders/track*` (`/orders/track` and `/orders/track/resend`) are rejected with `403 HTTPS_REQUIRED` (honoring `X-Forwarded-Proto`).
- API JSON responses include:
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cross-Origin-Resource-Policy: same-site` *(overridden to `cross-origin` on R2 image streams)*
  - `Cache-Control: no-store` *(overridden to `public, max-age=31536000, immutable` on immutable R2 image streams)*
  - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains` *(production HTTPS)*

### Allowed Origins (CORS)
- **Production (`ENVIRONMENT=production`)**:
  - Strictly `https://dreamtechkashmirsolutions.studio`, `https://www.dreamtechkashmirsolutions.studio`, and any explicit production domains in `CORS_ALLOWED_ORIGINS`. Localhost, loopback IPs, and `*.run.app` origins are unconditionally rejected (`ALLOW_LOCAL_CORS` cannot override production).
- **Development (`ENVIRONMENT=development`)**:
  - Production origins plus `http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:5173`, `http://127.0.0.1:5173`, `http://localhost:8787`, and `https://*.run.app`.

CORS preflight (`OPTIONS`) permits:
- `Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token, X-Auth-Mode, X-Requested-With, Accept`
- `Access-Control-Expose-Headers: X-Request-Id, X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After`
- `Access-Control-Allow-Credentials: true` (for allowlisted origins)

### Cookie-First Authentication & Bearer Opt-In
1. **Default Cookie Mode (`authMode: "cookie"`) — Recommended for Browser SPAs (`DTKS`):**
   - `POST /auth/login`, `POST /auth/refresh`, `POST /client/auth/login`, and `POST /client/auth/refresh` omit `accessToken` and `refreshToken` from the JSON response body and issue host-only `HttpOnly; SameSite=Lax; Secure` cookies:
     - **Admin:** `dtks_access` (`Path=/api/v1`), `dtks_refresh` (`Path=/api/v1/auth`), `dtks_csrf` (`Path=/api/v1`)
     - **Client:** `dtks_client_access` (`Path=/api/v1`), `dtks_client_refresh` (`Path=/api/v1/client/auth`), `dtks_client_csrf` (`Path=/api/v1`)
   - Call `GET /api/v1/auth/csrf` or `GET /api/v1/client/auth/csrf` before mutating cookie requests (or use the `csrfToken` returned in `/login` and `/refresh` JSON).
   - Send `credentials: 'include'` and header `X-CSRF-Token: <csrfToken>` on **all** cookie-authenticated `POST`, `PUT`, `PATCH`, and `DELETE` requests (including `/logout`, `/refresh`, and cookie-authenticated `POST /api/v1/orders`). Missing/mismatched tokens return `403 CSRF_VALIDATION_FAILED`.
2. **Bearer Opt-In Mode (`X-Auth-Mode: bearer`) — For CLI, Mobile & Automated API Clients:**
   - Send header `X-Auth-Mode: bearer` on `/login` and `/refresh` to receive `accessToken` and `refreshToken` in JSON and authenticate subsequent calls with `Authorization: Bearer <accessToken>`.

> **Strict Token Isolation:** Admin JWTs (`accountType: "admin"`) are rejected by all `/api/v1/client/*` routes (`401`), and Client JWTs (`accountType: "client"`) are rejected by all Admin routes (`401`).

> **Refresh Replay Detection:** Reusing an already rotated refresh token (`revoke_reason = 'rotated'`) immediately revokes **all** refresh sessions and increments `token_version` (`401 REFRESH_TOKEN_REPLAY_DETECTED`), while single-device logout (`revoke_reason = 'logout'`) preserves sibling device sessions.

---

## 4. Endpoints Reference

### 4.1 Authentication (`/api/v1/auth`)

#### `GET /api/v1/auth/csrf`
Issues a host-only `HttpOnly` `dtks_csrf` cookie (`Path=/api/v1`) and returns `{ csrfToken }` for double-submit CSRF protection.

#### `POST /api/v1/auth/login`
Authenticates an active administrator, verifies the WebCrypto PBKDF2-HMAC-SHA512 (`$pbkdf2-sha512$v=1$i=100000$...`) password hash in constant time (transparently migrating legacy `$argon2id$` hashes on login), updates `last_login_at`, creates a hashed session in `refresh_sessions`, and sets HttpOnly auth cookies (or returns `accessToken`/`refreshToken` JSON when `X-Auth-Mode: bearer` is sent).

- **Rate Limit:** 10 requests / 15 minutes per IP (fail-closed in production via D1 `rate_limits`).

#### `POST /api/v1/auth/refresh`
Validates a refresh token (cookie or JSON body when `X-Auth-Mode: bearer`), revokes the old session (`revoke_reason = 'rotated'`), and issues rotated tokens. Enforces `X-CSRF-Token` for cookie-mode requests and triggers full session cascade revocation (`401 REFRESH_TOKEN_REPLAY_DETECTED`) if a rotated token is replayed.

#### `POST /api/v1/auth/logout`
Enforces `X-CSRF-Token` when cookie-authenticated. Revokes a single session (`revoke_reason = 'logout'`, `scope: "single_device"`) or all active sessions + increments `token_version` (`allDevices: true` with authenticated admin session, `scope: "all_devices"`), and clears admin cookies (`Max-Age=0`).

#### `GET /api/v1/auth/me`
- **Auth Required:** Yes (Admin cookie or `BearerAuth`)
- **Response (`200 OK`):** Current administrator profile.

#### `PATCH /api/v1/auth/profile`
- **Auth Required:** Yes (Admin cookie + CSRF or `BearerAuth`)
- **Request Body:** `{ "name": "Updated Admin Name" }`
- **Security:** Rejects `role`, `isActive`, `email`, `id`, `password`, or `password_hash` with `400 VALIDATION_ERROR`.

#### `POST /api/v1/auth/change-password`
- **Auth Required:** Yes (Admin cookie + CSRF or `BearerAuth`)
- **Password Policy:** Minimum `12` characters (max `128`), mixed case, digit, symbol, weak-denylist checked.
- **Behavior:** Re-hashes password, increments `token_version`, revokes all `refresh_sessions`, and clears cookies.

#### `POST /api/v1/auth/accept-invite`
- **Auth Required:** Public (Rate-limited: 20 req / 15 min per IP, fail-closed in prod)
- **Delivery Format:** Invitation email directs to `${APP_URL}/admin/accept-invite#token=<rawInviteToken>`.
- **Behavior:** Validates single-use SHA-256-hashed invitation token (48h expiry), hashes strong `>=12`-char password, activates account, atomically marks token used (`julianday` check), and logs `ADMIN_INVITE_ACCEPTED`.

#### `POST /api/v1/auth/forgot-password`
- **Auth Required:** Public (Layered IP `8/15m` + HMAC email `5/15m` rate limits; fail-closed in prod)
- **Delivery Format:** `${APP_URL}/admin/reset-password#token=<rawToken>`
- **Response (`200 OK`):** Uniform `{ requested: true }` confirmation (no enumeration across nonexistent, inactive, pending-invite, or failed-delivery states; `503 EMAIL_PROVIDER_UNCONFIGURED` if Resend is unconfigured).

#### `POST /api/v1/auth/reset-password`
- **Auth Required:** Public (Layered IP `8/15m` + HMAC token `8/15m` rate limits; fail-closed in prod)
- **Behavior:** Enforces `12+` char password policy, atomically claims single-use token (`julianday(expires_at) > julianday(?)`), bumps `token_version`, revokes all `refresh_sessions`, and sends a non-blocking security alert email.

---

### 4.1B Admin Account Management (`/api/v1/admin/accounts`)

| Method | Endpoint | Auth / Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/admin/accounts` | `super_admin`, `admin` | List admin accounts with filters (`?search=`, `?role=`, `?status=`, `?isActive=`, `?page=`, `?limit=`) |
| `GET` | `/api/v1/admin/accounts/:id` | `super_admin`, `admin` | Inspect admin account, recent refresh sessions, and latest invitation metadata |
| `POST` | `/api/v1/admin/accounts` | `super_admin` only | Create pending admin account (`isActive: false`) and dispatch 48h `#token=` invitation email via Resend |
| `POST` | `/api/v1/admin/accounts/:id/resend-invite` | `super_admin` only | Revoke prior unused invite tokens and resend fresh `#token=` invitation email |
| `PATCH` / `PUT` | `/api/v1/admin/accounts/:id` | `super_admin` only | Update `name` and/or `role` (protects last active `super_admin`) |
| `PATCH` / `PUT` | `/api/v1/admin/accounts/:id/status` | `super_admin` only | Activate or deactivate an account (protects last active `super_admin`) |
| `DELETE` | `/api/v1/admin/accounts/:id/sessions` | `super_admin` only | Revoke all active refresh sessions and bump `token_version` |

---

### 4.1C Client Registration & Authentication (`/api/v1/client/auth`)

| Method | Endpoint | Auth | Rate Limit (Fail-Closed in Prod) | Description |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/client/auth/csrf` | Public | General | Issues host-only `HttpOnly` `dtks_client_csrf` cookie + `{ csrfToken }` |
| `POST` | `/api/v1/client/auth/register` | Public | `10 / 15m` IP + `5 / 15m` HMAC email | Register client (`>=12`-char strong password, legal consent), send 24h `#token=` verification email |
| `POST` | `/api/v1/client/auth/resend-verification` | Public | `6 / 15m` IP + `4 / 15m` HMAC email | Uniform `200 OK` `{ requested: true }` anti-enumeration; targeted token revocation preserves prior unused token on delivery failure |
| `POST` | `/api/v1/client/auth/verify-email` | Public | `15 / 15m` IP + `10 / 15m` HMAC token | Atomic single-use claim (`julianday`), verifies email, safely links existing `customers` + historical pre-registration `orders` (`orders.created_at <= account.created_at`) |
| `POST` | `/api/v1/client/auth/login` | Public | `10 / 15m` IP | Sets `HttpOnly` cookies (`authMode: "cookie"`) or returns JSON tokens with `X-Auth-Mode: bearer` |
| `POST` | `/api/v1/client/auth/refresh` | Public / CSRF | `30 / 15m` IP | Cookie + `X-CSRF-Token` or `X-Auth-Mode: bearer`; rotated-token reuse triggers cascade revocation (`REFRESH_TOKEN_REPLAY_DETECTED`) |
| `POST` | `/api/v1/client/auth/logout` | Client + CSRF | General | Single-device (`revoke_reason = 'logout'`) or `allDevices: true` revocation; clears client cookies |
| `GET` | `/api/v1/client/auth/me` | Client | General | Get current authenticated client profile |
| `PATCH` | `/api/v1/client/auth/profile` | Client + CSRF | General | Update `fullName`, `phone`, `city`, `businessName` |
| `POST` | `/api/v1/client/auth/change-password` | Client + CSRF | General | Enforces `12+`-char password, bumps `token_version`, revokes sessions, clears cookies, sends non-blocking alert |
| `POST` | `/api/v1/client/auth/forgot-password` | Public | `8 / 15m` IP + `5 / 15m` HMAC email | Dispatches `#token=` 1h reset link; uniform `200 OK` `{ requested: true }`; targeted token revocation on failure |
| `POST` | `/api/v1/client/auth/reset-password` | Public | `8 / 15m` IP + `8 / 15m` HMAC token | Atomic claim (`julianday`), enforces `12+`-char password, bumps `token_version`, revokes sessions, sends non-blocking alert |
| `POST` | `/api/v1/client/auth/deactivate` | Client + CSRF | General | Verifies password, deactivates account, revokes sessions, bumps `token_version`, sends non-blocking alert |

**Client Auth Contract & Error Codes:**
- Guest requests to `GET /api/v1/client/auth/me` return `401 UNAUTHORIZED` (never `200 { client: null }`).
- Cookie-mode session restoration uses `POST /api/v1/client/auth/refresh` with `dtks_client_refresh` + `X-CSRF-Token`, even when `dtks_client_access` is absent or expired.
- Access-token failures: `401 UNAUTHORIZED`, `401 TOKEN_EXPIRED`, `401 INVALID_TOKEN`, `401 SESSION_REVOKED`, `401 INVALID_TOKEN_TYPE` (Admin JWT rejected), `403 EMAIL_NOT_VERIFIED`, `403 ACCOUNT_DEACTIVATED`.
- Refresh-token failures: `400 MISSING_REFRESH_TOKEN`, `401 INVALID_REFRESH_TOKEN`, `401 REFRESH_TOKEN_REPLAY_DETECTED`, `401 REFRESH_TOKEN_EXPIRED`, `403 CSRF_VALIDATION_FAILED`, `403 ACCOUNT_DEACTIVATED`, `403 EMAIL_NOT_VERIFIED`.

---

### 4.1D Client-Only Data Access (`/api/v1/client`)

All endpoints require a valid **Client** session (`authenticateClient`) and strictly scope records to `client.customerId`. Unauthenticated guest orders use `customer_id = NULL` and never leak into verified client portals.

- `GET /api/v1/client/orders`
- `GET /api/v1/client/orders/:id`
- `GET /api/v1/client/quotations`
- `GET /api/v1/client/projects`

---

### 4.2 Services, Packages, Portfolio & R2 Media

- `GET / POST / PUT /api/v1/services`, `GET / PUT / PATCH / DELETE /api/v1/services/:slugOrId` — validates URL safety (`isSafeUrl`) on `image`.
- `GET / POST /api/v1/packages`, `GET / PUT / PATCH / DELETE /api/v1/packages/:id`, `GET / PUT /api/v1/packages/config/maintenance`, `GET / PUT /api/v1/packages/config/addons`.
- `GET / POST /api/v1/portfolio`, `GET / PUT / PATCH / DELETE /api/v1/portfolio/:slugOrId` — validates URL safety (`isSafeUrl`) on `thumbnail`, `images[]`, `projectUrl`, `githubUrl`, and `demoVideoUrl`.
- `POST /api/v1/portfolio/upload` — Admin + CSRF; pre-reads `Content-Length`, `file.size`, and base64 length against 5MB limit (`413 PAYLOAD_TOO_LARGE`); validates `folder`/`entityType` and `replaceKey` (`^(portfolio|services|team|general)\/[a-zA-Z0-9._-]+$`, returning `400 INVALID_ASSET_KEY` on invalid `replaceKey`).
- `DELETE /api/v1/portfolio/upload`, `DELETE /api/v1/portfolio/upload/:key` — Super Admin / Admin + CSRF.
- `GET /api/v1/uploads/:key`, `GET /api/v1/assets/:key` — Serves R2 object with `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; ...`, `Cross-Origin-Resource-Policy: cross-origin`, `Cache-Control: public, max-age=31536000, immutable`.

---

### 4.3 Website Order Management (`/api/v1/orders`)

| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/orders` | Optional Client Cookie + CSRF (Rate-limited `15 / 10m`) | Creates order; guest orders set `customer_id = NULL`; stores SHA-256 hash of 256-bit tracking token (90d TTL) and returns `{ order, trackingExpiresAt, trackingEmailSent }` (**never** returning raw `trackingToken` in JSON). Customer & admin emails dispatch independently and never block committed order persistence. |
| `POST` | `/api/v1/orders/track` | Public (Rate-limited IP `20/15m` + HMAC token `15/15m`) | Validates `{ "token": "..." }` against `order_tracking_tokens` and returns non-PII `status` & `statusHistory` (`status`, `customer_update`, `created_at` — internal admin `notes` are omitted); uniform `404 ORDER_NOT_FOUND` on invalid/expired/revoked tokens. |
| `POST` | `/api/v1/orders/track/resend` | Public (Rate-limited IP `8/15m` + HMAC email `5/15m` + HMAC order `5/15m`, `failClosedInProd: true`) | Validates `{ orderNumber, email }` against stored orders, dispatches a `#token=` link only to stored `customer_email`, revokes prior tokens strictly after confirmed delivery, and returns uniform `200 OK` `{ requested: true }` without enumeration or provider error leakage. |
| `GET` | `/api/v1/orders/track` | Public | Deprecated -> `410 LEGACY_TRACKING_DISABLED` |
| `GET / PATCH / PUT / DELETE` | `/api/v1/orders*` | Admin (+ CSRF) | Full admin order workflow & RBAC (`super_admin`, `admin` for `DELETE`) |

---

### 4.4 Contact, Dashboard, Site Settings, Team, Testimonials & Bootstrap

- `POST /api/v1/contact` (Rate-limited `15 / 10m`), `GET / PATCH / PUT / DELETE /api/v1/contact/:id` (Admin).
- `GET /api/v1/admin/dashboard/stats`, `/recent-orders`, `/recent-messages`, `/order-analytics`, `/customers`, `/customers/:id`, `/admin/activity-logs`, `/admin/notifications`.
- `GET /api/v1/team`, `GET /api/v1/testimonials`, `GET /api/v1/bootstrap` — **Visibility Isolation:** public callers see only visible team members (`visible !== false`) and approved testimonials (`isApproved !== false`); hidden/unapproved records require an authenticated Admin session AND `?includeInactive=true` or `?all=true`. Team avatar/social URLs are validated with `isSafeUrl`.

---

## 5. Role-Based Access Control (RBAC)

- `super_admin`: Full workspace access + `/admin/accounts` creation/invites/roles/statuses/session revocation (protects last active `super_admin`).
- `admin`: Full workspace access (`DELETE`, `PUT /settings`, `PUT /services`, configs, audit logs, notifications) + read-only `/admin/accounts`.
- `editor`: Create/update services, packages, portfolio, R2 uploads, orders, inquiries, team, testimonials; `403 Forbidden` on `DELETE`, bulk `PUT /services`, `PUT /packages/config/*`, `PUT /settings`, audit logs, notifications, and `/admin/accounts*`.
- `client`: Isolated to `/api/v1/client/*` and authenticated `POST /api/v1/orders`.

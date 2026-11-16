# DTKS Frontend <-> Backend API Contract Matrix

**Frontend Repository:** `https://github.com/shahnaveed07/DTKS.git` (`src/services/**`)  
**Backend Repository:** `https://github.com/shahnaveed07/DTKS_BE.git` (`backend/src/**`)  
**API Base Prefix:** `/api/v1`

---

## 1. Summary of Contract Alignment & Coordinated Frontend Remediation

Following the Master Security Remediation in `DTKS_BE`, all backend routes enforce HttpOnly cookie auth by default (with explicit `X-Auth-Mode: bearer` opt-in), double-submit CSRF validation on cookie mutations, token-based `POST /api/v1/orders/track`, `#token=` URL-fragment email links, `12+` character strong passwords, and fail-closed production rate limits.

**Required Updates in the Separate `DTKS` Frontend Repository (`https://github.com/shahnaveed07/DTKS.git`):**
1. **`src/services/api/apiClient.js` & `clientApiClient.js`:** Use `credentials: 'include'` by default, bootstrap CSRF via `GET /api/v1/auth/csrf` or `GET /api/v1/client/auth/csrf`, store `csrfToken` in memory (NOT JWTs in `sessionStorage`/`localStorage`), and send `X-CSRF-Token` on all `POST`/`PUT`/`PATCH`/`DELETE` requests (including `/auth/logout`, `/auth/refresh`, `/client/auth/logout`, `/client/auth/refresh`, and `POST /api/v1/orders`). *(For non-cookie mobile/API clients, pass `X-Auth-Mode: bearer` on `/login` and `/refresh`.)*
2. **`src/services/media/mediaService.js`:** Route `uploadImage` and `deleteImage` through `apiRequest` (`credentials: 'include'` + `X-CSRF-Token` or `Authorization: Bearer`) rather than unauthenticated `fetch()`.
3. **Order Tracking UI (`TrackOrderPage` / `orderService.js`):** Migrate from deprecated `GET /api/v1/orders/track?ref=...&email=...` (`410 LEGACY_TRACKING_DISABLED`) to `POST /api/v1/orders/track` with JSON body `{ "token": "..." }` parsed from `/track-order#token=...` (`window.location.hash`), clearing the hash immediately via `window.history.replaceState`.
4. **Email Token Pages (`/verify-email`, `/reset-password`, `/admin/accept-invite`, `/admin/reset-password`):** Parse tokens from `window.location.hash` (`#token=...`) into component state and strip the fragment from browser history immediately.

---

## 2. Endpoint-by-Endpoint Contract Matrix

| Domain | Frontend Consumer (`DTKS`) | Backend Route (`DTKS_BE`) | Payload / Query / Response Contract | Status |
| :--- | :--- | :--- | :--- | :--- |
| **System** | `API_ENDPOINTS.health` | `GET /api/v1/health` | Independent of D1/R2; returns `{ service, status: 'healthy', version }` | Aligned |
| **System** | `API_ENDPOINTS.ready` | `GET /api/v1/ready` | Checks D1 connection, 19 schema tables, and R2 `ASSETS_BUCKET` (`200` or `503`) | Aligned |
| **System** | `API_ENDPOINTS.bootstrap` | `GET /api/v1/bootstrap` | Returns `{ services, packages, maintenancePlans, addons, portfolio, settings, team, testimonials }` (excludes hidden team & unapproved testimonials unless admin + `?includeInactive=true`) | Aligned |
| **Admin Auth** | `apiClient.js` | `GET /api/v1/auth/csrf` | Sets host-only HttpOnly `dtks_csrf` cookie + returns `{ csrfToken }` | Aligned |
| **Admin Auth** | `apiClient.js` / `authService.js` | `POST /api/v1/auth/login` | `{ email, password }` -> sets `dtks_access`, `dtks_refresh`, `dtks_csrf` cookies (`authMode: 'cookie'`) or emits JSON tokens only with `X-Auth-Mode: bearer` | Aligned |
| **Admin Auth** | `apiClient.js` | `POST /api/v1/auth/refresh` | Cookie + `X-CSRF-Token` (default) or `{ refreshToken }` + `X-Auth-Mode: bearer`; detects replay of rotated tokens (`401 REFRESH_TOKEN_REPLAY_DETECTED`) | Aligned |
| **Admin Auth** | `apiClient.js` | `POST /api/v1/auth/logout` | Cookie + `X-CSRF-Token` (or Bearer); revokes session (`scope: single_device \| all_devices`) and clears cookies | Aligned |
| **Admin Auth** | `authService.js` | `GET /api/v1/auth/me` | Cookie or Bearer Admin JWT -> `{ admin }` | Aligned |
| **Admin Auth** | `authService.js` | `PATCH /api/v1/auth/profile` | `{ name }` -> `{ admin }` (with `X-CSRF-Token` if cookie-authenticated) | Aligned |
| **Admin Auth** | `authService.js` | `POST /api/v1/auth/change-password` | `{ currentPassword, newPassword (>=12 chars), confirmPassword? }` -> bumps `token_version`, revokes sessions, clears cookies | Aligned |
| **Admin Auth** | `AdminAcceptInvitePage.jsx` | `POST /api/v1/auth/accept-invite` | `{ token, password (>=12 chars), confirmPassword }` (`#token=` email link) -> `{ activated: true, account }` | Aligned |
| **Admin Auth** | Admin Forgot Password page | `POST /api/v1/auth/forgot-password` | `{ email }` -> sends 1h `#token=` link (`/admin/reset-password#token=...`); uniform `200` anti-enumeration | Aligned |
| **Admin Auth** | Admin Reset Password page | `POST /api/v1/auth/reset-password` | `{ token, newPassword \| password (>=12 chars), confirmPassword }` -> `{ reset: true }`; bumps `token_version` & revokes sessions | Aligned |
| **Admin Accounts** | `authService.js` / `AdminAccountsPage.jsx` | `GET /api/v1/admin/accounts` | Supports `status=all\|active\|inactive\|pending\|expired`, `role`, `search`, `page`, `limit` | Aligned |
| **Admin Accounts** | `authService.js` | `GET /api/v1/admin/accounts/:id` | Returns account details + `activeSessions`, `inviteExpiresAt`, `inviteExpired`, `recentSessions` | Aligned |
| **Admin Accounts** | `authService.js` | `POST /api/v1/admin/accounts` | `{ name, email, role }` -> `201` with `#token=` invite email | Aligned |
| **Admin Accounts** | `authService.js` | `POST /api/v1/admin/accounts/:id/resend-invite` | Revokes prior invites, sends `#token=` email | Aligned |
| **Admin Accounts** | `authService.js` | `PATCH /api/v1/admin/accounts/:id` | `{ name?, role? }` -> updates & bumps `token_version` on role change | Aligned |
| **Admin Accounts** | `authService.js` | `PATCH /api/v1/admin/accounts/:id/status` | `{ isActive }` -> activates/deactivates with last-super-admin protection | Aligned |
| **Admin Accounts** | `authService.js` | `DELETE /api/v1/admin/accounts/:id/sessions` | Revokes active sessions & increments `token_version` | Aligned |
| **Client Auth** | `clientApiClient.js` | `GET /api/v1/client/auth/csrf` | Sets host-only HttpOnly `dtks_client_csrf` cookie + returns `{ csrfToken }` | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/register` | `{ fullName, email, phone, password (>=12 chars), confirmPassword, acceptTerms, acceptPrivacy?, city?, businessName? }` -> sends `#token=` email | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/verify-email` | `{ token }` -> verifies email, links `customers` + pre-registration `orders` (`orders.created_at <= account.created_at`) | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/resend-verification` | `{ email }` -> layered IP + HMAC email rate limits; uniform `200` anti-enumeration; targeted revocation on failure | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/login` | `{ email, password }` -> sets `dtks_client_*` HttpOnly cookies (`authMode: 'cookie'`) or JSON tokens with `X-Auth-Mode: bearer` | Aligned |
| **Client Auth** | `clientApiClient.js` | `POST /api/v1/client/auth/refresh` | Cookie + `X-CSRF-Token` (default) or `{ refreshToken }` + `X-Auth-Mode: bearer`; replay detection | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/logout` | Cookie + `X-CSRF-Token` (or Bearer); revokes session(s) and clears client cookies | Aligned |
| **Client Auth** | `clientAuthService.js` | `GET /api/v1/client/auth/me` | Client cookie or Bearer JWT -> `{ client }` | Aligned |
| **Client Auth** | `clientAuthService.js` | `PATCH /api/v1/client/auth/profile` | `{ fullName?, phone?, city?, businessName? }` -> synced with `customers` | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/change-password` | `{ currentPassword, newPassword (>=12 chars) }` -> revokes sessions, clears cookies & sends non-blocking alert | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/forgot-password` | `{ email }` -> layered IP + HMAC email rate limits; `#token=` link; uniform `200` anti-enumeration | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/reset-password` | `{ token, newPassword \| password (>=12 chars), confirmPassword }` -> atomic claim + non-blocking alert | Aligned |
| **Client Portal** | `clientAccountService.js` | `GET /api/v1/client/orders` & `/:id` | Scoped strictly to `client.customerId`; strips `admin_notes` | Aligned |
| **Client Portal** | `clientAccountService.js` | `GET /api/v1/client/quotations` | Scoped client orders in quotation states | Aligned |
| **Client Portal** | `clientAccountService.js` | `GET /api/v1/client/projects` | Scoped client active/completed orders | Aligned |
| **Services** | `packageService.js` | `GET /api/v1/services`, `POST`, `PUT`, `GET/PUT/PATCH/DELETE /:slugOrId` | Validates URL safety (`isSafeUrl`) on `image`; supports raw arrays on bulk `PUT` | Aligned |
| **Packages** | `packageService.js` | `GET/POST /api/v1/packages`, `GET/PUT/PATCH/DELETE /:id` | Returns `{ packages, maintenancePlans, addons }` on list | Aligned |
| **Package Configs** | `packageService.js` | `GET` & `PUT /api/v1/packages/config/maintenance`, `/addons` | Supports raw arrays `[...]`, preserves nullable prices | Aligned |
| **Portfolio** | `portfolioService.js` | `GET/POST /api/v1/portfolio`, `GET/PUT/PATCH/DELETE /:slugOrId` | Validates `thumbnail`, `images`, `projectUrl`, `githubUrl`, `demoVideoUrl` via `isSafeUrl` | Aligned |
| **Media (R2)** | `mediaService.js` | `POST /api/v1/portfolio/upload`, `DELETE /api/v1/portfolio/upload/:key`, `GET /api/v1/uploads/:key` | Pre-read size ceiling (`413`), strict key/replaceKey regex (`400`), hardened serving headers (`nosniff`, CSP, CORP `cross-origin`) | **Frontend update needed** *(Section 1)* |
| **Orders** | `orderService.js` / `RequestQuotePage.jsx` | `POST /api/v1/orders`, `POST /api/v1/orders/track`, `GET/PATCH/PUT/DELETE /orders/:id` | Guest orders have `customer_id = NULL`; `POST /orders` enforces CSRF if client auth cookies are present; returns `trackingToken` (`POST /orders/track` returns non-PII summary; `GET /orders/track` returns `410`) | **Frontend update needed** *(Section 1)* |
| **Contact** | `inquiryService.js` | `POST/GET /api/v1/contact`, `GET/PATCH/PUT/DELETE /contact/:id` | XSS + honeypot filtering; rate-limited `15 / 10m` | Aligned |
| **Customers & Dashboard** | `AdminDashboardPage.jsx` | `/admin/dashboard/*`, `/customers*`, `/admin/activity-logs`, `/admin/notifications` | Real D1 SQL aggregations (`customer_id` or unlinked legacy email match) | Aligned |
| **Settings** | `settingsService.js` | `GET/PUT/PATCH /api/v1/settings` | Recursive secret & prototype-pollution stripping + XSS sanitization | Aligned |
| **Team & Testimonials** | `teamService.js` | `GET/POST /api/v1/team*`, `GET/POST/DELETE /testimonials*` | Public `GET` excludes `visible: false` / `isApproved: false` unless authenticated admin requests `includeInactive=true` / `all=true`; safe URL checks on team links | Aligned |

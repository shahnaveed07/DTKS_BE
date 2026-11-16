# DTKS Frontend <-> Backend API Contract Matrix

**Frontend Repository:** `https://github.com/shahnaveed07/DTKS.git` (`src/services/**`)  
**Backend Repository:** `https://github.com/shahnaveed07/DTKS_BE.git` (`backend/src/**`)  
**API Base Prefix:** `/api/v1`

---

## 1. Summary of Contract Alignment

All endpoints declared by `DTKS/src/services/models/backendModels.js` (`API_ENDPOINTS`) and invoked across the frontend service modules (`apiClient.js`, `authService.js`, `clientAuthService.js`, `clientAccountService.js`, `packageService.js`, `portfolioService.js`, `orderService.js`, `inquiryService.js`, `settingsService.js`, `teamService.js`, `mediaService.js`) are verified against `backend/src/routes/router.js` and controller implementations.

**Action Required in Separate `DTKS` Frontend Repository:**  
One client-side integration defect exists in the **separate frontend repo** (`DTKS/src/services/media/mediaService.js`) and is documented in Section 3 below. Because `DTKS_BE` must remain strictly backend-only and must not bypass authentication/CSRF, `DTKS_BE` enforces valid Admin auth + CSRF on media mutations, and `mediaService.js` in `DTKS` should be updated to reuse `apiClient.js` auth headers.

---

## 2. Endpoint-by-Endpoint Contract Matrix

| Domain | Frontend Consumer (`DTKS`) | Backend Route (`DTKS_BE`) | Payload / Query / Response Contract | Status |
| :--- | :--- | :--- | :--- | :--- |
| **System** | `API_ENDPOINTS.health` | `GET /api/v1/health` | Independent of D1/R2; returns `{ service, status: 'healthy', version }` | Aligned |
| **System** | `API_ENDPOINTS.ready` | `GET /api/v1/ready` | Checks D1 connection, 18 schema tables, and R2 `ASSETS_BUCKET` (`200` or `503`) | Aligned |
| **System** | `API_ENDPOINTS.bootstrap` | `GET /api/v1/bootstrap` | Returns `{ services, packages, maintenancePlans, addons, portfolio, settings, team, testimonials }` | Aligned |
| **Admin Auth** | `apiClient.js` / `authService.js` | `POST /api/v1/auth/login` | `{ email, password }` -> `{ accessToken, refreshToken, csrfToken, expiresIn, admin }` | Aligned |
| **Admin Auth** | `apiClient.js` | `POST /api/v1/auth/refresh` | `{ refreshToken }` (or cookie) -> `{ accessToken, refreshToken, csrfToken, expiresIn }` | Aligned |
| **Admin Auth** | `apiClient.js` | `POST /api/v1/auth/logout` | `{ refreshToken?, allDevices? }` -> `{ loggedOut, allDevices, scope, sessionsRevoked }` | Aligned |
| **Admin Auth** | `authService.js` | `GET /api/v1/auth/me` | Bearer Admin JWT -> `{ admin }` | Aligned |
| **Admin Auth** | `authService.js` | `PATCH /api/v1/auth/profile` | `{ name }` -> `{ admin }` | Aligned |
| **Admin Auth** | `authService.js` | `POST /api/v1/auth/change-password` | `{ currentPassword, newPassword, confirmPassword? }` -> revokes prior sessions | Aligned |
| **Admin Auth** | `AdminAcceptInvitePage.jsx` | `POST /api/v1/auth/accept-invite` | `{ token, password, confirmPassword }` -> `{ activated: true, account }` | Aligned |
| **Admin Auth** | Admin Forgot Password page | `POST /api/v1/auth/forgot-password` | `{ email }` -> sends 1h single-use link (`/admin/reset-password?token=...`); uniform `200` anti-enumeration | Aligned |
| **Admin Auth** | Admin Reset Password page | `POST /api/v1/auth/reset-password` | `{ token, newPassword \| password, confirmPassword }` -> `{ reset: true }`; bumps `token_version` & revokes `refresh_sessions` | Aligned |
| **Admin Accounts** | `authService.js` / `AdminAccountsPage.jsx` | `GET /api/v1/admin/accounts` | Supports `status=all\|active\|inactive\|pending\|expired`, `role`, `search`, `page`, `limit`; emits `invitePending`, `inviteExpiresAt`, `inviteExpired`, `activeSessions`, `activeSessionCount` | Aligned |
| **Admin Accounts** | `authService.js` | `GET /api/v1/admin/accounts/:id` | Returns account details + `activeSessions`, `inviteExpiresAt`, `inviteExpired`, `recentSessions` | Aligned |
| **Admin Accounts** | `authService.js` | `POST /api/v1/admin/accounts` | `{ name, email, role }` -> `201` with `{ account, invitationEmailSent, inviteEmailSent, inviteExpiresAt }` | Aligned |
| **Admin Accounts** | `authService.js` | `POST /api/v1/admin/accounts/:id/resend-invite` | Revokes prior invites, sends email, returns `inviteEmailSent` + `inviteExpiresAt` | Aligned |
| **Admin Accounts** | `authService.js` | `PATCH /api/v1/admin/accounts/:id` | `{ name?, role? }` -> updates & bumps `token_version` on role change | Aligned |
| **Admin Accounts** | `authService.js` | `PATCH /api/v1/admin/accounts/:id/status` | `{ isActive }` -> activates/deactivates with last-super-admin protection | Aligned |
| **Admin Accounts** | `authService.js` | `DELETE /api/v1/admin/accounts/:id/sessions` | Revokes active sessions & increments `token_version` | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/register` | `{ fullName, email, phone, password, confirmPassword, acceptTerms, acceptPrivacy?, city?, businessName? }` | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/verify-email` | `{ token }` -> verifies email, links `customers` + unlinked `orders` | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/resend-verification` | `{ email }` -> resends 24h verification email | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/login` | `{ email, password }` -> `{ accessToken, refreshToken, csrfToken, client }` | Aligned |
| **Client Auth** | `clientApiClient.js` | `POST /api/v1/client/auth/refresh` | `{ refreshToken }` -> rotated client token pair | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/logout` | `{ refreshToken?, allDevices? }` -> single or all-device session revocation | Aligned |
| **Client Auth** | `clientAuthService.js` | `GET /api/v1/client/auth/me` | Client Bearer JWT -> `{ client }` | Aligned |
| **Client Auth** | `clientAuthService.js` | `PATCH /api/v1/client/auth/profile` | `{ fullName?, phone?, city?, businessName? }` -> synced with `customers` | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/change-password` | `{ currentPassword, newPassword }` -> revokes sessions & notifies email | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/forgot-password` | `{ email }` -> sends 1h reset link (`/reset-password?token=...`) | Aligned |
| **Client Auth** | `clientAuthService.js` | `POST /api/v1/client/auth/reset-password` | `{ token, newPassword \| password, confirmPassword }` | Aligned |
| **Client Portal** | `clientAccountService.js` | `GET /api/v1/client/orders` & `/:id` | Scoped strictly to `client.customerId`; strips `admin_notes` | Aligned |
| **Client Portal** | `clientAccountService.js` | `GET /api/v1/client/quotations` | Scoped client orders in quotation states | Aligned |
| **Client Portal** | `clientAccountService.js` | `GET /api/v1/client/projects` | Scoped client active/completed orders | Aligned |
| **Services** | `packageService.js` | `GET /api/v1/services`, `POST`, `PUT`, `GET/PUT/PATCH/DELETE /:slugOrId` | `PUT /api/v1/services` accepts raw JSON arrays `[...]` from `saveServicesAsync`; supports `shortDescription`, `deliveryTimeline`, `startingPrice`, `active` aliases | Aligned |
| **Packages** | `packageService.js` | `GET/POST /api/v1/packages`, `GET/PUT/PATCH/DELETE /:id` | Returns `{ packages, maintenancePlans, addons }` on list; maps `title`, `startingPrice`, `active`, `featured` | Aligned |
| **Package Configs** | `packageService.js` | `GET` & `PUT /api/v1/packages/config/maintenance`, `GET` & `PUT /api/v1/packages/config/addons` | Both `GET` and raw-array `PUT` supported; preserves `price: null`, `startingPrice: null`, `updateAllowance`, `backupFrequency`, `securityChecks`, `responseTime`, `scopeNote`, `pricingNote` | Aligned |
| **Portfolio** | `portfolioService.js` | `GET/POST /api/v1/portfolio`, `GET/PUT/PATCH/DELETE /:slugOrId` | Supports `slug`, `published`, `shortOverview`, `coverImage`, `gallery`, category filtering & pagination | Aligned |
| **Media (R2)** | `mediaService.js` | `POST /api/v1/portfolio/upload`, `DELETE /api/v1/portfolio/upload/:key`, `GET /api/v1/uploads/:key` | Accepts `folder` or `entityType` (`portfolio`, `services`, `team`, `general`); returns `{ id, key, url, publicUrl, mimeType, sizeBytes }`; `DELETE` accepts encoded full URLs, `/api/v1/uploads/...`, or keys | **Requires Frontend Fix** *(See Section 3)* |
| **Orders** | `orderService.js` / `RequestQuotePage.jsx` | `POST /api/v1/orders`, `GET /orders/track`, `GET/PATCH/PUT/DELETE /orders/:id`, `PATCH/PUT /orders/:id/status` | Atomic batch order + item + history creation; 14 canonical/frontend status values supported | Aligned |
| **Contact** | `inquiryService.js` | `POST/GET /api/v1/contact`, `GET/PATCH/PUT/DELETE /contact/:id` | Supports `New`, `Read`, `In Review`, `Replied`, `Archived`; XSS + honeypot filtering | Aligned |
| **Customers & Dashboard** | `AdminDashboardPage.jsx` | `GET /admin/dashboard/stats`, `/recent-orders`, `/recent-messages`, `/order-analytics`, `/customers`, `/customers/:id`, `/admin/activity-logs`, `/admin/notifications` | Real D1 SQL aggregations (`customer_id` or unlinked legacy email match) | Aligned |
| **Settings** | `settingsService.js` | `GET/PUT/PATCH /api/v1/settings` | Recursive secret & prototype-pollution stripping + XSS sanitization | Aligned |
| **Team & Testimonials** | `teamService.js` | `GET/POST /api/v1/team`, `PATCH/PUT/DELETE /team/:id`, `POST/PATCH /team/:id/reorder`, `GET/POST/DELETE /testimonials` | Whitelisted team fields, `order` & `sortOrder` aliases, reorder direction (`up`/`down`) | Aligned |

---

## 3. Frontend Defect Identified During Cross-Repo Inspection (`DTKS/src/services/media/mediaService.js`)

In the separate frontend repository (`https://github.com/shahnaveed07/DTKS.git`), `src/services/media/mediaService.js` currently calls raw `fetch()` with `{ credentials: 'include' }` instead of routing through `apiRequest(...)` from `src/services/api/apiClient.js`:

- **`uploadImage(file, options)`** (`POST /api/v1/portfolio/upload`) omits the `Authorization: Bearer <accessToken>` header (and omits `X-CSRF-Token` if using cookie mode).
- **`deleteImage(mediaRefOrId)`** (`DELETE /api/v1/portfolio/upload/:id`) similarly omits `Authorization: Bearer <accessToken>` and `X-CSRF-Token`.

**Required Fix in `DTKS` Frontend Repo:**  
Update `DTKS/src/services/media/mediaService.js` to attach `Authorization: Bearer ${session.accessToken}` (or route via `apiRequest` supporting `FormData`) and `X-CSRF-Token` when cookies are present. Do **not** relax backend `authenticateAdmin` or CSRF enforcement on `POST`/`DELETE /portfolio/upload`.

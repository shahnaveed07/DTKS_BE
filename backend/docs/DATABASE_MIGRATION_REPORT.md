# DTKS_BE Database Schema & Migration Report

**Database Engine:** Cloudflare D1 (SQLite)  
**Production Database Name:** `dtks-production-db`  
**Database ID:** `be0ce24a-0151-412f-b308-1271bb62abba` (Binding: `DB`)

---

## 1. Migration Inventory (Strictly Additive & Non-Destructive)

| Order | Migration File | Purpose | Safety Mechanism |
| :--- | :--- | :--- | :--- |
| 1 | `backend/migrations/0001_initial_schema.sql` | Creates the 13 core tables (`admins`, `customers`, `services`, `packages`, `portfolio`, `orders`, `order_items`, `order_status_history`, `contact_messages`, `site_settings`, `activity_logs`, `refresh_sessions`, `rate_limits`) plus foreign keys, `CHECK` constraints, and indexes. | `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS` |
| 2 | `backend/migrations/0002_seed_data.sql` | Seeds initial non-secret company profile settings into `site_settings` (`companyName`, `contactEmail`, `officialDomain`, `location`). Does not seed default admin passwords. | `INSERT OR IGNORE` |
| 3 | `backend/migrations/0003_admin_accounts_and_client_auth.sql` | Adds `token_version`, `invited_by_admin_id`, `invite_accepted_at`, `deactivated_at` to `admins`; creates `admin_invitations`, `customer_accounts`, `customer_refresh_sessions`, and `customer_auth_tokens` (bringing total to **17 tables**). | Additive `ALTER TABLE` + `CREATE TABLE IF NOT EXISTS` |
| 4 | `backend/migrations/0004_client_legal_acceptance_and_security_fixes.sql` | Adds legal consent audit columns (`terms_accepted`, `terms_accepted_at`, `terms_version`, `privacy_accepted`, `privacy_accepted_at`, `privacy_version`, `legal_accepted_ip`) to `customer_accounts` and composite security indexes on session/token tables. | Additive `ALTER TABLE` + `CREATE INDEX IF NOT EXISTS` |
| 5 | `backend/migrations/0005_admin_password_reset.sql` | Creates `admin_auth_tokens` (`password_reset` SHA-256-hashed single-use expiring tokens) and lookup/expiry indexes (bringing total to **18 tables**). | `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS` |

---

## 2. All 18 Verified Tables Checked by `GET /api/v1/ready`

1. `admins`
2. `admin_invitations`
3. `admin_auth_tokens`
4. `refresh_sessions`
4. `customers`
5. `customer_accounts`
6. `customer_refresh_sessions`
7. `customer_auth_tokens`
8. `services`
9. `packages`
10. `portfolio`
11. `orders`
12. `order_items`
13. `order_status_history`
14. `contact_messages`
15. `site_settings`
16. `activity_logs`
17. `rate_limits`

---

## 3. Local & Runtime Seeding Behavior (`backend/src/database/seed.js`)

- `ensureDatabaseSeeded(env)` uses `INSERT OR IGNORE` for catalog services, packages, portfolio items, maintenance plans, add-ons, team members, testimonials, and site settings so existing production edits are **never** overwritten.
- `verifyDatabaseSchema(db)` inspects `sqlite_master` for all 18 required tables; if any migration is missing, `/api/v1/ready` cleanly returns `503 SERVICE_NOT_READY` (`schema: 'missing_tables'`) and standard API endpoints fail safely with `503 DATABASE_SCHEMA_MISSING` rather than an unhandled `500`.
- `LocalD1Database` (`backend/src/database/d1Adapter.js`) resolves `DEFAULT_MIGRATIONS_DIR` via `import.meta.url`, making local SQLite migrations CWD-independent across both repository root and `backend/`.

---

## 4. Safe Remote D1 Migration Procedure

```bash
cd backend
npx wrangler d1 migrations list dtks-production-db --remote
npx wrangler d1 migrations apply dtks-production-db --remote
```

*(Never run destructive `DROP TABLE` or database reset commands against `dtks-production-db`.)*

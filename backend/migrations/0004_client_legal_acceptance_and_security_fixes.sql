-- =============================================================================
-- DTKS (DreamTech Kashmir Solutions) — Client Legal Acceptance & Security Indexes
-- Migration: 0004_client_legal_acceptance_and_security_fixes.sql
-- Target: Cloudflare D1 (SQLite)
-- Safe & Additive: Preserves all existing tables, admins, customer accounts, and orders.
-- =============================================================================

PRAGMA foreign_keys = ON;

-- 1. Persist explicit client legal acceptance metadata (Terms & Conditions + Privacy Policy)
ALTER TABLE customer_accounts ADD COLUMN terms_accepted INTEGER NOT NULL DEFAULT 0 CHECK (terms_accepted IN (0, 1));
ALTER TABLE customer_accounts ADD COLUMN terms_accepted_at TEXT;
ALTER TABLE customer_accounts ADD COLUMN terms_version TEXT NOT NULL DEFAULT '';
ALTER TABLE customer_accounts ADD COLUMN privacy_accepted INTEGER NOT NULL DEFAULT 0 CHECK (privacy_accepted IN (0, 1));
ALTER TABLE customer_accounts ADD COLUMN privacy_accepted_at TEXT;
ALTER TABLE customer_accounts ADD COLUMN privacy_version TEXT NOT NULL DEFAULT '';
ALTER TABLE customer_accounts ADD COLUMN legal_accepted_ip TEXT DEFAULT '';

-- 2. Composite / covering indexes for high-frequency RBAC, session revocation, and token checks
CREATE INDEX IF NOT EXISTS idx_admins_active_role_created
  ON admins(is_active, role, created_at);

CREATE INDEX IF NOT EXISTS idx_refresh_sessions_admin_revoked
  ON refresh_sessions(admin_id, revoked_at);

CREATE INDEX IF NOT EXISTS idx_customer_refresh_sessions_acct_revoked
  ON customer_refresh_sessions(customer_account_id, revoked_at);

CREATE INDEX IF NOT EXISTS idx_customer_auth_tokens_acct_purpose_state
  ON customer_auth_tokens(customer_account_id, purpose, used_at, revoked_at);

CREATE INDEX IF NOT EXISTS idx_admin_invitations_admin_state
  ON admin_invitations(admin_id, used_at, revoked_at);

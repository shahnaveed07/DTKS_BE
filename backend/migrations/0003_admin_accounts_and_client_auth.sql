-- =============================================================================
-- DTKS (DreamTech Kashmir Solutions) — Admin Account Management & Client Auth
-- Migration: 0003_admin_accounts_and_client_auth.sql
-- Target: Cloudflare D1 (SQLite)
-- Safe & Additive: Never deletes or overwrites existing admins, customers, or orders.
-- =============================================================================

PRAGMA foreign_keys = ON;

-- 1. Additive security & onboarding columns on `admins`
ALTER TABLE admins ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE admins ADD COLUMN invited_by_admin_id TEXT;
ALTER TABLE admins ADD COLUMN invite_accepted_at TEXT;
ALTER TABLE admins ADD COLUMN deactivated_at TEXT;

-- 2. Admin invitation tokens (expiring, single-use, SHA-256 hashed)
CREATE TABLE IF NOT EXISTS admin_invitations (
  id TEXT PRIMARY KEY,
  admin_id TEXT NOT NULL,
  email TEXT NOT NULL COLLATE NOCASE,
  token_hash TEXT NOT NULL UNIQUE,
  invited_by_admin_id TEXT,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE,
  FOREIGN KEY (invited_by_admin_id) REFERENCES admins(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_invitations_admin_id ON admin_invitations(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_invitations_token_hash ON admin_invitations(token_hash);
CREATE INDEX IF NOT EXISTS idx_admin_invitations_expires_at ON admin_invitations(expires_at);

-- 3. Client authentication accounts (separate from `customers` & `admins`)
CREATE TABLE IF NOT EXISTS customer_accounts (
  id TEXT PRIMARY KEY,
  customer_id TEXT UNIQUE,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  phone TEXT NOT NULL,
  city TEXT DEFAULT '',
  business_name TEXT DEFAULT '',
  password_hash TEXT NOT NULL,
  is_email_verified INTEGER NOT NULL DEFAULT 0 CHECK (is_email_verified IN (0, 1)),
  email_verified_at TEXT,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  deactivated_at TEXT,
  token_version INTEGER NOT NULL DEFAULT 1,
  last_login_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_customer_accounts_email ON customer_accounts(email);
CREATE INDEX IF NOT EXISTS idx_customer_accounts_customer_id ON customer_accounts(customer_id);
CREATE INDEX IF NOT EXISTS idx_customer_accounts_is_active ON customer_accounts(is_active);
CREATE INDEX IF NOT EXISTS idx_customer_accounts_verified ON customer_accounts(is_email_verified);

-- 4. Client refresh token sessions (hashed, rotatable, revocable)
CREATE TABLE IF NOT EXISTS customer_refresh_sessions (
  id TEXT PRIMARY KEY,
  customer_account_id TEXT NOT NULL,
  refresh_token_hash TEXT NOT NULL UNIQUE,
  user_agent TEXT,
  ip_address TEXT,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (customer_account_id) REFERENCES customer_accounts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_customer_refresh_sessions_account_id ON customer_refresh_sessions(customer_account_id);
CREATE INDEX IF NOT EXISTS idx_customer_refresh_sessions_token_hash ON customer_refresh_sessions(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_customer_refresh_sessions_expires_at ON customer_refresh_sessions(expires_at);

-- 5. Client verification & password reset tokens (expiring, single-use, SHA-256 hashed)
CREATE TABLE IF NOT EXISTS customer_auth_tokens (
  id TEXT PRIMARY KEY,
  customer_account_id TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('email_verification', 'password_reset')),
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (customer_account_id) REFERENCES customer_accounts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_customer_auth_tokens_account_id ON customer_auth_tokens(customer_account_id);
CREATE INDEX IF NOT EXISTS idx_customer_auth_tokens_token_hash ON customer_auth_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_customer_auth_tokens_purpose ON customer_auth_tokens(purpose);
CREATE INDEX IF NOT EXISTS idx_customer_auth_tokens_expires_at ON customer_auth_tokens(expires_at);

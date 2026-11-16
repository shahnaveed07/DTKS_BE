-- =============================================================================
-- DTKS (DreamTech Kashmir Solutions) — Admin Password Reset Tokens
-- Migration: 0005_admin_password_reset.sql
-- Target: Cloudflare D1 (SQLite)
-- Safe & Additive: Preserves all existing tables, admins, client accounts, and orders.
-- =============================================================================

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS admin_auth_tokens (
  id TEXT PRIMARY KEY,
  admin_id TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('password_reset')),
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_admin_auth_tokens_token_hash
  ON admin_auth_tokens(token_hash);

CREATE INDEX IF NOT EXISTS idx_admin_auth_tokens_admin_purpose
  ON admin_auth_tokens(admin_id, purpose);

CREATE INDEX IF NOT EXISTS idx_admin_auth_tokens_admin_purpose_state
  ON admin_auth_tokens(admin_id, purpose, used_at, revoked_at);

CREATE INDEX IF NOT EXISTS idx_admin_auth_tokens_expires_at
  ON admin_auth_tokens(expires_at);

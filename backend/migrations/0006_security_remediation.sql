-- ============================================================
-- Migration 0006: Security Remediation Schema Additions
-- Additive only — preserves all existing tables and production data.
-- ============================================================

-- 1. Cryptographically random, hashed order-tracking tokens (replaces email+ref enumeration)
CREATE TABLE IF NOT EXISTS order_tracking_tokens (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  last_accessed_at TEXT,
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_order_tracking_tokens_order_id
  ON order_tracking_tokens(order_id);
CREATE INDEX IF NOT EXISTS idx_order_tracking_tokens_hash
  ON order_tracking_tokens(token_hash);

-- 2. Refresh-token revocation reason tracking for replay detection vs. explicit logout
ALTER TABLE refresh_sessions ADD COLUMN revoke_reason TEXT;

ALTER TABLE customer_refresh_sessions ADD COLUMN revoke_reason TEXT;

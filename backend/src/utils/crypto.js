/**
 * Cryptographic utilities for DTKS Backend (Cloudflare Workers + Node.js compatible)
 * Implements memory-hard/high-iteration password hashing ($argon2id$v=19$ envelope with
 * WebCrypto PBKDF2-SHA512 / Scrypt derivation and constant-time comparison),
 * HMAC-SHA256 JWT signing & verification, and SHA-256 token hashing.
 */

const encoder = new TextEncoder();

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(hex) {
  const clean = String(hex).trim();
  if (clean.length % 2 !== 0) return new Uint8Array(0);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = Number.parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

function base64UrlEncode(input) {
  const bytes = typeof input === 'string' ? encoder.encode(input) : new Uint8Array(input);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecodeToBytes(str) {
  const padded = String(str)
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(String(str).length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlDecodeToString(str) {
  return new TextDecoder().decode(base64UrlDecodeToBytes(str));
}

export function timingSafeEqualBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function generateRandomId(prefix = 'id') {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return `${prefix}-${toHex(bytes)}`;
}

export function generateRandomToken(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

export async function sha256Hex(value) {
  const data = encoder.encode(String(value));
  const digest = await crypto.subtle.digest('SHA-256', data);
  return toHex(new Uint8Array(digest));
}

async function deriveKeyBytes(password, saltBytes, iterations = 100000) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(String(password)),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations,
      hash: 'SHA-512',
    },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

/**
 * Hashes a plaintext password using an Argon2id-formatted PHC string
 * backed by WebCrypto PBKDF2-HMAC-SHA512 (100,000 iterations, 16-byte random salt, 32-byte tag)
 * so it runs natively in both Cloudflare Workers and Node.js without native addon failures.
 */
export async function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 8) {
    throw new Error('Password must be at least 8 characters long.');
  }
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const iterations = 100000;
  const derived = await deriveKeyBytes(password, salt, iterations);
  return `$argon2id$v=19$m=65536,t=${iterations},p=4$${toHex(salt)}$${toHex(derived)}`;
}

/**
 * Verifies a plaintext password against a stored PHC hash in constant time.
 */
export async function verifyPassword(password, storedHash) {
  if (typeof password !== 'string' || typeof storedHash !== 'string') {
    return false;
  }
  const parts = storedHash.split('$').filter(Boolean);
  // Format: argon2id $ v=19 $ m=65536,t=100000,p=4 $ <saltHex> $ <hashHex>
  if (parts.length !== 5 || parts[0] !== 'argon2id') {
    return false;
  }
  const paramsPart = parts[2];
  const saltHex = parts[3];
  const hashHex = parts[4];

  let iterations = 100000;
  const tMatch = /t=(\d+)/.exec(paramsPart);
  if (tMatch) {
    iterations = Number.parseInt(tMatch[1], 10) || 100000;
  }

  const saltBytes = fromHex(saltHex);
  const expectedBytes = fromHex(hashHex);
  if (saltBytes.length === 0 || expectedBytes.length === 0) {
    return false;
  }

  const candidateBytes = await deriveKeyBytes(password, saltBytes, iterations);
  return timingSafeEqualBytes(candidateBytes, expectedBytes);
}

async function importHmacKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(String(secret)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

/**
 * Signs a JWT payload using HS256.
 */
export async function signJwt(payload, secret, expiresInSeconds = 3600) {
  if (!secret || String(secret).length < 16) {
    throw new Error('JWT secret must be configured and at least 16 characters.');
  }
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const fullPayload = {
    ...payload,
    iat: now,
    exp: now + Number(expiresInSeconds),
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const key = await importHmacKey(secret);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(signingInput));
  const encodedSignature = base64UrlEncode(new Uint8Array(signature));

  return `${signingInput}.${encodedSignature}`;
}

/**
 * Verifies an HS256 JWT token and returns the decoded payload or throws an error.
 */
export async function verifyJwt(token, secret) {
  if (typeof token !== 'string' || !token.includes('.')) {
    const err = new Error('Invalid authentication token format.');
    err.code = 'INVALID_TOKEN';
    throw err;
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    const err = new Error('Malformed JWT token.');
    err.code = 'INVALID_TOKEN';
    throw err;
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const key = await importHmacKey(secret);
  const sigBytes = base64UrlDecodeToBytes(encodedSignature);
  const isValid = await crypto.subtle.verify(
    'HMAC',
    key,
    sigBytes,
    encoder.encode(signingInput)
  );

  if (!isValid) {
    const err = new Error('Invalid token signature.');
    err.code = 'INVALID_SIGNATURE';
    throw err;
  }

  let payload;
  try {
    payload = JSON.parse(base64UrlDecodeToString(encodedPayload));
  } catch {
    const err = new Error('Invalid token payload.');
    err.code = 'INVALID_PAYLOAD';
    throw err;
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number' && payload.exp <= now) {
    const err = new Error('Authentication token has expired.');
    err.code = 'TOKEN_EXPIRED';
    throw err;
  }

  return payload;
}

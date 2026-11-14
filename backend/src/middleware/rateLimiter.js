import { errorResponse } from '../utils/response.js';

/**
 * Sliding-window rate limiter for brute-force login protection, spam prevention,
 * and general API rate limiting.
 */

const buckets = new Map();

export const RATE_LIMIT_POLICIES = {
  authLogin: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 10,
    message: 'Too many login attempts. Please wait 15 minutes before trying again.',
  },
  publicSubmission: {
    windowMs: 10 * 60 * 1000, // 10 minutes
    maxRequests: 25,
    message: 'Submission rate limit exceeded. Please wait a few minutes before submitting again.',
  },
  generalApi: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 240,
    message: 'Too many requests. Please slow down.',
  },
};

export function getClientIp(request) {
  return (
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    request.headers.get('X-Real-IP') ||
    '127.0.0.1'
  );
}

export function checkRateLimit(request, policyName = 'generalApi', customKeySuffix = '') {
  const policy = RATE_LIMIT_POLICIES[policyName] || RATE_LIMIT_POLICIES.generalApi;
  const ip = getClientIp(request);
  const key = `${policyName}:${ip}${customKeySuffix ? `:${customKeySuffix}` : ''}`;
  const now = Date.now();

  let record = buckets.get(key);
  if (!record || now - record.windowStart >= policy.windowMs) {
    record = { windowStart: now, count: 0 };
  }

  record.count += 1;
  buckets.set(key, record);

  // Periodic cleanup to avoid unbounded memory growth
  if (buckets.size > 5000) {
    for (const [k, v] of buckets.entries()) {
      if (now - v.windowStart > 30 * 60 * 1000) {
        buckets.delete(k);
      }
    }
  }

  const remaining = Math.max(0, policy.maxRequests - record.count);
  const resetSeconds = Math.max(1, Math.ceil((record.windowStart + policy.windowMs - now) / 1000));

  if (record.count > policy.maxRequests) {
    return {
      allowed: false,
      response: errorResponse(
        policy.message,
        429,
        'RATE_LIMIT_EXCEEDED',
        { retryAfterSeconds: resetSeconds },
        {
          'Retry-After': String(resetSeconds),
          'X-RateLimit-Limit': String(policy.maxRequests),
          'X-RateLimit-Remaining': '0',
        }
      ),
    };
  }

  return {
    allowed: true,
    headers: {
      'X-RateLimit-Limit': String(policy.maxRequests),
      'X-RateLimit-Remaining': String(remaining),
    },
  };
}

export function resetRateLimiter() {
  buckets.clear();
}

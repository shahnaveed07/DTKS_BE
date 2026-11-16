/**
 * DTKS Backend Constants & Allowed Domain Enums
 * Strictly scoped to Website Design, Development, Redesign, Hosting & Maintenance.
 */

export const API_PREFIX = '/api/v1';

// Supports both canonical backend statuses from specification and detailed frontend progress stages
export const VALID_ORDER_STATUSES = [
  'Pending',
  'New Request',
  'Reviewed',
  'Under Review',
  'Requirements Clarification',
  'Quotation Sent',
  'Awaiting Customer Approval',
  'Approved',
  'InProgress',
  'In Progress',
  'Under Testing',
  'Completed',
  'Rejected',
  'Cancelled',
];

export const VALID_CONTACT_STATUSES = [
  'New',
  'Read',
  'In Review',
  'Replied',
  'Archived',
];

export const VALID_ADMIN_ROLES = [
  'super_admin',
  'admin',
  'editor',
];

export const PENDING_INVITE_PASSWORD_SENTINEL = '!PENDING_INVITE_SETUP';

export const ADMIN_INVITE_EXPIRY_SECONDS = 48 * 60 * 60; // 48 hours
export const ADMIN_PASSWORD_RESET_EXPIRY_SECONDS = 60 * 60; // 1 hour
export const CLIENT_EMAIL_VERIFICATION_EXPIRY_SECONDS = 24 * 60 * 60; // 24 hours
export const CLIENT_PASSWORD_RESET_EXPIRY_SECONDS = 60 * 60; // 1 hour
export const ORDER_TRACKING_TOKEN_EXPIRY_SECONDS = 90 * 24 * 60 * 60; // 90 days

export const ADMIN_ACCESS_COOKIE_NAME = 'dtks_access';
export const ADMIN_REFRESH_COOKIE_NAME = 'dtks_refresh';
export const ADMIN_CSRF_COOKIE_NAME = 'dtks_csrf';

export const CLIENT_ACCESS_COOKIE_NAME = 'dtks_client_access';
export const CLIENT_REFRESH_COOKIE_NAME = 'dtks_client_refresh';
export const CLIENT_CSRF_COOKIE_NAME = 'dtks_client_csrf';

export const CURRENT_TERMS_VERSION = '2026-01';
export const CURRENT_PRIVACY_VERSION = '2026-01';

export const DEFAULT_ADMIN_ACCOUNTS_PAGE = 1;
export const DEFAULT_ADMIN_ACCOUNTS_LIMIT = 20;
export const MAX_ADMIN_ACCOUNTS_LIMIT = 100;

export const QUOTATION_ORDER_STATUSES = [
  'Quotation Sent',
  'Awaiting Customer Approval',
  'Approved',
];

export const PROJECT_ORDER_STATUSES = [
  'Approved',
  'InProgress',
  'In Progress',
  'Under Testing',
  'Completed',
];

export const ALLOWED_IMAGE_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/webp',
];

export const ALLOWED_ASSET_FOLDERS = [
  'portfolio',
  'services',
  'team',
  'general',
];

export const MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB
export const MAX_MULTIPART_BODY_BYTES = 6 * 1024 * 1024; // 6 MB multipart ceiling
export const MAX_JSON_UPLOAD_BYTES = 8 * 1024 * 1024; // 8 MB JSON base64 ceiling
export const MAX_JSON_BODY_BYTES = 1 * 1024 * 1024;  // 1 MB

export const WEBSITE_CATEGORIES = [
  'Business & Corporate Websites',
  'Personal Portfolio Websites',
  'Landing Pages',
  'E-Commerce Websites',
  'Restaurant & Hotel Websites',
  'Educational Institution Websites',
  'Real Estate Websites',
  'Blog & News Websites',
  'Booking & Appointment Websites',
  'Custom Website Development',
];

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
export const CLIENT_EMAIL_VERIFICATION_EXPIRY_SECONDS = 24 * 60 * 60; // 24 hours
export const CLIENT_PASSWORD_RESET_EXPIRY_SECONDS = 60 * 60; // 1 hour

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

export const MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB
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

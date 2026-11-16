import { generateRandomId } from '../utils/crypto.js';
import {
  successResponse,
  errorResponse,
  parseJsonBody,
  safeJsonParse,
  sanitizeText,
} from '../utils/response.js';
import { isSafeUrl } from '../validators/schemas.js';
import { logAdminActivity } from '../services/auditService.js';
import { authenticateAdmin } from '../middleware/authMiddleware.js';
import { mapServiceRow } from './servicesController.js';
import { mapPackageRow } from './packagesController.js';
import { mapPortfolioRow } from './portfolioController.js';

const FORBIDDEN_SECRET_KEYS = [
  'jwtSecret',
  'jwt_secret',
  'apiKey',
  'api_key',
  'resendApiKey',
  'resend_api_key',
  'passwordHash',
  'password_hash',
  'databaseSecret',
  'privateKey',
];

const FORBIDDEN_PROTOTYPE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function sanitizeSettingValue(val, depth = 0) {
  if (depth > 4) return undefined;
  if (typeof val === 'string') return sanitizeText(val, 4000);
  if (typeof val === 'number' || typeof val === 'boolean' || val === null) return val;
  if (Array.isArray(val)) {
    return val
      .slice(0, 100)
      .map((item) => sanitizeSettingValue(item, depth + 1))
      .filter((v) => v !== undefined);
  }
  if (typeof val === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(val)) {
      if (
        FORBIDDEN_PROTOTYPE_KEYS.has(k) ||
        FORBIDDEN_SECRET_KEYS.includes(k) ||
        /secret|password|private_key|api_key/i.test(k)
      ) {
        continue;
      }
      const cleanVal = sanitizeSettingValue(v, depth + 1);
      if (cleanVal !== undefined) out[k] = cleanVal;
    }
    return out;
  }
  return undefined;
}

function stripSensitiveSettings(settingsObj = {}) {
  if (!settingsObj || typeof settingsObj !== 'object' || Array.isArray(settingsObj)) return {};
  const cleaned = {};
  for (const [key, val] of Object.entries(settingsObj)) {
    if (
      FORBIDDEN_PROTOTYPE_KEYS.has(key) ||
      FORBIDDEN_SECRET_KEYS.includes(key) ||
      /secret|password|private_key|api_key/i.test(key)
    ) {
      continue;
    }
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      cleaned[key] = stripSensitiveSettings(val);
    } else {
      cleaned[key] = val;
    }
  }
  return cleaned;
}

export async function getSiteSettings(request, env) {
  const row = await env.DB.prepare(
    'SELECT setting_value, updated_at FROM site_settings WHERE setting_key = ?'
  )
    .bind('general')
    .first();

  const rawSettings = safeJsonParse(row?.setting_value, {});
  const settings = stripSensitiveSettings(rawSettings);
  return successResponse({ settings }, 'Site settings fetched.');
}

export async function updateSiteSettings(request, env, admin) {
  const body = await parseJsonBody(request);
  const existingRow = await env.DB.prepare(
    'SELECT setting_value FROM site_settings WHERE setting_key = ?'
  )
    .bind('general')
    .first();

  const currentSettings = stripSensitiveSettings(safeJsonParse(existingRow?.setting_value, {}));
  const sanitizedPatch = sanitizeSettingValue(stripSensitiveSettings(body)) || {};
  const nextSettings = stripSensitiveSettings({
    ...currentSettings,
    ...sanitizedPatch,
  });

  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO site_settings (setting_key, setting_value, updated_at, updated_by_admin_id)
     VALUES ('general', ?, ?, ?)
     ON CONFLICT(setting_key) DO UPDATE SET
       setting_value = excluded.setting_value,
       updated_at = excluded.updated_at,
       updated_by_admin_id = excluded.updated_by_admin_id`
  )
    .bind(JSON.stringify(nextSettings), now, admin.id)
    .run();

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'UPDATE_SITE_SETTINGS',
    entityType: 'SiteSettings',
    entityId: 'general',
    details: 'Updated website settings and contact configuration',
    request,
  });

  return successResponse({ settings: nextSettings }, 'Website settings updated successfully.');
}

async function readSettingArray(env, key) {
  const row = await env.DB.prepare(
    'SELECT setting_value FROM site_settings WHERE setting_key = ?'
  )
    .bind(key)
    .first();
  const parsed = safeJsonParse(row?.setting_value, []);
  return Array.isArray(parsed) ? parsed : [];
}

async function writeSettingArray(env, key, arr, adminId) {
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO site_settings (setting_key, setting_value, updated_at, updated_by_admin_id)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(setting_key) DO UPDATE SET
       setting_value = excluded.setting_value,
       updated_at = excluded.updated_at,
       updated_by_admin_id = excluded.updated_by_admin_id`
  )
    .bind(key, JSON.stringify(arr), now, adminId || null)
    .run();
}

function normalizeTeamMemberOutput(member) {
  if (!member || typeof member !== 'object') return member;
  const sortOrder = Number(member.sortOrder ?? member.order ?? 1);
  return {
    ...member,
    sortOrder,
    order: sortOrder,
  };
}

export async function listTeamMembers(request, env) {
  const url = new URL(request.url);
  const wantsAll =
    url.searchParams.get('includeInactive') === 'true' ||
    url.searchParams.get('all') === 'true';

  let showAll = false;
  if (wantsAll) {
    const auth = await authenticateAdmin(request, env);
    if (auth.authenticated) {
      showAll = true;
    }
  }

  let team = (await readSettingArray(env, 'team_members')).map(normalizeTeamMemberOutput);
  if (!showAll) {
    team = team.filter((m) => m && m.visible !== false);
  }
  team.sort((a, b) => Number(a.sortOrder || 1) - Number(b.sortOrder || 1));
  return successResponse({ team }, 'Team members fetched.');
}

export async function createTeamMember(request, env, admin) {
  const body = await parseJsonBody(request);
  const fullName = sanitizeText(body.fullName ?? body.full_name, 160);
  if (!fullName || fullName.length < 2) {
    return errorResponse('Team member full name is required.', 400, 'VALIDATION_ERROR');
  }

  const avatarUrl = sanitizeText(body.avatarUrl || '', 2000);
  const linkedinUrl = sanitizeText(body.linkedinUrl || '', 500);
  const githubUrl = sanitizeText(body.githubUrl || '', 500);
  const websiteUrl = sanitizeText(body.websiteUrl || '', 500);
  const urlErrors = {};
  if (avatarUrl && !isSafeUrl(avatarUrl, { allowRelative: true, allowDataImage: true })) {
    urlErrors.avatarUrl = 'Avatar URL must be a valid HTTP(S) URL or internal asset path.';
  }
  if (linkedinUrl && !isSafeUrl(linkedinUrl, { allowRelative: false })) {
    urlErrors.linkedinUrl = 'LinkedIn URL must use HTTP or HTTPS.';
  }
  if (githubUrl && !isSafeUrl(githubUrl, { allowRelative: false })) {
    urlErrors.githubUrl = 'GitHub URL must use HTTP or HTTPS.';
  }
  if (websiteUrl && !isSafeUrl(websiteUrl, { allowRelative: false })) {
    urlErrors.websiteUrl = 'Website URL must use HTTP or HTTPS.';
  }
  if (Object.keys(urlErrors).length > 0) {
    return errorResponse('Team member URL validation failed.', 400, 'VALIDATION_ERROR', urlErrors);
  }

  const team = await readSettingArray(env, 'team_members');
  const maxOrder = team.reduce((max, m) => Math.max(max, Number(m.sortOrder ?? m.order ?? 0)), 0);
  const now = new Date().toISOString();
  const id = generateRandomId('team');
  const initials =
    sanitizeText(body.initials, 6) ||
    fullName
      .split(/\s+/)
      .slice(0, 2)
      .map((w) => w[0]?.toUpperCase() || '')
      .join('');
  const sortOrder = maxOrder + 1;

  const member = {
    id,
    fullName,
    role: sanitizeText(body.role || 'Full-Stack Web Developer', 120),
    title: sanitizeText(body.title || '', 200),
    bio: sanitizeText(body.bio || '', 1500),
    skills: Array.isArray(body.skills)
      ? body.skills.map((s) => sanitizeText(String(s || ''), 120)).filter(Boolean)
      : [],
    technologies: Array.isArray(body.technologies)
      ? body.technologies.map((t) => sanitizeText(String(t || ''), 120)).filter(Boolean)
      : [],
    avatarUrl,
    initials,
    linkedinUrl,
    githubUrl,
    websiteUrl,
    visible: body.visible !== false,
    isPlaceholder: Boolean(body.isPlaceholder),
    sortOrder,
    order: sortOrder,
    createdAt: now,
    updatedAt: now,
  };

  team.push(member);
  await writeSettingArray(env, 'team_members', team, admin.id);

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'CREATE_TEAM_MEMBER',
    entityType: 'TeamMember',
    entityId: id,
    details: `Added team member "${fullName}"`,
    request,
  });

  return successResponse({ member }, 'Team profile created.', 201);
}

export async function updateTeamMember(request, env, admin, id) {
  const team = await readSettingArray(env, 'team_members');
  const idx = team.findIndex((m) => m.id === id);
  if (idx < 0) {
    return errorResponse('Team member not found.', 404, 'NOT_FOUND');
  }

  const body = await parseJsonBody(request);
  const existing = team[idx];
  const nextFullName =
    body.fullName !== undefined || body.full_name !== undefined
      ? sanitizeText(body.fullName ?? body.full_name, 160)
      : existing.fullName;

  if (!nextFullName || nextFullName.length < 2) {
    return errorResponse('Team member full name must be at least 2 characters.', 400, 'VALIDATION_ERROR');
  }

  const rawSort = body.sortOrder ?? body.order;
  const sortOrder =
    rawSort !== undefined && Number.isFinite(Number(rawSort))
      ? Number(rawSort)
      : Number(existing.sortOrder ?? existing.order ?? idx + 1);

  const nextAvatarUrl =
    body.avatarUrl !== undefined ? sanitizeText(body.avatarUrl, 2000) : existing.avatarUrl || '';
  const nextLinkedinUrl =
    body.linkedinUrl !== undefined ? sanitizeText(body.linkedinUrl, 500) : existing.linkedinUrl || '';
  const nextGithubUrl =
    body.githubUrl !== undefined ? sanitizeText(body.githubUrl, 500) : existing.githubUrl || '';
  const nextWebsiteUrl =
    body.websiteUrl !== undefined ? sanitizeText(body.websiteUrl, 500) : existing.websiteUrl || '';

  const urlErrors = {};
  if (nextAvatarUrl && !isSafeUrl(nextAvatarUrl, { allowRelative: true, allowDataImage: true })) {
    urlErrors.avatarUrl = 'Avatar URL must be a valid HTTP(S) URL or internal asset path.';
  }
  if (nextLinkedinUrl && !isSafeUrl(nextLinkedinUrl, { allowRelative: false })) {
    urlErrors.linkedinUrl = 'LinkedIn URL must use HTTP or HTTPS.';
  }
  if (nextGithubUrl && !isSafeUrl(nextGithubUrl, { allowRelative: false })) {
    urlErrors.githubUrl = 'GitHub URL must use HTTP or HTTPS.';
  }
  if (nextWebsiteUrl && !isSafeUrl(nextWebsiteUrl, { allowRelative: false })) {
    urlErrors.websiteUrl = 'Website URL must use HTTP or HTTPS.';
  }
  if (Object.keys(urlErrors).length > 0) {
    return errorResponse('Team member URL validation failed.', 400, 'VALIDATION_ERROR', urlErrors);
  }

  const now = new Date().toISOString();
  const updated = {
    id,
    fullName: nextFullName,
    role: body.role !== undefined ? sanitizeText(body.role, 120) : existing.role || '',
    title: body.title !== undefined ? sanitizeText(body.title, 200) : existing.title || '',
    bio: body.bio !== undefined ? sanitizeText(body.bio, 1500) : existing.bio || '',
    skills: Array.isArray(body.skills)
      ? body.skills.map((s) => sanitizeText(String(s || ''), 120)).filter(Boolean)
      : Array.isArray(existing.skills)
      ? existing.skills
      : [],
    technologies: Array.isArray(body.technologies)
      ? body.technologies.map((t) => sanitizeText(String(t || ''), 120)).filter(Boolean)
      : Array.isArray(existing.technologies)
      ? existing.technologies
      : [],
    avatarUrl: nextAvatarUrl,
    initials:
      body.initials !== undefined ? sanitizeText(body.initials, 6) : existing.initials || '',
    linkedinUrl: nextLinkedinUrl,
    githubUrl: nextGithubUrl,
    websiteUrl: nextWebsiteUrl,
    visible: body.visible !== undefined ? Boolean(body.visible) : existing.visible !== false,
    isPlaceholder:
      body.isPlaceholder !== undefined ? Boolean(body.isPlaceholder) : Boolean(existing.isPlaceholder),
    sortOrder,
    order: sortOrder,
    createdAt: existing.createdAt || now,
    updatedAt: now,
  };
  team[idx] = updated;
  await writeSettingArray(env, 'team_members', team, admin.id);

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'UPDATE_TEAM_MEMBER',
    entityType: 'TeamMember',
    entityId: id,
    details: `Updated team member "${updated.fullName}"`,
    request,
  });

  return successResponse({ member: updated }, 'Team member updated.');
}

export async function deleteTeamMember(request, env, admin, id) {
  const team = await readSettingArray(env, 'team_members');
  const existing = team.find((m) => m.id === id);
  if (!existing) {
    return errorResponse('Team member not found.', 404, 'NOT_FOUND');
  }

  const filtered = team.filter((m) => m.id !== id);
  await writeSettingArray(env, 'team_members', filtered, admin.id);

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'DELETE_TEAM_MEMBER',
    entityType: 'TeamMember',
    entityId: id,
    details: `Removed team member "${existing.fullName}"`,
    request,
  });

  return successResponse({ deletedId: id }, 'Team member removed.');
}

export async function reorderTeamMember(request, env, admin, id) {
  const body = await parseJsonBody(request);
  const direction = body.direction === 'up' ? 'up' : 'down';

  const team = (await readSettingArray(env, 'team_members')).map(normalizeTeamMemberOutput);
  team.sort((a, b) => Number(a.sortOrder || 1) - Number(b.sortOrder || 1));
  const idx = team.findIndex((m) => m.id === id);
  if (idx < 0) {
    return errorResponse('Team member not found.', 404, 'NOT_FOUND');
  }

  const targetIdx = direction === 'up' ? idx - 1 : idx + 1;
  if (targetIdx >= 0 && targetIdx < team.length) {
    const [moved] = team.splice(idx, 1);
    team.splice(targetIdx, 0, moved);
    const now = new Date().toISOString();
    team.forEach((m, i) => {
      m.sortOrder = i + 1;
      m.order = i + 1;
      m.updatedAt = now;
    });
    await writeSettingArray(env, 'team_members', team, admin.id);
  }

  return successResponse({ team }, 'Team reordered.');
}

export async function listTestimonials(request, env) {
  const url = new URL(request.url);
  const wantsAll =
    url.searchParams.get('includeInactive') === 'true' ||
    url.searchParams.get('all') === 'true';

  let showAll = false;
  if (wantsAll) {
    const auth = await authenticateAdmin(request, env);
    if (auth.authenticated) {
      showAll = true;
    }
  }

  let testimonials = await readSettingArray(env, 'testimonials');
  if (!showAll) {
    testimonials = testimonials.filter((t) => t && t.isApproved !== false);
  }
  return successResponse({ testimonials }, 'Testimonials fetched.');
}

export async function createTestimonial(request, env, admin) {
  const body = await parseJsonBody(request);
  const clientName = sanitizeText(body.clientName ?? body.client_name, 160);
  const quote = sanitizeText(body.quote, 2000);
  if (!clientName || !quote) {
    return errorResponse('Client name and testimonial quote are required.', 400, 'VALIDATION_ERROR');
  }

  const testimonials = await readSettingArray(env, 'testimonials');
  const id = generateRandomId('testi');
  const now = new Date().toISOString();
  const testimonial = {
    id,
    clientName,
    clientRole: sanitizeText(body.clientRole || '', 120),
    companyName: sanitizeText(body.companyName || '', 160),
    quote,
    rating: Math.min(5, Math.max(1, Number(body.rating || 5))),
    projectSlug: sanitizeText(body.projectSlug || '', 160),
    isApproved: body.isApproved !== false,
    displayOrder: Number(body.displayOrder || testimonials.length + 1),
    createdAt: now,
  };

  testimonials.push(testimonial);
  await writeSettingArray(env, 'testimonials', testimonials, admin.id);

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'CREATE_TESTIMONIAL',
    entityType: 'Testimonial',
    entityId: id,
    details: `Added testimonial from ${clientName}`,
    request,
  });

  return successResponse({ testimonial }, 'Testimonial created.', 201);
}

export async function deleteTestimonial(request, env, admin, id) {
  const testimonials = await readSettingArray(env, 'testimonials');
  const filtered = testimonials.filter((t) => t.id !== id);
  await writeSettingArray(env, 'testimonials', filtered, admin.id);

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'DELETE_TESTIMONIAL',
    entityType: 'Testimonial',
    entityId: id,
    details: `Deleted testimonial ${id}`,
    request,
  });
  return successResponse({ deletedId: id }, 'Testimonial deleted.');
}

/**
 * Public Bootstrap Endpoint: returns all public website catalog & configuration data in one fast query.
 * Unauthenticated requests receive only active services, active packages, and published portfolio items.
 */
export async function getPublicBootstrap(request, env) {
  const url = new URL(request.url);
  const wantsAll =
    url.searchParams.get('includeInactive') === 'true' ||
    url.searchParams.get('all') === 'true';

  let showAll = false;
  if (wantsAll) {
    const auth = await authenticateAdmin(request, env);
    if (auth.authenticated) {
      showAll = true;
    }
  }

  const servicesSql = showAll
    ? 'SELECT * FROM services ORDER BY display_order ASC, created_at ASC'
    : 'SELECT * FROM services WHERE is_active = 1 ORDER BY display_order ASC, created_at ASC';
  const packagesSql = showAll
    ? 'SELECT * FROM packages ORDER BY display_order ASC, created_at ASC'
    : 'SELECT * FROM packages WHERE is_active = 1 ORDER BY display_order ASC, created_at ASC';
  const portfolioSql = showAll
    ? 'SELECT * FROM portfolio ORDER BY display_order ASC, created_at DESC'
    : 'SELECT * FROM portfolio WHERE is_published = 1 ORDER BY display_order ASC, created_at DESC';

  const [servicesRes, packagesRes, portfolioRes, settingsRows] = await Promise.all([
    env.DB.prepare(servicesSql).all(),
    env.DB.prepare(packagesSql).all(),
    env.DB.prepare(portfolioSql).all(),
    env.DB.prepare('SELECT setting_key, setting_value FROM site_settings').all(),
  ]);

  const settingsMap = {};
  for (const r of settingsRows.results || []) {
    settingsMap[r.setting_key] = safeJsonParse(r.setting_value, {});
  }

  const rawTeam = Array.isArray(settingsMap.team_members)
    ? settingsMap.team_members.map(normalizeTeamMemberOutput)
    : [];
  const rawTestimonials = Array.isArray(settingsMap.testimonials) ? settingsMap.testimonials : [];

  return successResponse(
    {
      services: (servicesRes.results || []).map(mapServiceRow),
      packages: (packagesRes.results || []).map(mapPackageRow),
      portfolio: (portfolioRes.results || []).map(mapPortfolioRow),
      team: showAll ? rawTeam : rawTeam.filter((m) => m && m.visible !== false),
      testimonials: showAll
        ? rawTestimonials
        : rawTestimonials.filter((t) => t && t.isApproved !== false),
      settings: stripSensitiveSettings(settingsMap.general || {}),
      addons: Array.isArray(settingsMap.addons) ? settingsMap.addons : [],
      maintenancePlans: Array.isArray(settingsMap.maintenance_plans)
        ? settingsMap.maintenance_plans
        : [],
    },
    'Public site bootstrap data loaded.'
  );
}

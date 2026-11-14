import { API_PREFIX } from '../config/constants.js';
import { isOriginAllowed } from '../config/cors.js';
import { applySecurityAndCorsHeaders } from '../middleware/securityHeaders.js';
import { checkRateLimit } from '../middleware/rateLimiter.js';
import { authenticateAdmin } from '../middleware/authMiddleware.js';
import { handleException } from '../middleware/errorHandler.js';
import { successResponse, errorResponse, parseJsonBody } from '../utils/response.js';
import { ensureDatabaseSeeded, resetAndReseedDatabase } from '../database/seed.js';
import { serveImageFromR2 } from '../services/storageService.js';

import {
  loginAdmin,
  logoutAdmin,
  refreshAdminToken,
  getAuthenticatedAdmin,
  changeAdminPassword,
  updateAdminProfile,
} from '../controllers/authController.js';
import {
  listServices,
  getServiceBySlugOrId,
  createService,
  updateService,
  deleteService,
} from '../controllers/servicesController.js';
import {
  listPackages,
  getPackageById,
  createPackage,
  updatePackage,
  deletePackage,
  updateMaintenancePlansConfig,
  updateAddonsConfig,
} from '../controllers/packagesController.js';
import {
  listPortfolio,
  getPortfolioBySlugOrId,
  createPortfolioProject,
  updatePortfolioProject,
  deletePortfolioProject,
  uploadPortfolioImage,
  deletePortfolioImage,
} from '../controllers/portfolioController.js';
import {
  createOrder,
  trackCustomerOrder,
  listOrders,
  getOrderById,
  updateOrderStatusOnly,
  updateOrderDetails,
  deleteOrder,
} from '../controllers/ordersController.js';
import {
  createContactMessage,
  listContactMessages,
  getContactMessageById,
  updateContactMessage,
  deleteContactMessage,
} from '../controllers/contactController.js';
import {
  getDashboardStats,
  getRecentOrders,
  getRecentMessages,
  getOrderAnalytics,
  listCustomers,
  getCustomerById,
  listActivityLogs,
  listNotifications,
} from '../controllers/dashboardController.js';
import {
  getSiteSettings,
  updateSiteSettings,
  listTeamMembers,
  createTeamMember,
  updateTeamMember,
  deleteTeamMember,
  reorderTeamMember,
  listTestimonials,
  createTestimonial,
  deleteTestimonial,
  getPublicBootstrap,
} from '../controllers/settingsController.js';

function matchPath(pattern, pathname) {
  const patternParts = pattern.split('/').filter(Boolean);
  const pathParts = pathname.split('/').filter(Boolean);
  if (patternParts.length !== pathParts.length) return null;

  const params = {};
  for (let i = 0; i < patternParts.length; i++) {
    if (patternParts[i].startsWith(':')) {
      params[patternParts[i].slice(1)] = decodeURIComponent(pathParts[i]);
    } else if (patternParts[i] !== pathParts[i]) {
      return null;
    }
  }
  return params;
}

export async function handleApiRequest(request, env) {
  const method = request.method.toUpperCase();
  const url = new URL(request.url);
  const pathname = url.pathname.replace(/\/+$/, '') || '/';

  // 1. CORS Origin Check
  const origin = request.headers.get('Origin');
  if (origin && !isOriginAllowed(origin, env)) {
    const forbidden = errorResponse('CORS origin is not permitted.', 403, 'CORS_ORIGIN_FORBIDDEN');
    return applySecurityAndCorsHeaders(forbidden, request, env);
  }

  // 2. Handle Preflight OPTIONS
  if (method === 'OPTIONS') {
    const preflight = new Response(null, { status: 204 });
    return applySecurityAndCorsHeaders(preflight, request, env);
  }

  // 3. General API Rate Limit Check
  const generalRate = checkRateLimit(request, 'generalApi');
  if (!generalRate.allowed) {
    return applySecurityAndCorsHeaders(generalRate.response, request, env);
  }

  try {
    // Ensure database is seeded idempotently
    await ensureDatabaseSeeded(env);

    let response = null;

    // Health check endpoint
    if (pathname === `${API_PREFIX}/health` && method === 'GET') {
      response = successResponse(
        {
          service: 'DTKS Backend API',
          status: 'healthy',
          version: '1.0.0',
        },
        'DTKS API is operational.'
      );
      return applySecurityAndCorsHeaders(response, request, env);
    }

    // Public Bootstrap endpoint
    if (pathname === `${API_PREFIX}/bootstrap` && method === 'GET') {
      response = await getPublicBootstrap(request, env);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    // Serve uploaded R2 assets: GET /api/v1/uploads/:folder/:filename
    if (pathname.startsWith(`${API_PREFIX}/uploads/`) && method === 'GET') {
      const key = pathname.slice(`${API_PREFIX}/uploads/`.length);
      const assetRes = await serveImageFromR2(env, key);
      if (!assetRes) {
        return applySecurityAndCorsHeaders(
          errorResponse('Uploaded asset not found.', 404, 'ASSET_NOT_FOUND'),
          request,
          env
        );
      }
      return applySecurityAndCorsHeaders(assetRes, request, env);
    }

    // ========================================================================
    // 1. AUTHENTICATION ROUTES (/api/v1/auth/*)
    // ========================================================================
    if (pathname === `${API_PREFIX}/auth/login` && method === 'POST') {
      const loginRate = checkRateLimit(request, 'authLogin');
      if (!loginRate.allowed) {
        return applySecurityAndCorsHeaders(loginRate.response, request, env);
      }
      response = await loginAdmin(request, env);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/auth/refresh` && method === 'POST') {
      response = await refreshAdminToken(request, env);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/auth/logout` && method === 'POST') {
      const auth = await authenticateAdmin(request, env);
      response = await logoutAdmin(request, env, auth.authenticated ? auth.admin : null);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/auth/me` && method === 'GET') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await getAuthenticatedAdmin(request, env, auth.admin);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/auth/profile` && (method === 'PATCH' || method === 'PUT')) {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await updateAdminProfile(request, env, auth.admin);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/auth/change-password` && method === 'POST') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await changeAdminPassword(request, env, auth.admin);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    // ========================================================================
    // 2. SERVICES ROUTES (/api/v1/services/*)
    // ========================================================================
    if (pathname === `${API_PREFIX}/services`) {
      if (method === 'GET') {
        response = await listServices(request, env);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'POST') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await createService(request, env, auth.admin);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    const serviceMatch = matchPath(`${API_PREFIX}/services/:slugOrId`, pathname);
    if (serviceMatch) {
      if (method === 'GET') {
        response = await getServiceBySlugOrId(request, env, serviceMatch.slugOrId);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'PUT' || method === 'PATCH') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await updateService(request, env, auth.admin, serviceMatch.slugOrId);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'DELETE') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await deleteService(request, env, auth.admin, serviceMatch.slugOrId);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    // ========================================================================
    // 3. PACKAGES ROUTES (/api/v1/packages/*)
    // ========================================================================
    if (pathname === `${API_PREFIX}/packages`) {
      if (method === 'GET') {
        response = await listPackages(request, env);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'POST') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await createPackage(request, env, auth.admin);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    if (pathname === `${API_PREFIX}/packages/config/maintenance` && method === 'PUT') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await updateMaintenancePlansConfig(request, env, auth.admin);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/packages/config/addons` && method === 'PUT') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await updateAddonsConfig(request, env, auth.admin);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    const packageMatch = matchPath(`${API_PREFIX}/packages/:id`, pathname);
    if (packageMatch) {
      if (method === 'GET') {
        response = await getPackageById(request, env, packageMatch.id);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'PUT' || method === 'PATCH') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await updatePackage(request, env, auth.admin, packageMatch.id);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'DELETE') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await deletePackage(request, env, auth.admin, packageMatch.id);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    // ========================================================================
    // 4. PORTFOLIO & R2 ASSET UPLOAD ROUTES (/api/v1/portfolio/*)
    // ========================================================================
    if (pathname === `${API_PREFIX}/portfolio/upload`) {
      if (method === 'POST') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await uploadPortfolioImage(request, env, auth.admin);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'DELETE') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        let key = url.searchParams.get('key') || '';
        if (!key) {
          const body = await parseJsonBody(request);
          key = body.key || '';
        }
        response = await deletePortfolioImage(request, env, auth.admin, key);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    if (pathname.startsWith(`${API_PREFIX}/portfolio/upload/`) && method === 'DELETE') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      const key = pathname.slice(`${API_PREFIX}/portfolio/upload/`.length);
      response = await deletePortfolioImage(request, env, auth.admin, key);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/portfolio`) {
      if (method === 'GET') {
        response = await listPortfolio(request, env);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'POST') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await createPortfolioProject(request, env, auth.admin);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    const portfolioMatch = matchPath(`${API_PREFIX}/portfolio/:slugOrId`, pathname);
    if (portfolioMatch) {
      if (method === 'GET') {
        response = await getPortfolioBySlugOrId(request, env, portfolioMatch.slugOrId);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'PUT' || method === 'PATCH') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await updatePortfolioProject(request, env, auth.admin, portfolioMatch.slugOrId);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'DELETE') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await deletePortfolioProject(request, env, auth.admin, portfolioMatch.slugOrId);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    // ========================================================================
    // 5. ORDERS ROUTES (/api/v1/orders/*)
    // ========================================================================
    if (pathname === `${API_PREFIX}/orders/track` && method === 'GET') {
      response = await trackCustomerOrder(request, env);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/orders`) {
      if (method === 'POST') {
        const subRate = checkRateLimit(request, 'publicSubmission');
        if (!subRate.allowed) return applySecurityAndCorsHeaders(subRate.response, request, env);
        response = await createOrder(request, env);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'GET') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await listOrders(request, env);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    const orderStatusMatch = matchPath(`${API_PREFIX}/orders/:id/status`, pathname);
    if (orderStatusMatch && (method === 'PATCH' || method === 'PUT')) {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await updateOrderStatusOnly(request, env, auth.admin, orderStatusMatch.id);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    const orderMatch = matchPath(`${API_PREFIX}/orders/:id`, pathname);
    if (orderMatch) {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);

      if (method === 'GET') {
        response = await getOrderById(request, env, orderMatch.id);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'PATCH' || method === 'PUT') {
        response = await updateOrderDetails(request, env, auth.admin, orderMatch.id);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'DELETE') {
        response = await deleteOrder(request, env, auth.admin, orderMatch.id);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    // ========================================================================
    // 6. CONTACT ROUTES (/api/v1/contact/*)
    // ========================================================================
    if (pathname === `${API_PREFIX}/contact`) {
      if (method === 'POST') {
        const subRate = checkRateLimit(request, 'publicSubmission');
        if (!subRate.allowed) return applySecurityAndCorsHeaders(subRate.response, request, env);
        response = await createContactMessage(request, env);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'GET') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await listContactMessages(request, env);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    const contactMatch = matchPath(`${API_PREFIX}/contact/:id`, pathname);
    if (contactMatch) {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);

      if (method === 'GET') {
        response = await getContactMessageById(request, env, contactMatch.id);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'PATCH' || method === 'PUT') {
        response = await updateContactMessage(request, env, auth.admin, contactMatch.id);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'DELETE') {
        response = await deleteContactMessage(request, env, auth.admin, contactMatch.id);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    // ========================================================================
    // 7. DASHBOARD, CUSTOMERS, LOGS & ADMIN ROUTES (/api/v1/admin/*, /api/v1/customers/*)
    // ========================================================================
    if (pathname === `${API_PREFIX}/admin/dashboard/stats` && method === 'GET') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await getDashboardStats(request, env);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/admin/dashboard/recent-orders` && method === 'GET') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await getRecentOrders(request, env);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/admin/dashboard/recent-messages` && method === 'GET') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await getRecentMessages(request, env);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/admin/dashboard/order-analytics` && method === 'GET') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await getOrderAnalytics(request, env);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/customers` && method === 'GET') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await listCustomers(request, env);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    const customerMatch = matchPath(`${API_PREFIX}/customers/:id`, pathname);
    if (customerMatch && method === 'GET') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await getCustomerById(request, env, customerMatch.id);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/admin/activity-logs` && method === 'GET') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await listActivityLogs(request, env);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/admin/notifications` && method === 'GET') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await listNotifications(request, env);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    if (pathname === `${API_PREFIX}/admin/reset-seed` && method === 'POST') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      await resetAndReseedDatabase(env, auth.admin);
      response = await getPublicBootstrap(request, env);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    // ========================================================================
    // 8. SETTINGS, TEAM & TESTIMONIALS (/api/v1/settings, /api/v1/team, /api/v1/testimonials)
    // ========================================================================
    if (pathname === `${API_PREFIX}/settings`) {
      if (method === 'GET') {
        response = await getSiteSettings(request, env);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'PUT' || method === 'PATCH') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await updateSiteSettings(request, env, auth.admin);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    if (pathname === `${API_PREFIX}/team`) {
      if (method === 'GET') {
        response = await listTeamMembers(request, env);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'POST') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await createTeamMember(request, env, auth.admin);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    const teamReorderMatch = matchPath(`${API_PREFIX}/team/:id/reorder`, pathname);
    if (teamReorderMatch && (method === 'PATCH' || method === 'POST')) {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await reorderTeamMember(request, env, auth.admin, teamReorderMatch.id);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    const teamMatch = matchPath(`${API_PREFIX}/team/:id`, pathname);
    if (teamMatch) {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      if (method === 'PUT' || method === 'PATCH') {
        response = await updateTeamMember(request, env, auth.admin, teamMatch.id);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'DELETE') {
        response = await deleteTeamMember(request, env, auth.admin, teamMatch.id);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    if (pathname === `${API_PREFIX}/testimonials`) {
      if (method === 'GET') {
        response = await listTestimonials(request, env);
        return applySecurityAndCorsHeaders(response, request, env);
      }
      if (method === 'POST') {
        const auth = await authenticateAdmin(request, env);
        if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
        response = await createTestimonial(request, env, auth.admin);
        return applySecurityAndCorsHeaders(response, request, env);
      }
    }

    const testimonialMatch = matchPath(`${API_PREFIX}/testimonials/:id`, pathname);
    if (testimonialMatch && method === 'DELETE') {
      const auth = await authenticateAdmin(request, env);
      if (!auth.authenticated) return applySecurityAndCorsHeaders(auth.response, request, env);
      response = await deleteTestimonial(request, env, auth.admin, testimonialMatch.id);
      return applySecurityAndCorsHeaders(response, request, env);
    }

    const notFound = errorResponse(
      `API endpoint ${method} ${pathname} not found.`,
      404,
      'ENDPOINT_NOT_FOUND'
    );
    return applySecurityAndCorsHeaders(notFound, request, env);
  } catch (err) {
    const errRes = handleException(err);
    return applySecurityAndCorsHeaders(errRes, request, env);
  }
}

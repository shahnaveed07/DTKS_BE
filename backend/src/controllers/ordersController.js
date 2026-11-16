import { generateRandomId, generateRandomToken, sha256Hex } from '../utils/crypto.js';
import { ORDER_TRACKING_TOKEN_EXPIRY_SECONDS } from '../config/constants.js';
import { successResponse, errorResponse, parseJsonBody, sanitizeText } from '../utils/response.js';
import {
  validateOrderSubmission,
  validateOrderStatus,
  validateOrderTrackInput,
} from '../validators/schemas.js';
import { logAdminActivity } from '../services/auditService.js';
import { notifyOrderCreated, notifyOrderStatusUpdated } from '../services/emailService.js';
import { resolveOptionalClientAuth } from '../middleware/authMiddleware.js';

export function mapOrderRow(row, { includeInternal = true } = {}) {
  if (!row) return null;
  const quotationAmount =
    row.quotation_amount !== null && row.quotation_amount !== undefined
      ? Number(row.quotation_amount)
      : null;

  const mapped = {
    id: row.id,
    order_number: row.order_number,
    orderNumber: row.order_number,
    referenceId: row.order_number,
    customer_id: row.customer_id || null,
    customerId: row.customer_id || null,
    service_id: row.service_id || null,
    serviceId: row.service_id || null,
    package_id: row.package_id || null,
    packageId: row.package_id || null,
    service: row.service_name,
    service_name: row.service_name,
    serviceName: row.service_name,
    package_title: row.package_title || '',
    packageTitle: row.package_title || '',
    project_name: row.project_name,
    projectName: row.project_name,
    business_name: row.business_name || '',
    businessName: row.business_name || '',
    customer_name: row.customer_name,
    customerName: row.customer_name,
    customer_email: row.customer_email,
    customerEmail: row.customer_email,
    customer_phone: row.customer_phone,
    customerPhone: row.customer_phone,
    customer_city: row.customer_city || '',
    customerCity: row.customer_city || '',
    project_description: row.project_description,
    projectDescription: row.project_description,
    required_pages: row.required_pages || '',
    requiredPages: row.required_pages || '',
    required_functionality: row.required_functionality || '',
    requiredFunctionality: row.required_functionality || '',
    reference_websites: row.reference_websites || '',
    referenceWebsites: row.reference_websites || '',
    preferred_design_style: row.preferred_design_style || '',
    preferredDesignStyle: row.preferred_design_style || '',
    required_integrations: row.required_integrations || '',
    requiredIntegrations: row.required_integrations || '',
    additional_instructions: row.additional_instructions || '',
    additionalInstructions: row.additional_instructions || '',
    domain_preference: row.domain_preference || 'Need domain advice',
    domainPreference: row.domain_preference || 'Need domain advice',
    hosting_preference: row.hosting_preference || 'Need advice',
    hostingPreference: row.hosting_preference || 'Need advice',
    hosting_notes: row.hosting_notes || '',
    hostingNotes: row.hosting_notes || '',
    maintenance_interest: row.maintenance_interest || 'Need more information',
    maintenanceInterest: row.maintenance_interest || 'Need more information',
    maintenance_plan_selected: row.maintenance_plan_selected || 'Undecided',
    maintenancePlanSelected: row.maintenance_plan_selected || 'Undecided',
    budget: row.budget,
    estimatedBudget: row.budget,
    expected_delivery_date: row.expected_delivery_date || '',
    expectedDeliveryDate: row.expected_delivery_date || '',
    expected_timeline: row.expected_timeline || '',
    expectedTimeline: row.expected_timeline || '',
    urgency: row.urgency || 'Standard',
    status: row.status,
    quotation_amount: quotationAmount,
    quotationAmount,
    quotation_currency: row.quotation_currency || 'INR',
    quotationCurrency: row.quotation_currency || 'INR',
    quotation_notes: row.quotation_notes || '',
    quotationNotes: row.quotation_notes || '',
    customer_update: row.customer_update || '',
    customerUpdate: row.customer_update || '',
    created_at: row.created_at,
    createdAt: row.created_at,
    updated_at: row.updated_at,
    updatedAt: row.updated_at,
  };

  if (includeInternal) {
    mapped.admin_notes = row.admin_notes || '';
    mapped.adminNotes = row.admin_notes || '';
    mapped.internalNotes = row.admin_notes || '';
  }

  return mapped;
}

async function generateNextOrderNumber(env) {
  const year = new Date().getFullYear();
  const prefix = `DKS-${year}-`;
  const rows = await env.DB.prepare(
    'SELECT order_number FROM orders WHERE order_number LIKE ? ORDER BY order_number DESC LIMIT 50'
  )
    .bind(`${prefix}%`)
    .all();

  let maxSeq = 0;
  for (const r of rows.results || []) {
    if (r.order_number && r.order_number.startsWith(prefix)) {
      const seq = Number.parseInt(r.order_number.slice(prefix.length), 10);
      if (!Number.isNaN(seq) && seq > maxSeq) {
        maxSeq = seq;
      }
    }
  }
  return `${prefix}${String(maxSeq + 1).padStart(4, '0')}`;
}

function mapTrackedOrderSummary(row, historyRows = []) {
  if (!row) return null;
  const quotationAmount =
    row.quotation_amount !== null && row.quotation_amount !== undefined
      ? Number(row.quotation_amount)
      : null;

  return {
    id: row.id,
    order_number: row.order_number,
    orderNumber: row.order_number,
    referenceId: row.order_number,
    service: row.service_name,
    service_name: row.service_name,
    serviceName: row.service_name,
    package_title: row.package_title || '',
    packageTitle: row.package_title || '',
    project_name: row.project_name,
    projectName: row.project_name,
    status: row.status,
    quotation_amount: quotationAmount,
    quotationAmount,
    quotation_currency: row.quotation_currency || 'INR',
    quotationCurrency: row.quotation_currency || 'INR',
    expected_delivery_date: row.expected_delivery_date || '',
    expectedDeliveryDate: row.expected_delivery_date || '',
    expected_timeline: row.expected_timeline || '',
    expectedTimeline: row.expected_timeline || '',
    urgency: row.urgency || 'Standard',
    customer_update: row.customer_update || '',
    customerUpdate: row.customer_update || '',
    created_at: row.created_at,
    createdAt: row.created_at,
    updated_at: row.updated_at,
    updatedAt: row.updated_at,
    statusHistory: (historyRows || []).map((h) => ({
      id: h.id,
      previous_status: h.previous_status,
      previousStatus: h.previous_status,
      new_status: h.new_status,
      newStatus: h.new_status,
      notes: h.notes,
      note: h.notes,
      created_at: h.created_at,
      createdAt: h.created_at,
      changedAt: h.created_at,
    })),
  };
}

export async function createOrder(request, env) {
  const { client: authClient, errorResponse: authCsrfError } = await resolveOptionalClientAuth(
    request,
    env
  );
  if (authCsrfError) {
    return authCsrfError;
  }

  const body = await parseJsonBody(request);
  const validation = validateOrderSubmission(body);
  if (!validation.isValid) {
    return errorResponse('Order validation failed.', 400, 'VALIDATION_ERROR', validation.errors);
  }

  const d = validation.data;
  const now = new Date().toISOString();

  // Strictly isolate guest submissions from existing verified client portals:
  // only authenticated verified clients attach orders to their customer_id.
  let orderCustomerId = null;
  if (authClient && authClient.customerId) {
    orderCustomerId = authClient.customerId;
    await env.DB.prepare(
      'UPDATE customers SET full_name = ?, phone = ?, city = ?, business_name = ?, updated_at = ? WHERE id = ?'
    )
      .bind(d.customerName, d.customerPhone, d.customerCity, d.businessName, now, orderCustomerId)
      .run();
  } else {
    const existingCustomer = await env.DB.prepare(
      'SELECT id FROM customers WHERE lower(email) = lower(?)'
    )
      .bind(d.customerEmail)
      .first();

    if (existingCustomer) {
      const linkedAccount = await env.DB.prepare(
        'SELECT id FROM customer_accounts WHERE customer_id = ? LIMIT 1'
      )
        .bind(existingCustomer.id)
        .first();
      if (!linkedAccount) {
        await env.DB.prepare(
          'UPDATE customers SET full_name = ?, phone = ?, city = ?, business_name = ?, updated_at = ? WHERE id = ?'
        )
          .bind(
            d.customerName,
            d.customerPhone,
            d.customerCity,
            d.businessName,
            now,
            existingCustomer.id
          )
          .run();
      }
    } else {
      const newCustomerId = generateRandomId('cust');
      try {
        await env.DB.prepare(
          `INSERT INTO customers (id, full_name, email, phone, city, business_name, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            newCustomerId,
            d.customerName,
            d.customerEmail,
            d.customerPhone,
            d.customerCity,
            d.businessName,
            now,
            now
          )
          .run();
      } catch (custErr) {
        if (!/UNIQUE constraint failed/i.test(String(custErr?.message || ''))) {
          throw custErr;
        }
      }
    }
  }

  // 2. Resolve service_id and package_id if valid foreign keys exist
  let resolvedServiceId = null;
  let resolvedServiceName = d.serviceName;
  if (d.serviceId) {
    const svcRow = await env.DB.prepare('SELECT id, title FROM services WHERE id = ? OR slug = ? LIMIT 1')
      .bind(d.serviceId, d.serviceId)
      .first();
    if (svcRow) {
      resolvedServiceId = svcRow.id;
      resolvedServiceName = d.serviceName || svcRow.title;
    }
  } else if (d.serviceName) {
    const svcRow = await env.DB.prepare(
      'SELECT id, title FROM services WHERE lower(title) = lower(?) OR lower(order_category) = lower(?) LIMIT 1'
    )
      .bind(d.serviceName, d.serviceName)
      .first();
    if (svcRow) {
      resolvedServiceId = svcRow.id;
    }
  }

  let resolvedPackageId = null;
  let resolvedPackageTitle = d.packageTitle;
  let packagePrice = null;
  if (d.packageId) {
    const pkgRow = await env.DB.prepare('SELECT id, name, price FROM packages WHERE id = ?')
      .bind(d.packageId)
      .first();
    if (pkgRow) {
      resolvedPackageId = pkgRow.id;
      resolvedPackageTitle = resolvedPackageTitle || pkgRow.name;
      packagePrice = pkgRow.price !== null ? Number(pkgRow.price) : null;
    }
  }

  // 3. Atomically insert order + order_items + initial order_status_history + tracking token
  const orderId = generateRandomId('ord');
  const initialStatus = 'Pending';
  const initialCustomerUpdate =
    'Your website development request has been received by DreamTech Kashmir Solutions and is queued for scope review.';
  const orderItemId = generateRandomId('item');
  const historyId = generateRandomId('hist');
  const trackingTokenId = generateRandomId('otok');
  const rawTrackingToken = generateRandomToken(32);
  const trackingTokenHash = await sha256Hex(rawTrackingToken);
  const trackingExpiresAt = new Date(
    Date.now() + ORDER_TRACKING_TOKEN_EXPIRY_SECONDS * 1000
  ).toISOString();

  let orderNumber = '';
  for (let attempt = 0; attempt < 5; attempt++) {
    const candidate = await generateNextOrderNumber(env);
    const suffixOffset =
      attempt === 0
        ? candidate
        : `${candidate.slice(0, -4)}${String(Number.parseInt(candidate.slice(-4), 10) + attempt).padStart(4, '0')}`;
    orderNumber = attempt === 0 ? candidate : suffixOffset;

    try {
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO orders
           (id, order_number, customer_id, service_id, package_id, service_name, package_title, project_name, business_name,
            customer_name, customer_email, customer_phone, customer_city, project_description, required_pages,
            required_functionality, reference_websites, preferred_design_style, required_integrations, additional_instructions,
            domain_preference, hosting_preference, hosting_notes, maintenance_interest, maintenance_plan_selected,
            budget, expected_delivery_date, expected_timeline, urgency, status, quotation_amount, quotation_currency,
            quotation_notes, customer_update, admin_notes, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          orderId,
          orderNumber,
          orderCustomerId,
          resolvedServiceId,
          resolvedPackageId,
          resolvedServiceName,
          resolvedPackageTitle,
          d.projectName,
          d.businessName,
          d.customerName,
          d.customerEmail,
          d.customerPhone,
          d.customerCity,
          d.projectDescription,
          d.requiredPages,
          d.requiredFunctionality,
          d.referenceWebsites,
          d.preferredDesignStyle,
          d.requiredIntegrations,
          d.additionalInstructions,
          d.domainPreference,
          d.hostingPreference,
          '',
          d.maintenanceInterest,
          d.maintenancePlanSelected,
          d.budget,
          d.expectedDeliveryDate,
          d.expectedTimeline,
          d.urgency,
          initialStatus,
          null,
          'INR',
          '',
          initialCustomerUpdate,
          '',
          now,
          now
        ),
        env.DB.prepare(
          `INSERT INTO order_items (id, order_id, item_type, title, description, quantity, unit_price, currency, created_at)
           VALUES (?, ?, 'package', ?, ?, 1, ?, 'INR', ?)`
        ).bind(
          orderItemId,
          orderId,
          resolvedPackageTitle || resolvedServiceName,
          d.projectDescription.slice(0, 300),
          packagePrice,
          now
        ),
        env.DB.prepare(
          `INSERT INTO order_status_history (id, order_id, previous_status, new_status, changed_by_admin_id, notes, created_at)
           VALUES (?, ?, NULL, ?, NULL, 'Customer submitted website order request', ?)`
        ).bind(historyId, orderId, initialStatus, now),
        env.DB.prepare(
          `INSERT INTO order_tracking_tokens (id, order_id, token_hash, expires_at, revoked_at, created_at, last_accessed_at)
           VALUES (?, ?, ?, ?, NULL, ?, NULL)`
        ).bind(trackingTokenId, orderId, trackingTokenHash, trackingExpiresAt, now),
      ]);
      break;
    } catch (insertErr) {
      if (
        attempt < 4 &&
        /UNIQUE constraint failed:\s*orders\.order_number/i.test(String(insertErr?.message || ''))
      ) {
        continue;
      }
      throw insertErr;
    }
  }

  const createdRow = await env.DB.prepare('SELECT * FROM orders WHERE id = ?').bind(orderId).first();
  const publicOrder = mapOrderRow(createdRow, { includeInternal: false });

  await notifyOrderCreated(env, publicOrder, { trackingToken: rawTrackingToken });

  return successResponse(
    {
      order: publicOrder,
      trackingToken: rawTrackingToken,
      trackingExpiresAt,
    },
    'Website order submitted successfully.',
    201
  );
}

export async function trackCustomerOrder(request, env) {
  const body = await parseJsonBody(request);
  const validation = validateOrderTrackInput(body);
  if (!validation.isValid) {
    return errorResponse(
      'A valid order tracking token is required.',
      400,
      'VALIDATION_ERROR',
      validation.errors
    );
  }

  const tokenHash = await sha256Hex(validation.data.token);
  const now = new Date().toISOString();

  const row = await env.DB.prepare(
    `SELECT o.*, ott.id AS tracking_token_id
     FROM order_tracking_tokens ott
     INNER JOIN orders o ON o.id = ott.order_id
     WHERE ott.token_hash = ?
       AND ott.revoked_at IS NULL
       AND julianday(ott.expires_at) > julianday(?)
     LIMIT 1`
  )
    .bind(tokenHash, now)
    .first();

  if (!row) {
    return errorResponse(
      'No active website order was found for the provided tracking token.',
      404,
      'ORDER_NOT_FOUND'
    );
  }

  await env.DB.prepare('UPDATE order_tracking_tokens SET last_accessed_at = ? WHERE id = ?')
    .bind(now, row.tracking_token_id)
    .run()
    .catch(() => {});

  const historyResult = await env.DB.prepare(
    'SELECT id, previous_status, new_status, notes, created_at FROM order_status_history WHERE order_id = ? ORDER BY created_at ASC'
  )
    .bind(row.id)
    .all();

  const order = mapTrackedOrderSummary(row, historyResult.results || []);
  return successResponse({ order }, 'Order tracking record retrieved.');
}

export async function listOrders(request, env) {
  const url = new URL(request.url);
  const status = url.searchParams.get('status');
  const service = url.searchParams.get('service') || url.searchParams.get('service_id');
  const search = (url.searchParams.get('search') || url.searchParams.get('q') || '').trim();

  let sql = 'SELECT * FROM orders';
  const conditions = [];
  const params = [];

  if (status && status !== 'All') {
    conditions.push('status = ?');
    params.push(status);
  }
  if (service && service !== 'All') {
    conditions.push('(service_name = ? OR service_id = ?)');
    params.push(service, service);
  }
  if (search) {
    conditions.push(
      '(order_number LIKE ? OR project_name LIKE ? OR customer_name LIKE ? OR customer_email LIKE ? OR business_name LIKE ?)'
    );
    const pattern = `%${search}%`;
    params.push(pattern, pattern, pattern, pattern, pattern);
  }

  if (conditions.length > 0) {
    sql += ` WHERE ${conditions.join(' AND ')}`;
  }
  sql += ' ORDER BY created_at DESC';

  const result = await env.DB.prepare(sql)
    .bind(...params)
    .all();

  const orders = (result.results || []).map((r) => mapOrderRow(r, { includeInternal: true }));
  return successResponse({ orders }, 'Orders retrieved successfully.');
}

export async function getOrderById(request, env, id) {
  const row = await env.DB.prepare('SELECT * FROM orders WHERE id = ? OR order_number = ? LIMIT 1')
    .bind(id, id)
    .first();

  if (!row) {
    return errorResponse('Order not found.', 404, 'NOT_FOUND');
  }

  const itemsResult = await env.DB.prepare('SELECT * FROM order_items WHERE order_id = ?')
    .bind(row.id)
    .all();
  const historyResult = await env.DB.prepare(
    'SELECT * FROM order_status_history WHERE order_id = ? ORDER BY created_at DESC'
  )
    .bind(row.id)
    .all();

  const order = mapOrderRow(row, { includeInternal: true });
  order.items = (itemsResult.results || []).map((item) => ({
    id: item.id,
    item_type: item.item_type,
    itemType: item.item_type,
    title: item.title,
    description: item.description,
    quantity: item.quantity,
    unit_price: item.unit_price,
    unitPrice: item.unit_price,
    currency: item.currency,
  }));
  order.statusHistory = (historyResult.results || []).map((h) => ({
    id: h.id,
    previous_status: h.previous_status,
    previousStatus: h.previous_status,
    new_status: h.new_status,
    newStatus: h.new_status,
    changed_by_admin_id: h.changed_by_admin_id,
    changedByAdminId: h.changed_by_admin_id,
    notes: h.notes,
    note: h.notes,
    created_at: h.created_at,
    createdAt: h.created_at,
    changedAt: h.created_at,
  }));

  return successResponse({ order }, 'Order details retrieved.');
}

export async function updateOrderStatusOnly(request, env, admin, id) {
  const existing = await env.DB.prepare('SELECT * FROM orders WHERE id = ? OR order_number = ? LIMIT 1')
    .bind(id, id)
    .first();

  if (!existing) {
    return errorResponse('Order not found.', 404, 'NOT_FOUND');
  }

  const body = await parseJsonBody(request);
  const statusCheck = validateOrderStatus(body.status);
  if (!statusCheck.isValid) {
    return errorResponse(statusCheck.error, 400, 'INVALID_STATUS');
  }

  const newStatus = statusCheck.status;
  const rawAdminNotes = body.adminNotes ?? body.admin_notes ?? body.internalNotes;
  const adminNotes =
    rawAdminNotes !== undefined ? sanitizeText(rawAdminNotes, 4000) : existing.admin_notes;

  const rawCustomerUpdate = body.customerUpdate ?? body.customer_update;
  const customerUpdate =
    rawCustomerUpdate !== undefined
      ? sanitizeText(rawCustomerUpdate, 2000)
      : existing.customer_update;

  const now = new Date().toISOString();
  await env.DB.prepare(
    'UPDATE orders SET status = ?, admin_notes = ?, customer_update = ?, updated_at = ? WHERE id = ?'
  )
    .bind(newStatus, adminNotes, customerUpdate, now, existing.id)
    .run();

  if (existing.status !== newStatus) {
    await env.DB.prepare(
      `INSERT INTO order_status_history (id, order_id, previous_status, new_status, changed_by_admin_id, notes, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        generateRandomId('hist'),
        existing.id,
        existing.status,
        newStatus,
        admin.id,
        sanitizeText(body.notes || rawCustomerUpdate || `Status changed to ${newStatus}`, 500),
        now
      )
      .run();
  }

  const updatedRow = await env.DB.prepare('SELECT * FROM orders WHERE id = ?').bind(existing.id).first();
  const historyResult = await env.DB.prepare(
    'SELECT * FROM order_status_history WHERE order_id = ? ORDER BY created_at ASC'
  )
    .bind(existing.id)
    .all();

  const updatedOrder = mapOrderRow(updatedRow, { includeInternal: true });
  updatedOrder.statusHistory = (historyResult.results || []).map((h) => ({
    id: h.id,
    previous_status: h.previous_status,
    previousStatus: h.previous_status,
    new_status: h.new_status,
    newStatus: h.new_status,
    changed_by_admin_id: h.changed_by_admin_id,
    changedByAdminId: h.changed_by_admin_id,
    notes: h.notes,
    note: h.notes,
    created_at: h.created_at,
    createdAt: h.created_at,
    changedAt: h.created_at,
  }));

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'UPDATE_ORDER_STATUS',
    entityType: 'Order',
    entityId: existing.id,
    details: `Order ${existing.order_number} status changed from "${existing.status}" to "${newStatus}"`,
    request,
  });

  await notifyOrderStatusUpdated(env, updatedOrder, existing.status);

  return successResponse({ order: updatedOrder }, 'Order status updated.');
}

export async function updateOrderDetails(request, env, admin, id) {
  const existing = await env.DB.prepare('SELECT * FROM orders WHERE id = ? OR order_number = ? LIMIT 1')
    .bind(id, id)
    .first();

  if (!existing) {
    return errorResponse('Order not found.', 404, 'NOT_FOUND');
  }

  const body = await parseJsonBody(request);
  let nextStatus = existing.status;
  if (body.status !== undefined) {
    const statusCheck = validateOrderStatus(body.status);
    if (!statusCheck.isValid) {
      return errorResponse(statusCheck.error, 400, 'INVALID_STATUS');
    }
    nextStatus = statusCheck.status;
  }

  let quotationAmount = existing.quotation_amount;
  const rawQuotationAmount =
    body.quotationAmount !== undefined ? body.quotationAmount : body.quotation_amount;
  if (rawQuotationAmount !== undefined) {
    if (rawQuotationAmount === null || rawQuotationAmount === '') {
      quotationAmount = null;
    } else {
      const num = Number(rawQuotationAmount);
      if (Number.isNaN(num) || num < 0) {
        return errorResponse('Quotation amount must be a non-negative number.', 400, 'VALIDATION_ERROR');
      }
      quotationAmount = num;
    }
  }

  const budget =
    body.estimatedBudget !== undefined
      ? sanitizeText(body.estimatedBudget, 160)
      : body.budget !== undefined
      ? sanitizeText(body.budget, 160)
      : existing.budget;

  const expectedDeliveryDate =
    body.expectedDeliveryDate !== undefined
      ? sanitizeText(body.expectedDeliveryDate, 60)
      : body.expected_delivery_date !== undefined
      ? sanitizeText(body.expected_delivery_date, 60)
      : existing.expected_delivery_date;

  const quotationNotes =
    body.quotationNotes !== undefined
      ? sanitizeText(body.quotationNotes, 2000)
      : body.quotation_notes !== undefined
      ? sanitizeText(body.quotation_notes, 2000)
      : existing.quotation_notes;

  const domainPreference =
    body.domainPreference !== undefined
      ? sanitizeText(body.domainPreference, 120)
      : body.domain_preference !== undefined
      ? sanitizeText(body.domain_preference, 120)
      : existing.domain_preference;

  const hostingPreference =
    body.hostingPreference !== undefined
      ? sanitizeText(body.hostingPreference, 120)
      : body.hosting_preference !== undefined
      ? sanitizeText(body.hosting_preference, 120)
      : existing.hosting_preference;

  const hostingNotes =
    body.hostingNotes !== undefined
      ? sanitizeText(body.hostingNotes, 2000)
      : body.hosting_notes !== undefined
      ? sanitizeText(body.hosting_notes, 2000)
      : existing.hosting_notes;

  const maintenanceInterest =
    body.maintenanceInterest !== undefined
      ? sanitizeText(body.maintenanceInterest, 120)
      : body.maintenance_interest !== undefined
      ? sanitizeText(body.maintenance_interest, 120)
      : existing.maintenance_interest;

  const maintenancePlanSelected =
    body.maintenancePlanSelected !== undefined
      ? sanitizeText(body.maintenancePlanSelected, 120)
      : body.maintenance_plan_selected !== undefined
      ? sanitizeText(body.maintenance_plan_selected, 120)
      : existing.maintenance_plan_selected;

  const customerUpdate =
    body.customerUpdate !== undefined
      ? sanitizeText(body.customerUpdate, 2000)
      : body.customer_update !== undefined
      ? sanitizeText(body.customer_update, 2000)
      : existing.customer_update;

  const adminNotes =
    body.internalNotes !== undefined
      ? sanitizeText(body.internalNotes, 4000)
      : body.adminNotes !== undefined
      ? sanitizeText(body.adminNotes, 4000)
      : body.admin_notes !== undefined
      ? sanitizeText(body.admin_notes, 4000)
      : existing.admin_notes;

  const now = new Date().toISOString();
  await env.DB.prepare(
    `UPDATE orders SET
       status = ?, budget = ?, expected_delivery_date = ?, quotation_amount = ?,
       quotation_notes = ?, domain_preference = ?, hosting_preference = ?,
       hosting_notes = ?, maintenance_interest = ?, maintenance_plan_selected = ?,
       customer_update = ?, admin_notes = ?, updated_at = ?
     WHERE id = ?`
  )
    .bind(
      nextStatus,
      budget,
      expectedDeliveryDate,
      quotationAmount,
      quotationNotes,
      domainPreference,
      hostingPreference,
      hostingNotes,
      maintenanceInterest,
      maintenancePlanSelected,
      customerUpdate,
      adminNotes,
      now,
      existing.id
    )
    .run();

  if (existing.status !== nextStatus) {
    await env.DB.prepare(
      `INSERT INTO order_status_history (id, order_id, previous_status, new_status, changed_by_admin_id, notes, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        generateRandomId('hist'),
        existing.id,
        existing.status,
        nextStatus,
        admin.id,
        customerUpdate || `Updated status to ${nextStatus}`,
        now
      )
      .run();
  }

  const updatedRow = await env.DB.prepare('SELECT * FROM orders WHERE id = ?').bind(existing.id).first();
  const updatedOrder = mapOrderRow(updatedRow, { includeInternal: true });

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'UPDATE_ORDER',
    entityType: 'Order',
    entityId: existing.id,
    details: `Updated order ${existing.order_number} (Status: ${nextStatus})`,
    request,
  });

  if (existing.status !== nextStatus) {
    await notifyOrderStatusUpdated(env, updatedOrder, existing.status);
  }

  return successResponse({ order: updatedOrder }, 'Order updated successfully.');
}

export async function deleteOrder(request, env, admin, id) {
  const existing = await env.DB.prepare('SELECT * FROM orders WHERE id = ? OR order_number = ? LIMIT 1')
    .bind(id, id)
    .first();

  if (!existing) {
    return errorResponse('Order not found.', 404, 'NOT_FOUND');
  }

  await env.DB.prepare('DELETE FROM orders WHERE id = ?').bind(existing.id).run();

  await logAdminActivity(env, {
    adminId: admin.id,
    action: 'DELETE_ORDER',
    entityType: 'Order',
    entityId: existing.id,
    details: `Deleted order ${existing.order_number} (${existing.project_name})`,
    request,
  });

  return successResponse({ deletedId: existing.id }, 'Order deleted successfully.');
}

import { QUOTATION_ORDER_STATUSES, PROJECT_ORDER_STATUSES } from '../config/constants.js';
import { successResponse, errorResponse } from '../utils/response.js';
import { mapOrderRow } from './ordersController.js';

function mapClientStatusHistory(rows = []) {
  return rows.map((h) => ({
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
  }));
}

export async function listClientOrders(request, env, client) {
  if (!client?.customerId) {
    return successResponse({ orders: [] }, 'Client orders retrieved.');
  }

  const url = new URL(request.url);
  const status = (url.searchParams.get('status') || '').trim();
  const search = (url.searchParams.get('search') || url.searchParams.get('q') || '').trim();

  const conditions = ['customer_id = ?'];
  const params = [client.customerId];

  if (status && status !== 'All') {
    conditions.push('status = ?');
    params.push(status);
  }
  if (search) {
    conditions.push('(order_number LIKE ? OR project_name LIKE ? OR service_name LIKE ?)');
    const pattern = `%${search}%`;
    params.push(pattern, pattern, pattern);
  }

  const sql = `SELECT * FROM orders WHERE ${conditions.join(' AND ')} ORDER BY created_at DESC`;
  const result = await env.DB.prepare(sql)
    .bind(...params)
    .all();

  const orders = (result.results || []).map((row) => mapOrderRow(row, { includeInternal: false }));
  return successResponse({ orders }, 'Client orders retrieved.');
}

export async function getClientOrderById(request, env, client, id) {
  if (!client?.customerId) {
    return errorResponse('Order not found.', 404, 'NOT_FOUND');
  }

  const row = await env.DB.prepare(
    'SELECT * FROM orders WHERE (id = ? OR order_number = ?) AND customer_id = ? LIMIT 1'
  )
    .bind(id, id, client.customerId)
    .first();

  if (!row) {
    return errorResponse('Order not found.', 404, 'NOT_FOUND');
  }

  const [itemsResult, historyResult] = await Promise.all([
    env.DB.prepare(
      'SELECT id, item_type, title, description, quantity, unit_price, currency, created_at FROM order_items WHERE order_id = ?'
    )
      .bind(row.id)
      .all(),
    env.DB.prepare(
      'SELECT id, previous_status, new_status, notes, created_at FROM order_status_history WHERE order_id = ? ORDER BY created_at ASC'
    )
      .bind(row.id)
      .all(),
  ]);

  const order = mapOrderRow(row, { includeInternal: false });
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
  order.statusHistory = mapClientStatusHistory(historyResult.results || []);

  return successResponse({ order }, 'Client order details retrieved.');
}

export async function listClientQuotations(request, env, client) {
  if (!client?.customerId) {
    return successResponse({ quotations: [] }, 'Client quotations retrieved.');
  }

  const placeholders = QUOTATION_ORDER_STATUSES.map(() => '?').join(', ');
  const sql = `
    SELECT id, order_number, project_name, service_name, package_title, budget,
           status, quotation_amount, quotation_currency, quotation_notes,
           expected_delivery_date, expected_timeline, customer_update,
           created_at, updated_at
    FROM orders
    WHERE customer_id = ?
      AND (
        quotation_amount IS NOT NULL
        OR quotation_notes != ''
        OR status IN (${placeholders})
      )
    ORDER BY updated_at DESC`;

  const result = await env.DB.prepare(sql)
    .bind(client.customerId, ...QUOTATION_ORDER_STATUSES)
    .all();

  const quotations = (result.results || []).map((row) => ({
    id: row.id,
    order_id: row.id,
    orderId: row.id,
    order_number: row.order_number,
    orderNumber: row.order_number,
    project_name: row.project_name,
    projectName: row.project_name,
    service_name: row.service_name,
    serviceName: row.service_name,
    package_title: row.package_title || '',
    packageTitle: row.package_title || '',
    estimated_budget: row.budget,
    estimatedBudget: row.budget,
    status: row.status,
    quotation_amount:
      row.quotation_amount !== null && row.quotation_amount !== undefined
        ? Number(row.quotation_amount)
        : null,
    quotationAmount:
      row.quotation_amount !== null && row.quotation_amount !== undefined
        ? Number(row.quotation_amount)
        : null,
    quotation_currency: row.quotation_currency || 'INR',
    quotationCurrency: row.quotation_currency || 'INR',
    quotation_notes: row.quotation_notes || '',
    quotationNotes: row.quotation_notes || '',
    expected_delivery_date: row.expected_delivery_date || '',
    expectedDeliveryDate: row.expected_delivery_date || '',
    expected_timeline: row.expected_timeline || '',
    expectedTimeline: row.expected_timeline || '',
    customer_update: row.customer_update || '',
    customerUpdate: row.customer_update || '',
    created_at: row.created_at,
    createdAt: row.created_at,
    updated_at: row.updated_at,
    updatedAt: row.updated_at,
  }));

  return successResponse({ quotations }, 'Client quotations retrieved.');
}

export async function listClientProjects(request, env, client) {
  if (!client?.customerId) {
    return successResponse({ projects: [] }, 'Client projects retrieved.');
  }

  const placeholders = PROJECT_ORDER_STATUSES.map(() => '?').join(', ');
  const sql = `
    SELECT id, order_number, project_name, business_name, service_id, service_name,
           package_id, package_title, status, domain_preference, hosting_preference,
           hosting_notes, maintenance_interest, maintenance_plan_selected,
           expected_delivery_date, expected_timeline, quotation_amount,
           quotation_currency, customer_update, created_at, updated_at
    FROM orders
    WHERE customer_id = ?
      AND status IN (${placeholders})
    ORDER BY updated_at DESC`;

  const result = await env.DB.prepare(sql)
    .bind(client.customerId, ...PROJECT_ORDER_STATUSES)
    .all();

  const projects = (result.results || []).map((row) => ({
    id: row.id,
    order_id: row.id,
    orderId: row.id,
    order_number: row.order_number,
    orderNumber: row.order_number,
    project_name: row.project_name,
    projectName: row.project_name,
    business_name: row.business_name || '',
    businessName: row.business_name || '',
    service_id: row.service_id || null,
    serviceId: row.service_id || null,
    service_name: row.service_name,
    serviceName: row.service_name,
    package_id: row.package_id || null,
    packageId: row.package_id || null,
    package_title: row.package_title || '',
    packageTitle: row.package_title || '',
    status: row.status,
    domain_preference: row.domain_preference || '',
    domainPreference: row.domain_preference || '',
    hosting_preference: row.hosting_preference || '',
    hostingPreference: row.hosting_preference || '',
    hosting_notes: row.hosting_notes || '',
    hostingNotes: row.hosting_notes || '',
    maintenance_interest: row.maintenance_interest || '',
    maintenanceInterest: row.maintenance_interest || '',
    maintenance_plan_selected: row.maintenance_plan_selected || '',
    maintenancePlanSelected: row.maintenance_plan_selected || '',
    expected_delivery_date: row.expected_delivery_date || '',
    expectedDeliveryDate: row.expected_delivery_date || '',
    expected_timeline: row.expected_timeline || '',
    expectedTimeline: row.expected_timeline || '',
    quotation_amount:
      row.quotation_amount !== null && row.quotation_amount !== undefined
        ? Number(row.quotation_amount)
        : null,
    quotationAmount:
      row.quotation_amount !== null && row.quotation_amount !== undefined
        ? Number(row.quotation_amount)
        : null,
    quotation_currency: row.quotation_currency || 'INR',
    quotationCurrency: row.quotation_currency || 'INR',
    customer_update: row.customer_update || '',
    customerUpdate: row.customer_update || '',
    created_at: row.created_at,
    createdAt: row.created_at,
    updated_at: row.updated_at,
    updatedAt: row.updated_at,
  }));

  return successResponse({ projects }, 'Client projects retrieved.');
}

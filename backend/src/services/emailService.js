import { logAdminActivity } from './auditService.js';

/**
 * Configurable Transactional Email Notification Service (Resend HTTP API)
 *
 * Standardized Secret & Config Names:
 *   - `RESEND_API_KEY` (also accepts legacy alias `EMAIL_PROVIDER_API_KEY`)
 *   - `EMAIL_FROM_ADDRESS` (also accepts alias `EMAIL_FROM`, default: `notifications@dreamtechkashmirsolutions.studio`)
 *   - `ADMIN_NOTIFICATION_EMAIL` (default: `contact@dreamtechkashmirsolutions.studio`)
 *   - `APP_URL` / `FRONTEND_URL` (default: `https://dreamtechkashmirsolutions.studio`)
 *
 * Delivery Integrity Guarantee:
 *   - Never reports `sent: true` when `RESEND_API_KEY` is unconfigured or when Resend returns an error.
 *   - Order & contact notifications remain non-blocking for public forms.
 *   - Auth-critical flows (client email verification, password reset, admin invitations) inspect
 *     `{ sent, status }` and keep accounts pending until delivery succeeds.
 *   - Audit logs record delivery metadata ONLY — never raw tokens, secrets, or passwords.
 */

export function getAppBaseUrl(env = {}) {
  const raw =
    env?.APP_URL ||
    env?.FRONTEND_URL ||
    (typeof process !== 'undefined' && (process.env?.APP_URL || process.env?.FRONTEND_URL)) ||
    'https://dreamtechkashmirsolutions.studio';
  return String(raw).trim().replace(/\/+$/, '');
}

export function isEmailProviderConfigured(env = {}) {
  const apiKey = (env?.RESEND_API_KEY || env?.EMAIL_PROVIDER_API_KEY || '').trim();
  return Boolean(apiKey && !apiKey.startsWith('re_replace_'));
}

export async function dispatchEmail(
  env,
  {
    recipientEmail,
    recipientType,
    subject,
    bodyText,
    eventType,
    relatedEntityId,
    skipExampleDomains = false,
  }
) {
  const apiKey = (env?.RESEND_API_KEY || env?.EMAIL_PROVIDER_API_KEY || '').trim();
  const fromAddress =
    env?.EMAIL_FROM_ADDRESS ||
    env?.EMAIL_FROM ||
    'notifications@dreamtechkashmirsolutions.studio';
  const fetchImpl = typeof env?.EMAIL_FETCH === 'function' ? env.EMAIL_FETCH : fetch;

  let status = 'skipped_unconfigured';
  let detailMessage = 'RESEND_API_KEY not configured; email not dispatched';
  let messageId = null;

  const isExampleDomain =
    recipientEmail &&
    (recipientEmail.endsWith('.example') || recipientEmail.endsWith('@example.com'));

  if (!apiKey || apiKey.startsWith('re_replace_')) {
    status = 'skipped_unconfigured';
    detailMessage = 'RESEND_API_KEY not configured; email not dispatched';
  } else if (!recipientEmail) {
    status = 'failed';
    detailMessage = 'Missing recipient email address';
  } else if (skipExampleDomains && isExampleDomain) {
    status = 'skipped_example_domain';
    detailMessage = 'Skipped dispatch to reserved example domain';
  } else {
    try {
      const fetchOptions = {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: `DreamTech Kashmir Solutions <${fromAddress}>`,
          to: [recipientEmail],
          subject,
          text: bodyText,
        }),
      };
      if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
        fetchOptions.signal = AbortSignal.timeout(10000);
      }
      const response = await fetchImpl('https://api.resend.com/emails', fetchOptions);

      if (response.ok) {
        const resJson = await response.json().catch(() => null);
        messageId = resJson?.id || null;
        status = 'sent';
        detailMessage = `Dispatched email to ${recipientEmail}`;
      } else {
        const errBody = await response.text().catch(() => '');
        status = 'failed';
        detailMessage = `Resend API returned HTTP ${response.status}${errBody ? `: ${errBody.slice(0, 200)}` : ''}`;
      }
    } catch (err) {
      status = 'failed';
      detailMessage = err?.message || 'Network error while contacting Resend API';
    }
  }

  await logAdminActivity(env, {
    adminId: null,
    action: `EMAIL_NOTIFICATION_${eventType}`,
    entityType: recipientType === 'admin' ? 'AdminNotification' : 'CustomerNotification',
    entityId: relatedEntityId || '',
    details: JSON.stringify({
      recipientEmail,
      subject,
      status,
      ...(messageId ? { messageId } : {}),
      note: detailMessage,
    }),
  });

  return {
    sent: status === 'sent',
    status,
    detailMessage,
    messageId,
  };
}

export async function notifyOrderCreated(env, order, { trackingToken = null } = {}) {
  const adminEmail = env?.ADMIN_NOTIFICATION_EMAIL || 'contact@dreamtechkashmirsolutions.studio';
  const orderNumber = order.orderNumber || order.order_number || order.referenceId;
  const appUrl = getAppBaseUrl(env);
  const trackingLine = trackingToken
    ? `Track your project status securely anytime using your private tracking link:\n${appUrl}/track-order#token=${encodeURIComponent(trackingToken)}`
    : `You can track your project status anytime from your DTKS Client Portal at ${appUrl}/client/orders.`;

  await dispatchEmail(env, {
    recipientEmail: order.customerEmail || order.customer_email,
    recipientType: 'customer',
    subject: `[DTKS] Website Order Received — Reference ${orderNumber}`,
    bodyText: [
      `Hello ${order.customerName || order.customer_name},`,
      '',
      `Thank you for submitting your website development order with DreamTech Kashmir Solutions (DTKS).`,
      `Order Number: ${orderNumber}`,
      `Website Category: ${order.service || order.service_name || 'Website Development'}`,
      `Selected Package: ${order.packageTitle || 'Custom Website Quote'}`,
      `Current Status: ${order.status}`,
      '',
      trackingLine,
      '',
      `Keep your private tracking link safe and do not share it publicly.`,
      '',
      `Best regards,`,
      `DreamTech Kashmir Solutions (DTKS)`,
    ].join('\n'),
    eventType: 'ORDER_RECEIVED_CUSTOMER',
    relatedEntityId: order.id,
    skipExampleDomains: true,
  });

  await dispatchEmail(env, {
    recipientEmail: adminEmail,
    recipientType: 'admin',
    subject: `[DTKS Admin] New Website Order ${orderNumber} from ${order.customerName || order.customer_name}`,
    bodyText: [
      `A new website development order has been submitted on DTKS:`,
      `Order Number: ${orderNumber}`,
      `Customer: ${order.customerName || order.customer_name} (${order.customerEmail || order.customer_email} | ${order.customerPhone || order.customer_phone})`,
      `Budget: ${order.budget || order.estimatedBudget}`,
      `Description: ${order.projectDescription || order.project_description}`,
    ].join('\n'),
    eventType: 'ORDER_RECEIVED_ADMIN',
    relatedEntityId: order.id,
    skipExampleDomains: true,
  });
}

export async function notifyOrderStatusUpdated(env, order, previousStatus, { trackingToken = null } = {}) {
  const customerEmail = order?.customerEmail || order?.customer_email;
  const orderNumber = order?.orderNumber || order?.order_number || order?.referenceId;
  if (!customerEmail || order.status === previousStatus) return;
  const appUrl = getAppBaseUrl(env);
  const trackingLine = trackingToken
    ? `Track full details at ${appUrl}/track-order#token=${encodeURIComponent(trackingToken)}`
    : `View full details in your DTKS Client Portal at ${appUrl}/client/orders or via your private order tracking link.`;

  await dispatchEmail(env, {
    recipientEmail: customerEmail,
    recipientType: 'customer',
    subject: `[DTKS] Order ${orderNumber} Status Updated to "${order.status}"`,
    bodyText: [
      `Hello ${order.customerName || order.customer_name},`,
      '',
      `Your website development order (${orderNumber}) has been updated.`,
      `Previous Status: ${previousStatus}`,
      `New Status: ${order.status}`,
      ...(order.quotationAmount ? [`Quotation Amount: INR ${order.quotationAmount}`] : []),
      ...(order.customerUpdate ? [`Team Update: ${order.customerUpdate}`] : []),
      '',
      trackingLine,
      '',
      `DreamTech Kashmir Solutions (DTKS)`,
    ].join('\n'),
    eventType: 'ORDER_STATUS_UPDATED_CUSTOMER',
    relatedEntityId: order.id,
    skipExampleDomains: true,
  });
}

export async function notifyContactSubmitted(env, inquiry) {
  const adminEmail = env?.ADMIN_NOTIFICATION_EMAIL || 'contact@dreamtechkashmirsolutions.studio';

  await dispatchEmail(env, {
    recipientEmail: adminEmail,
    recipientType: 'admin',
    subject: `[DTKS Admin] New Contact Message: ${inquiry.subject}`,
    bodyText: [
      `New contact message received on DreamTech Kashmir Solutions:`,
      `From: ${inquiry.name} (${inquiry.email}${inquiry.phone ? ` | ${inquiry.phone}` : ''})`,
      `Subject: ${inquiry.subject}`,
      '',
      inquiry.message,
    ].join('\n'),
    eventType: 'CONTACT_RECEIVED_ADMIN',
    relatedEntityId: inquiry.id,
    skipExampleDomains: true,
  });
}

export async function sendClientVerificationEmail(
  env,
  { accountId, email, fullName, verificationToken, expiresHours = 24 }
) {
  const appUrl = getAppBaseUrl(env);
  const verifyUrl = `${appUrl}/verify-email#token=${encodeURIComponent(verificationToken)}`;

  return dispatchEmail(env, {
    recipientEmail: email,
    recipientType: 'customer',
    subject: '[DTKS] Verify your DreamTech Kashmir Solutions client account',
    bodyText: [
      `Hello ${fullName},`,
      '',
      `Thank you for registering for a DreamTech Kashmir Solutions (DTKS) client account.`,
      `Please verify your email address using the link below within ${expiresHours} hours to activate your account:`,
      '',
      verifyUrl,
      '',
      `If you did not create this account, you can safely ignore this email.`,
      '',
      `DreamTech Kashmir Solutions (DTKS)`,
    ].join('\n'),
    eventType: 'CLIENT_EMAIL_VERIFICATION',
    relatedEntityId: accountId,
    skipExampleDomains: false,
  });
}

export async function sendClientPasswordResetEmail(
  env,
  { accountId, email, fullName, resetToken, expiresMinutes = 60 }
) {
  const appUrl = getAppBaseUrl(env);
  const resetUrl = `${appUrl}/reset-password#token=${encodeURIComponent(resetToken)}`;

  return dispatchEmail(env, {
    recipientEmail: email,
    recipientType: 'customer',
    subject: '[DTKS] Reset your client account password',
    bodyText: [
      `Hello ${fullName},`,
      '',
      `We received a request to reset the password for your DTKS client account.`,
      `Use the single-use link below within ${expiresMinutes} minutes to set a new password:`,
      '',
      resetUrl,
      '',
      `If you did not request a password reset, no action is needed and your current password remains unchanged.`,
      '',
      `DreamTech Kashmir Solutions (DTKS)`,
    ].join('\n'),
    eventType: 'CLIENT_PASSWORD_RESET',
    relatedEntityId: accountId,
    skipExampleDomains: false,
  });
}

export async function sendClientSecurityNotificationEmail(
  env,
  { accountId, email, fullName, eventTitle, eventDescription }
) {
  return dispatchEmail(env, {
    recipientEmail: email,
    recipientType: 'customer',
    subject: `[DTKS Security] ${eventTitle}`,
    bodyText: [
      `Hello ${fullName},`,
      '',
      eventDescription,
      '',
      `Timestamp: ${new Date().toISOString()}`,
      `If you did not authorize this change, please contact DreamTech Kashmir Solutions immediately.`,
      '',
      `DreamTech Kashmir Solutions (DTKS)`,
    ].join('\n'),
    eventType: 'CLIENT_SECURITY_ALERT',
    relatedEntityId: accountId,
    skipExampleDomains: false,
  });
}

export async function sendAdminInvitationEmail(
  env,
  { adminId, email, name, role, inviteToken, expiresHours = 48, invitedByName = 'Super Administrator' }
) {
  const appUrl = getAppBaseUrl(env);
  const inviteUrl = `${appUrl}/admin/accept-invite#token=${encodeURIComponent(inviteToken)}`;

  return dispatchEmail(env, {
    recipientEmail: email,
    recipientType: 'admin',
    subject: `[DTKS Admin] You have been invited as ${role} on DreamTech Kashmir Solutions`,
    bodyText: [
      `Hello ${name},`,
      '',
      `${invitedByName} has invited you to join the DreamTech Kashmir Solutions (DTKS) administration workspace with the role "${role}".`,
      `Use the single-use invitation link below within ${expiresHours} hours to set your password and activate your account:`,
      '',
      inviteUrl,
      '',
      `If you were not expecting this invitation, please contact the DTKS principal administrator.`,
      '',
      `DreamTech Kashmir Solutions (DTKS)`,
    ].join('\n'),
    eventType: 'ADMIN_INVITATION',
    relatedEntityId: adminId,
    skipExampleDomains: false,
  });
}

export async function sendAdminPasswordResetEmail(
  env,
  { adminId, email, name, resetToken, expiresMinutes = 60 }
) {
  const appUrl = getAppBaseUrl(env);
  const contactEmail = env?.ADMIN_NOTIFICATION_EMAIL || 'contact@dreamtechkashmirsolutions.studio';
  const resetUrl = `${appUrl}/admin/reset-password#token=${encodeURIComponent(resetToken)}`;

  return dispatchEmail(env, {
    recipientEmail: email,
    recipientType: 'admin',
    subject: '[DTKS Admin] Reset your administrator password',
    bodyText: [
      `Hello ${name},`,
      '',
      `We received a request to reset the password for your DreamTech Kashmir Solutions (DTKS) administrator account.`,
      `Use the single-use administrator password reset link below within ${expiresMinutes} minutes to set a new password:`,
      '',
      resetUrl,
      '',
      `Security Notice: Never share this reset link with anyone. If you did not request an administrator password reset, you can safely ignore this email (your current password remains unchanged) and notify the DTKS principal administrator at ${contactEmail}.`,
      '',
      `DreamTech Kashmir Solutions (DTKS)`,
      `Website: ${appUrl}`,
      `Contact: ${contactEmail}`,
    ].join('\n'),
    eventType: 'ADMIN_PASSWORD_RESET',
    relatedEntityId: adminId,
    skipExampleDomains: false,
  });
}

export async function sendAdminSecurityNotificationEmail(
  env,
  { adminId, email, name, eventTitle, eventDescription }
) {
  const appUrl = getAppBaseUrl(env);
  const contactEmail = env?.ADMIN_NOTIFICATION_EMAIL || 'contact@dreamtechkashmirsolutions.studio';

  return dispatchEmail(env, {
    recipientEmail: email,
    recipientType: 'admin',
    subject: `[DTKS Admin Security] ${eventTitle}`,
    bodyText: [
      `Hello ${name},`,
      '',
      eventDescription,
      '',
      `Timestamp: ${new Date().toISOString()}`,
      `If you did not authorize this administrator security change, please contact the DTKS principal administrator immediately at ${contactEmail}.`,
      '',
      `DreamTech Kashmir Solutions (DTKS)`,
      `Website: ${appUrl}`,
      `Contact: ${contactEmail}`,
    ].join('\n'),
    eventType: 'ADMIN_SECURITY_ALERT',
    relatedEntityId: adminId,
    skipExampleDomains: false,
  });
}

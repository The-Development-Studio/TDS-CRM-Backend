import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { Router } from 'express';
import { ObjectId } from 'mongodb';
import { Resend } from 'resend';
import { z } from 'zod';
import { config, requireConfig } from '../config.js';
import { getDatabase } from '../database.js';
import { asyncHandler, HttpError, parseObjectId, serializeDocument } from '../http.js';
import { createDocumentDownloadUrl } from '../objectStorage.js';
import { requireStaffAdmin } from '../staffAuth.js';

const invitationSchema = z.object({
  customer: z.object({
    customerCode: z.string().trim().min(1),
    companyName: z.string().trim().min(1),
    primaryContact: z.string().trim().default(''),
    email: z.string().trim().email()
  })
});
const acceptInvitationSchema = z.object({
  token: z.string().min(32),
  password: z.string().min(12).max(128)
});
const loginSchema = z.object({
  email: z.string().trim().email(),
  password: z.string().min(1).max(128)
});
const ticketSchema = z.object({
  subject: z.string().trim().min(4).max(160),
  category: z.enum(['Project', 'Billing', 'Technical Support', 'Access', 'Other']),
  priority: z.enum(['Low', 'Normal', 'High', 'Urgent']),
  description: z.string().trim().min(10).max(5000)
});

const sessionCookie = 'tds_customer_session';
const sessionDurationMs = 7 * 24 * 60 * 60 * 1000;
const invitationDurationMs = 48 * 60 * 60 * 1000;
const passwordKeyLength = 64;
const resend = new Resend(config.RESEND_API_KEY ?? 're_not_configured');

const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const hashPassword = (password: string, salt = randomBytes(16).toString('hex')) => ({
  salt,
  passwordHash: scryptSync(password, salt, passwordKeyLength).toString('hex')
});

const verifyPassword = (password: string, salt: string, passwordHash: string) => {
  const expected = Buffer.from(passwordHash, 'hex');
  const actual = scryptSync(password, salt, passwordKeyLength);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
};

const readSessionToken = (cookieHeader = '') => {
  const cookie = cookieHeader.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${sessionCookie}=`));
  return cookie ? cookie.slice(sessionCookie.length + 1) : '';
};

const setSessionCookie = (response: Parameters<Parameters<typeof asyncHandler>[0]>[1], token: string) => {
  response.cookie(sessionCookie, token, {
    httpOnly: true,
    secure: config.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/customer-portal',
    maxAge: sessionDurationMs
  });
};

const clearSessionCookie = (response: Parameters<Parameters<typeof asyncHandler>[0]>[1]) => {
  response.clearCookie(sessionCookie, {
    httpOnly: true,
    secure: config.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/customer-portal'
  });
};

const findPortalSession = async (cookieHeader = '') => {
  const token = readSessionToken(cookieHeader);
  if (!token) return null;

  const db = await getDatabase();
  const session = await db.collection('portal_sessions').findOne({
    tokenHash: hash(token),
    expiresAt: { $gt: new Date() }
  });
  if (!session) return null;

  const user = await db.collection('portal_users').findOne({
    _id: session.userId,
    active: true,
    customerId: session.customerId
  });
  if (!user) return null;

  return { customerId: String(session.customerId), email: user.email as string, tenantId: String(session.tenantId ?? user.tenantId ?? 'default') };
};

export const customerPortalRouter = Router();

customerPortalRouter.post('/invitations', requireStaffAdmin, asyncHandler(async (request, response) => {
  const values = invitationSchema.parse(request.body);
  const db = await getDatabase();
  const email = values.customer.email.trim().toLowerCase();
  if (!email) throw new HttpError(400, 'Add a customer email before sending a portal invitation');

  const apiKey = requireConfig('RESEND_API_KEY');
  const from = requireConfig('RESEND_FROM_EMAIL');
  const existingCustomer = await db.collection('customers').findOne({
    customerCode: values.customer.customerCode,
    tenantId: request.staffUser?.tenantId
  });
  const existingCustomerId = existingCustomer ? String(existingCustomer._id) : '';
  const existingUser = await db.collection('portal_users').findOne({ email });
  if (existingUser && existingCustomerId && String(existingUser.customerId) !== existingCustomerId) {
    throw new HttpError(409, 'This email already has portal access for another customer account');
  }
  if (existingUser && !existingCustomerId) {
    throw new HttpError(409, 'This email already has portal access for another customer account');
  }

  const now = new Date();
  await db.collection('customers').updateOne(
    { customerCode: values.customer.customerCode, tenantId: request.staffUser?.tenantId },
    {
      $set: {
        companyName: values.customer.companyName,
        primaryContact: values.customer.primaryContact,
        email,
        tenantId: request.staffUser?.tenantId,
        updatedAt: now
      },
      $setOnInsert: {
        customerCode: values.customer.customerCode,
        customerType: 'Enterprise',
        industry: 'SaaS & Cloud',
        phone: '',
        totalDealsValue: 0,
        activeContracts: 0,
        amcStatus: 'None',
        renewalDate: '',
        relationshipManager: '',
        city: '',
        createdAt: now
      }
    },
    { upsert: true }
  );
  const customer = await db.collection('customers').findOne({ customerCode: values.customer.customerCode, tenantId: request.staffUser?.tenantId });
  if (!customer) throw new HttpError(500, 'Could not create the customer portal account');
  const customerId = String(customer._id);
  if (existingUser && String(existingUser.customerId) !== customerId) {
    throw new HttpError(409, 'This email already has portal access for another customer account');
  }

  const rawToken = randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + invitationDurationMs);
  await db.collection('portal_invitations').updateOne(
    { email, customerId },
    {
      $set: {
        email,
        customerId,
        tenantId: request.staffUser?.tenantId,
        tokenHash: hash(rawToken),
        expiresAt,
        createdAt: new Date()
      }
    },
    { upsert: true }
  );

  const mailer = apiKey === config.RESEND_API_KEY ? resend : new Resend(apiKey);
  const result = await mailer.emails.send({
    from,
    to: email,
    subject: `Set up your ${String(customer.companyName)} customer portal`,
    html: `<p>You have been invited to the TDS customer portal for <strong>${String(customer.companyName).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char] ?? char)}</strong>.</p><p><a href="${config.CLIENT_ORIGIN.split(',')[0].trim()}/customer-portal?invite=${rawToken}">Accept invitation and set your password</a></p><p>This invitation expires in 48 hours. If you were not expecting it, you can ignore this message.</p>`
  });
  if (result.error) {
    await db.collection('portal_invitations').deleteOne({ tokenHash: hash(rawToken) });
    throw new HttpError(502, 'Could not send customer portal invitation');
  }

  response.status(202).json({ message: `Invitation sent to ${email}` });
}));

customerPortalRouter.post('/accept-invitation', asyncHandler(async (request, response) => {
  const values = acceptInvitationSchema.parse(request.body);
  const db = await getDatabase();
  const invitation = await db.collection('portal_invitations').findOne({
    tokenHash: hash(values.token),
    expiresAt: { $gt: new Date() }
  });
  if (!invitation) throw new HttpError(400, 'Invitation is invalid or has expired');

  const password = hashPassword(values.password);
  const now = new Date();
  await db.collection('portal_users').updateOne(
    { email: invitation.email },
    {
      $set: {
        email: invitation.email,
        customerId: invitation.customerId,
        tenantId: invitation.tenantId ?? 'default',
        ...password,
        active: true,
        updatedAt: now
      },
      $setOnInsert: { createdAt: now }
    },
    { upsert: true }
  );
  const user = await db.collection('portal_users').findOne({ email: invitation.email });
  if (user) await db.collection('portal_sessions').deleteMany({ userId: user._id });
  await db.collection('portal_invitations').deleteOne({ _id: invitation._id });
  response.status(201).json({ message: 'Customer portal account activated. You can now sign in.' });
}));

customerPortalRouter.post('/login', asyncHandler(async (request, response) => {
  const values = loginSchema.parse(request.body);
  const db = await getDatabase();
  const email = values.email.trim().toLowerCase();
  const attemptKey = hash(`${email}:${request.ip}`);
  const attempt = await db.collection('portal_login_attempts').findOne({
    key: attemptKey,
    expiresAt: { $gt: new Date() }
  });
  if (attempt && Number(attempt.count) >= 10) {
    throw new HttpError(429, 'Too many sign-in attempts. Try again in 15 minutes.');
  }

  const user = await db.collection('portal_users').findOne({ email, active: true });
  const valid = user && typeof user.salt === 'string' && typeof user.passwordHash === 'string' &&
    verifyPassword(values.password, user.salt, user.passwordHash);
  if (!valid) {
    const now = new Date();
    await db.collection('portal_login_attempts').updateOne(
      { key: attemptKey },
      {
        $set: { expiresAt: new Date(now.getTime() + 15 * 60 * 1000) },
        $setOnInsert: { key: attemptKey },
        $inc: { count: 1 }
      },
      { upsert: true }
    );
    throw new HttpError(401, 'Email or password is incorrect');
  }

  await db.collection('portal_login_attempts').deleteOne({ key: attemptKey });
  const token = randomBytes(32).toString('hex');
  const now = new Date();
  await db.collection('portal_sessions').insertOne({
    tokenHash: hash(token),
    userId: user._id,
    customerId: user.customerId,
    tenantId: user.tenantId ?? 'default',
    createdAt: now,
    expiresAt: new Date(now.getTime() + sessionDurationMs)
  });
  setSessionCookie(response, token);
  response.json({ data: { email: user.email } });
}));

customerPortalRouter.get('/session', asyncHandler(async (request, response) => {
  const session = await findPortalSession(request.header('cookie'));
  if (!session) {
    clearSessionCookie(response);
    throw new HttpError(401, 'Customer portal sign-in required');
  }
  const db = await getDatabase();
  const customer = await db.collection('customers').findOne({ _id: parseObjectId(session.customerId), tenantId: session.tenantId });
  if (!customer) throw new HttpError(401, 'Customer portal account is no longer active');
  response.json({ data: { email: session.email, customer: serializeDocument(customer) } });
}));

customerPortalRouter.post('/logout', asyncHandler(async (request, response) => {
  const token = readSessionToken(request.header('cookie'));
  if (token) {
    const db = await getDatabase();
    await db.collection('portal_sessions').deleteOne({ tokenHash: hash(token) });
  }
  clearSessionCookie(response);
  response.status(204).send();
}));

customerPortalRouter.get('/data', asyncHandler(async (request, response) => {
  const session = await findPortalSession(request.header('cookie'));
  if (!session) throw new HttpError(401, 'Customer portal sign-in required');
  const db = await getDatabase();
  const customerId = session.customerId;
  const tenantId = session.tenantId;
  const [projects, proposals, contracts, invoices, supportTickets, documents] = await Promise.all([
    db.collection('projects').find({ customerId, tenantId }).sort({ updatedAt: -1 }).limit(100).toArray(),
    db.collection('proposals').find({ customerId, tenantId }).sort({ updatedAt: -1 }).limit(100).toArray(),
    db.collection('contracts').find({ customerId, tenantId }).sort({ expiryDate: 1 }).limit(100).toArray(),
    db.collection('invoices').find({ customerId, tenantId }).sort({ issueDate: -1 }).limit(100).toArray(),
    db.collection('support_tickets').find({ customerId, tenantId }).sort({ updatedAt: -1 }).limit(100).toArray(),
    db.collection('documents').find({ customerId, tenantId, storageKey: { $type: 'string' } })
      .project({ appId: 1, name: 1, category: 1, mimeType: 1, size: 1, updatedAt: 1 })
      .sort({ updatedAt: -1 }).limit(100).toArray()
  ]);

  response.json({
    data: {
      projects: projects.map(serializeDocument),
      proposals: proposals.map(serializeDocument),
      contracts: contracts.map(serializeDocument),
      invoices: invoices.map(serializeDocument),
      supportTickets: supportTickets.map(serializeDocument),
      documents: documents.map(serializeDocument)
    }
  });
}));

customerPortalRouter.get('/documents/:id/download-url', asyncHandler(async (request, response) => {
  const session = await findPortalSession(request.header('cookie'));
  if (!session) throw new HttpError(401, 'Customer portal sign-in required');
  const id = String(request.params.id);
  const db = await getDatabase();
  const document = await db.collection('documents').findOne({
    customerId: session.customerId,
    tenantId: session.tenantId,
    $or: [{ appId: id }, ...(ObjectId.isValid(id) ? [{ _id: parseObjectId(id) }] : [])]
  });
  if (!document || typeof document.storageKey !== 'string') throw new HttpError(404, 'Document not found');
  const url = await createDocumentDownloadUrl(document.storageKey, String(document.name), String(document.mimeType));
  response.json({ data: { url } });
}));

customerPortalRouter.post('/tickets', asyncHandler(async (request, response) => {
  const session = await findPortalSession(request.header('cookie'));
  if (!session) throw new HttpError(401, 'Customer portal sign-in required');
  const values = ticketSchema.parse(request.body);
  const db = await getDatabase();
  const customer = await db.collection('customers').findOne({ _id: parseObjectId(session.customerId), tenantId: session.tenantId });
  if (!customer) throw new HttpError(401, 'Customer portal account is no longer active');

  const now = new Date();
  const ticket = {
    ticketNo: `TKT-${now.getFullYear()}-${randomBytes(3).toString('hex').toUpperCase()}`,
    customerId: session.customerId,
    tenantId: session.tenantId,
    customer: customer.companyName,
    createdBy: session.email,
    ...values,
    status: 'Open',
    createdAt: now,
    updatedAt: now
  };
  const result = await db.collection('support_tickets').insertOne(ticket);
  response.status(201).json({ data: serializeDocument({ ...ticket, _id: result.insertedId }) });
}));

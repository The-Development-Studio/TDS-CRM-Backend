import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import { getDatabase } from '../database.js';
import { asyncHandler, HttpError, serializeDocument } from '../http.js';
import { hashStaffSessionToken, requireStaffAdmin, staffSessionCookie } from '../staffAuth.js';

const themeSchema = z.object({
  primaryColor: z.string().regex(/^#[0-9a-f]{6}$/i),
  sidebarTone: z.enum(['light', 'dark']),
  density: z.enum(['comfortable', 'compact'])
});

const tenantSchema = z.object({
  name: z.string().trim().min(2).max(120),
  slug: z.string().trim().toLowerCase().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/).max(48),
  status: z.enum(['Active', 'Suspended']).default('Active'),
  logoDataUrl: z.union([
    z.string().max(700_000).regex(/^data:image\/(?:png|jpeg|webp|svg\+xml);base64,/),
    z.literal('')
  ]).optional().default(''),
  theme: themeSchema
});

const sessionToken = (cookieHeader = '') => cookieHeader.split(';').map((part) => part.trim())
  .find((part) => part.startsWith(`${staffSessionCookie}=`))?.slice(staffSessionCookie.length + 1);

export const tenantsRouter = Router();

tenantsRouter.get('/', asyncHandler(async (request, response) => {
  const db = await getDatabase();
  const tenantIds = request.staffUser?.tenantIds ?? ['default'];
  const tenants = await db.collection('organizations').find(
    { tenantId: { $in: tenantIds } },
    { projection: { legalName: 0, displayName: 0, bankAccountNumber: 0 } }
  ).sort({ name: 1 }).toArray();
  response.json({ data: tenants.map((tenant) => ({
    ...serializeDocument(tenant),
    id: String(tenant.tenantId)
  })) });
}));

tenantsRouter.post('/', requireStaffAdmin, asyncHandler(async (request, response) => {
  const values = tenantSchema.parse(request.body);
  const db = await getDatabase();
  if (await db.collection('organizations').findOne({ slug: values.slug })) {
    throw new HttpError(409, 'That workspace URL is already in use');
  }
  const tenantId = randomUUID();
  const now = new Date();
  await db.collection('organizations').insertOne({
    ...values,
    tenantId,
    organizationKey: tenantId,
    createdBy: request.staffUser?.id,
    createdAt: now,
    updatedAt: now
  });
  await db.collection('staff_users').updateOne(
    { _id: request.staffUser?.objectId },
    { $addToSet: { tenantIds: tenantId, tenantAdminIds: tenantId }, $set: { updatedAt: now } }
  );
  response.status(201).json({ data: { ...values, id: tenantId, tenantId } });
}));

tenantsRouter.put('/:tenantId', requireStaffAdmin, asyncHandler(async (request, response) => {
  const values = tenantSchema.parse(request.body);
  const tenantId = String(request.params.tenantId);
  if (!request.staffUser?.tenantIds.includes(tenantId)) throw new HttpError(403, 'Tenant access required');
  const db = await getDatabase();
  const duplicate = await db.collection('organizations').findOne({ slug: values.slug, tenantId: { $ne: tenantId } });
  if (duplicate) throw new HttpError(409, 'That workspace URL is already in use');
  const saved = await db.collection('organizations').findOneAndUpdate(
    { tenantId },
    { $set: { ...values, updatedAt: new Date() } },
    { returnDocument: 'after' }
  );
  if (!saved) throw new HttpError(404, 'Tenant not found');
  response.json({ data: { ...serializeDocument(saved), id: tenantId } });
}));

tenantsRouter.post('/:tenantId/activate', asyncHandler(async (request, response) => {
  const tenantId = String(request.params.tenantId);
  if (!request.staffUser?.tenantIds.includes(tenantId)) throw new HttpError(403, 'Tenant access required');
  const db = await getDatabase();
  const tenant = await db.collection('organizations').findOne({ tenantId, status: { $ne: 'Suspended' } });
  if (!tenant) throw new HttpError(404, 'Active tenant not found');
  const token = sessionToken(request.header('cookie'));
  if (!token) throw new HttpError(401, 'Staff sign-in required');
  await db.collection('staff_sessions').updateOne(
    { tokenHash: hashStaffSessionToken(token), userId: request.staffUser?.objectId },
    { $set: { activeTenantId: tenantId } }
  );
  response.json({ data: { id: tenantId, slug: tenant.slug, name: tenant.name } });
}));

tenantsRouter.delete('/:tenantId', requireStaffAdmin, asyncHandler(async (request, response) => {
  const tenantId = String(request.params.tenantId);
  if (tenantId === request.staffUser?.tenantId) throw new HttpError(409, 'Switch tenants before deleting this workspace');
  if (!request.staffUser?.tenantIds.includes(tenantId)) throw new HttpError(403, 'Tenant access required');
  const db = await getDatabase();
  await db.collection('organizations').updateOne(
    { tenantId },
    { $set: { status: 'Suspended', updatedAt: new Date() } }
  );
  response.status(204).send();
}));


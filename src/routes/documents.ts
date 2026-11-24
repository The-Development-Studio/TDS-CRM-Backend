import { Router } from 'express';
import { Filter, ObjectId } from 'mongodb';
import { z } from 'zod';
import { getDatabase } from '../database.js';
import { asyncHandler, HttpError, parseObjectId } from '../http.js';
import { createDocumentDownloadUrl, createDocumentUpload, confirmDocumentUpload, deleteStoredObject, validateDocumentSize } from '../objectStorage.js';
import { documentSchema } from '../schemas.js';

const uploadSchema = z.object({
  id: z.string().trim().min(1).max(160),
  name: z.string().trim().min(1).max(255),
  category: z.string().trim().min(1).max(80),
  client: z.string().trim().max(160).default('Internal'),
  mimeType: z.string().trim().min(1).max(160),
  size: z.number().int().positive().max(20 * 1024 * 1024)
});

const confirmSchema = z.object({ id: z.string().trim().min(1).max(160) });

export const documentsRouter = Router();

documentsRouter.get('/', asyncHandler(async (request, response) => {
  const db = await getDatabase();
  const limit = Math.min(Math.max(Number(request.query.limit) || 100, 1), 10000);
  const records = await db.collection('documents')
    .find({ tenantId: request.staffUser?.tenantId, storageKey: { $type: 'string' } })
    .sort({ updatedAt: -1 })
    .limit(limit)
    .toArray();
  response.json({ data: records.map((record) => ({
    id: record.appId ?? String(record._id),
    name: record.name,
    category: record.category,
    client: record.client ?? '',
    size: record.size,
    mimeType: record.mimeType,
    updatedAt: record.updatedAt,
    hasFile: true
  })), count: records.length });
}));

documentsRouter.post('/upload-url', asyncHandler(async (request, response) => {
  const values = uploadSchema.parse(request.body);
  validateDocumentSize(values.size);
  const db = await getDatabase();
  const existing = await db.collection('documents').findOne({ appId: values.id, tenantId: request.staffUser?.tenantId });
  if (existing && typeof existing.storageKey === 'string') throw new HttpError(409, 'A document with this ID already exists');

  let customerId = 'internal';
  if (values.client && values.client.toLowerCase() !== 'internal') {
    const escapedClient = values.client.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const customer = await db.collection('customers').findOne({
      tenantId: request.staffUser?.tenantId,
      $or: [
        { companyName: { $regex: `^${escapedClient}$`, $options: 'i' } },
        { customerCode: { $regex: `^${escapedClient}$`, $options: 'i' } }
      ]
    });
    if (customer) customerId = String(customer._id);
  }

  const { storageKey, uploadUrl } = await createDocumentUpload(values.mimeType, values.size);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await db.collection('document_uploads').updateOne(
    { appId: values.id, tenantId: request.staffUser?.tenantId },
    {
      $set: {
        appId: values.id,
        tenantId: request.staffUser?.tenantId,
        storageKey,
        name: values.name,
        category: values.category,
        client: values.client || 'Internal',
        customerId,
        mimeType: values.mimeType,
        size: values.size,
        uploadedBy: request.staffUser?.email ?? '',
        expiresAt
      }
    },
    { upsert: true }
  );
  response.status(201).json({ data: { id: values.id, uploadUrl } });
}));

documentsRouter.post('/confirm-upload', asyncHandler(async (request, response) => {
  const { id } = confirmSchema.parse(request.body);
  const db = await getDatabase();
  const pending = await db.collection('document_uploads').findOne({
    appId: id,
    tenantId: request.staffUser?.tenantId,
    expiresAt: { $gt: new Date() }
  });
  if (!pending) throw new HttpError(404, 'Document upload not found or expired');
  const storageKey = await confirmDocumentUpload(
    String(pending.storageKey),
    Number(pending.size),
    String(pending.mimeType)
  );
  const values = documentSchema.parse({
    customerId: pending.customerId,
    name: pending.name,
    category: pending.category,
    mimeType: pending.mimeType,
    size: pending.size,
    storageKey,
    uploadedBy: pending.uploadedBy,
    client: pending.client
  });
  const now = new Date();
  await db.collection('documents').updateOne(
    { appId: id, tenantId: request.staffUser?.tenantId },
    {
      $set: { ...values, appId: id, tenantId: request.staffUser?.tenantId, updatedAt: now },
      $setOnInsert: { createdAt: now }
    },
    { upsert: true }
  );
  await db.collection('document_uploads').deleteOne({ _id: pending._id });
  response.status(201).json({ data: { id, ...values, updatedAt: now } });
}));

documentsRouter.get('/:id/download-url', asyncHandler(async (request, response) => {
  const db = await getDatabase();
  const id = String(request.params.id);
  const document = await db.collection('documents').findOne({
    tenantId: request.staffUser?.tenantId,
    $or: [{ appId: id }, ...(ObjectId.isValid(id) ? [{ _id: parseObjectId(id) }] : [])]
  });
  if (!document || typeof document.storageKey !== 'string') throw new HttpError(404, 'Document not found');
  const url = await createDocumentDownloadUrl(document.storageKey, String(document.name), String(document.mimeType));
  response.json({ data: { url } });
}));

documentsRouter.delete('/:id', asyncHandler(async (request, response) => {
  const db = await getDatabase();
  const id = String(request.params.id);
  const filter: Filter<Record<string, unknown>> = {
    tenantId: request.staffUser?.tenantId,
    $or: [{ appId: id }, ...(ObjectId.isValid(id) ? [{ _id: parseObjectId(id) }] : [])]
  };
  const document = await db.collection('documents').findOne(filter);
  if (!document) throw new HttpError(404, 'Document not found');
  if (typeof document.storageKey === 'string') await deleteStoredObject(document.storageKey);
  await db.collection('documents').deleteOne(filter);
  response.status(204).send();
}));

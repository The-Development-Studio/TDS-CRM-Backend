import { Router } from 'express';
import { z } from 'zod';
import { getDatabase } from '../database.js';
import { asyncHandler, HttpError, serializeDocument } from '../http.js';
import { resourceSchemas } from '../schemas.js';
import { requireStaffAdmin, requireStaffPage, staffRoute } from '../staffAuth.js';

const importSchema = z.object({
  collections: z.record(
    z.string(),
    z.array(z.record(z.string(), z.unknown()).and(z.object({ id: z.string().trim().min(1).max(160) }))).max(1000)
  )
});

export const staffDataRouter = Router();

staffDataRouter.post('/import-local', requireStaffAdmin, asyncHandler(async (request, response) => {
  const { collections } = importSchema.parse(request.body);
  const db = await getDatabase();
  const results: Record<string, number> = {};

  for (const [name, records] of Object.entries(collections)) {
    if (!(name in resourceSchemas)) throw new HttpError(400, `Unsupported collection: ${name}`);
    const resource = name as keyof typeof resourceSchemas;
    const schema = resourceSchemas[resource];
    const prepared = records.map(({ id, ...record }) => ({
      id,
      values: schema.parse(record) as Record<string, unknown>
    }));
    const operations = prepared.map(({ id, values }) => ({
      updateOne: {
        filter: { appId: id },
        update: {
          $setOnInsert: { ...values, appId: id, createdAt: new Date(), updatedAt: new Date() }
        },
        upsert: true
      }
    }));
    if (operations.length) {
      const result = await db.collection(resource).bulkWrite(operations);
      results[name] = result.upsertedCount;
    } else {
      results[name] = 0;
    }
  }

  response.status(201).json({ imported: results });
}));

staffDataRouter.get('/organization', staffRoute, asyncHandler(async (_request, response) => {
  const db = await getDatabase();
  const organization = await db.collection('organizations').findOne({ organizationKey: 'default' });
  response.json({ data: organization ? serializeDocument(organization) : null });
}));

staffDataRouter.put('/organization', requireStaffPage('org-setup'), asyncHandler(async (request, response) => {
  const {
    id: _id,
    _id: _mongoId,
    organizationKey: _organizationKey,
    createdAt: _createdAt,
    updatedAt: _updatedAt,
    ...editableOrganization
  } = request.body as Record<string, unknown>;
  const organization = resourceSchemas.organizations.parse({
    ...editableOrganization,
    organizationKey: 'default'
  }) as Record<string, unknown>;
  const db = await getDatabase();
  const saved = await db.collection('organizations').findOneAndUpdate(
    { organizationKey: 'default' },
    { $set: { ...organization, updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } },
    { upsert: true, returnDocument: 'after' }
  );
  response.json({ data: serializeDocument(saved) });
}));

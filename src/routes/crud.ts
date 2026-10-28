import { Router } from 'express';
import { Db, Filter, ObjectId } from 'mongodb';
import { z } from 'zod';
import { getDatabase } from '../database.js';
import { asyncHandler, HttpError, parseObjectId, serializeDocument } from '../http.js';
import { ResourceName } from '../schemas.js';

interface CrudOptions {
  resource: ResourceName;
  schema: z.ZodObject;
  searchFields?: string[];
  userOwnershipField?: string;
  userOwnershipIdField?: string;
}

const ownershipScope = async (
  db: Db,
  staffUser: Express.Request['staffUser'],
  ownerField?: string,
  ownerIdField?: string
): Promise<Filter<Record<string, unknown>> | null> => {
  if (!ownerField || !staffUser) return null;
  if (staffUser.role === 'admin') return null;
  if (staffUser.role === 'user') {
    return { $or: [
      { [ownerField]: staffUser.name },
      ...(ownerIdField ? [{ [ownerIdField]: staffUser.id }] : [])
    ] };
  }
  const managerId = new ObjectId(staffUser.id);
  const team = await db.collection('staff_users').find({
    active: true,
    $or: [{ _id: managerId }, { reportingManagerId: managerId }]
  }, { projection: { _id: 1, name: 1 } }).toArray();
  const names = team.map((user) => String(user.name ?? '')).filter(Boolean);
  const ids = team.map((user) => String(user._id));
  return { $or: [
    { [ownerField]: { $in: [...names, ''] } },
    ...(ownerIdField ? [{ [ownerIdField]: { $in: ids } }] : [])
  ] };
};

const canUseOwner = async (
  db: Db,
  staffUser: Express.Request['staffUser'],
  owner: unknown,
  ownerId: unknown
) => {
  if (!staffUser) return false;
  if (staffUser.role === 'admin') return true;
  const ownerName = typeof owner === 'string' ? owner : '';
  const stableOwnerId = typeof ownerId === 'string' ? ownerId : '';
  if (staffUser.role === 'user') return ownerName === staffUser.name || stableOwnerId === staffUser.id;
  if (!ownerName && !stableOwnerId) return true;
  const managerId = new ObjectId(staffUser.id);
  const identity = ObjectId.isValid(stableOwnerId)
    ? { _id: new ObjectId(stableOwnerId) }
    : { name: ownerName };
  return Boolean(await db.collection('staff_users').findOne({
    ...identity,
    active: true,
    $or: [{ _id: managerId }, { reportingManagerId: managerId }]
  }));
};

export const createCrudRouter = ({ resource, schema, searchFields = [], userOwnershipField, userOwnershipIdField }: CrudOptions) => {
  const router = Router();
  const syncSchema = z.object({
    upsert: z.array(z.record(z.string(), z.unknown()).and(z.object({ id: z.string().trim().min(1).max(160) }))).max(250),
    deleteIds: z.array(z.string().trim().min(1).max(160)).max(250).default([])
  });

  router.get('/', asyncHandler(async (request, response) => {
    const db = await getDatabase();
    const limit = Math.min(Math.max(Number(request.query.limit) || 100, 1), 10000);
    const filter: Filter<Record<string, unknown>> = {};
    const search = typeof request.query.search === 'string' ? request.query.search.trim() : '';
    const customerId = typeof request.query.customerId === 'string' ? request.query.customerId : '';

    const scope = await ownershipScope(db, request.staffUser, userOwnershipField, userOwnershipIdField);

    if (search && searchFields.length) {
      filter.$or = searchFields.map((field) => ({ [field]: { $regex: search, $options: 'i' } }));
    }
    if (customerId) filter.customerId = customerId;
    const scopedFilter: Filter<Record<string, unknown>> = scope ? { $and: [scope, filter] } : filter;

    const records = await db.collection(resource).find(scopedFilter).sort({ updatedAt: -1 }).limit(limit).toArray();
    response.json({ data: records.map(serializeDocument), count: records.length });
  }));

  router.put('/sync', asyncHandler(async (request, response) => {
    const input = syncSchema.parse(request.body);
    const db = await getDatabase();
    const scope = await ownershipScope(db, request.staffUser, userOwnershipField, userOwnershipIdField);
    if (userOwnershipField) {
      const permissions = await Promise.all(input.upsert.map((item) =>
        canUseOwner(db, request.staffUser, item[userOwnershipField], userOwnershipIdField ? item[userOwnershipIdField] : undefined)
      ));
      if (permissions.some((allowed) => !allowed)) throw new HttpError(403, 'Records can only be assigned within your authorized team');
    }
    const operations = input.upsert.map((item) => {
      const { id, createdAt: _createdAt, updatedAt: _updatedAt, ...record } = item;
      const values = schema.parse(record) as Record<string, unknown>;
      return {
        updateOne: {
          filter: scope ? { $and: [{ appId: id }, scope] } : { appId: id },
          update: {
            $set: { ...values, appId: id, updatedAt: new Date() },
            $setOnInsert: { createdAt: new Date() }
          },
          upsert: true
        }
      };
    });
    if (operations.length) await db.collection(resource).bulkWrite(operations);
    if (input.deleteIds.length) {
      await db.collection(resource).deleteMany({
        appId: { $in: input.deleteIds },
        ...(scope ? { $and: [scope] } : {})
      });
    }
    response.json({ upserted: operations.length, deleted: input.deleteIds.length });
  }));

  router.post('/', asyncHandler(async (request, response) => {
    const db = await getDatabase();
    const { createdAt: _createdAt, updatedAt: _updatedAt, ...body } = (request.body ?? {}) as Record<string, unknown>;
    const values = schema.parse(body) as Record<string, unknown>;
    if (userOwnershipField && !await canUseOwner(db, request.staffUser, values[userOwnershipField], userOwnershipIdField ? values[userOwnershipIdField] : undefined)) {
      throw new HttpError(403, 'Records can only be assigned within your authorized team');
    }
    const now = new Date();
    const appId = typeof request.body?.id === 'string' ? request.body.id : undefined;
    const result = await db.collection(resource).insertOne({ ...values, ...(appId ? { appId } : {}), createdAt: now, updatedAt: now });
    const created = await db.collection(resource).findOne({ _id: result.insertedId });
    response.status(201).json({ data: serializeDocument(created) });
  }));

  router.get('/:id', asyncHandler(async (request, response) => {
    const db = await getDatabase();
    const id = String(request.params.id);
    const scope = await ownershipScope(db, request.staffUser, userOwnershipField, userOwnershipIdField);
    const record = await db.collection(resource).findOne({
      $and: [
        { $or: [{ appId: id }, ...(ObjectId.isValid(id) ? [{ _id: parseObjectId(id) }] : [])] },
        ...(scope ? [scope] : [])
      ]
    });
    if (!record) throw new HttpError(404, 'Record not found');
    response.json({ data: serializeDocument(record) });
  }));

  router.patch('/:id', asyncHandler(async (request, response) => {
    const db = await getDatabase();
    const { createdAt: _createdAt, updatedAt: _updatedAt, ...body } = (request.body ?? {}) as Record<string, unknown>;
    const values = schema.partial().parse(body) as Record<string, unknown>;
    if (userOwnershipField && (values[userOwnershipField] !== undefined || (userOwnershipIdField && values[userOwnershipIdField] !== undefined)) &&
      !await canUseOwner(db, request.staffUser, values[userOwnershipField] ?? request.staffUser?.name, userOwnershipIdField ? values[userOwnershipIdField] : undefined)) {
      throw new HttpError(403, 'Records can only be reassigned within your authorized team');
    }
    const id = String(request.params.id);
    const scope = await ownershipScope(db, request.staffUser, userOwnershipField, userOwnershipIdField);
    const record = await db.collection(resource).findOneAndUpdate(
      {
        $and: [
          { $or: [{ appId: id }, ...(ObjectId.isValid(id) ? [{ _id: parseObjectId(id) }] : [])] },
          ...(scope ? [scope] : [])
        ]
      },
      { $set: { ...values, updatedAt: new Date() } },
      { returnDocument: 'after' }
    );
    if (!record) throw new HttpError(404, 'Record not found');
    response.json({ data: serializeDocument(record) });
  }));

  router.delete('/:id', asyncHandler(async (request, response) => {
    const db = await getDatabase();
    const id = String(request.params.id);
    const scope = await ownershipScope(db, request.staffUser, userOwnershipField, userOwnershipIdField);
    const result = await db.collection(resource).deleteOne({
      $and: [
        { $or: [{ appId: id }, ...(ObjectId.isValid(id) ? [{ _id: parseObjectId(id) }] : [])] },
        ...(scope ? [scope] : [])
      ]
    });
    if (!result.deletedCount) throw new HttpError(404, 'Record not found');
    response.status(204).send();
  }));

  return router;
};

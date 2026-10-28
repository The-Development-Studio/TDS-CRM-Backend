import { setServers } from 'node:dns';
import { Db, MongoClient } from 'mongodb';
import { config, requireConfig } from './config.js';

if (config.DNS_SERVERS.length) setServers(config.DNS_SERVERS);

let client: MongoClient | undefined;
let database: Db | undefined;

export const getDatabase = async () => {
  if (database) return database;

  client = new MongoClient(requireConfig('MONGODB_URI'), {
    appName: 'TDS-CRM-API',
    maxPoolSize: 20,
    serverSelectionTimeoutMS: 8_000
  });
  await client.connect();
  database = client.db(config.MONGODB_DB_NAME);
  return database;
};

export const createIndexes = async () => {
  const db = await getDatabase();
  await Promise.all([
    ...['customers', 'leads', 'activities', 'opportunities', 'proposals', 'invoices', 'contracts', 'projects', 'documents', 'organizations']
      .map((collection) => db.collection(collection).createIndex({ appId: 1 }, { unique: true, sparse: true })),
    db.collection('customers').createIndex({ customerCode: 1 }, { unique: true }),
    db.collection('customers').createIndex({ email: 1 }),
    db.collection('leads').createIndex({ email: 1 }),
    db.collection('leads').createIndex({ status: 1, updatedAt: -1 }),
    db.collection('leads').createIndex({ leadOwnerId: 1, updatedAt: -1 }),
    db.collection('activities').createIndex({ customerId: 1, date: -1 }),
    db.collection('activities').createIndex({ activityOwnerId: 1, date: -1 }),
    db.collection('activities').createIndex({ leadId: 1, date: -1 }),
    db.collection('opportunities').createIndex({ customerId: 1, stage: 1 }),
    db.collection('proposals').createIndex({ customerId: 1, createdAt: -1 }),
    db.collection('invoices').createIndex({ invoiceNo: 1 }, { unique: true }),
    db.collection('invoices').createIndex({ customerId: 1, status: 1 }),
    db.collection('contracts').createIndex({ customerId: 1, expiryDate: 1 }),
    db.collection('documents').createIndex({ customerId: 1, updatedAt: -1 }),
    db.collection('document_uploads').createIndex({ appId: 1 }, { unique: true }),
    db.collection('document_uploads').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    db.collection('projects').createIndex({ customerId: 1, updatedAt: -1 }),
    db.collection('support_tickets').createIndex({ customerId: 1, createdAt: -1 }),
    db.collection('portal_users').createIndex({ email: 1 }, { unique: true }),
    db.collection('portal_sessions').createIndex({ tokenHash: 1 }, { unique: true }),
    db.collection('portal_sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    db.collection('portal_invitations').createIndex({ tokenHash: 1 }, { unique: true }),
    db.collection('portal_invitations').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    db.collection('portal_login_attempts').createIndex({ key: 1 }, { unique: true }),
    db.collection('portal_login_attempts').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    db.collection('staff_users').createIndex({ email: 1 }, { unique: true }),
    db.collection('staff_users').createIndex({ reportingManagerId: 1 }),
    db.collection('staff_sessions').createIndex({ tokenHash: 1 }, { unique: true }),
    db.collection('staff_sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    db.collection('staff_invitations').createIndex({ tokenHash: 1 }, { unique: true }),
    db.collection('staff_invitations').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    db.collection('staff_password_resets').createIndex({ email: 1 }, { unique: true }),
    db.collection('staff_password_resets').createIndex({ tokenHash: 1 }, { unique: true }),
    db.collection('staff_password_resets').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    db.collection('staff_login_attempts').createIndex({ key: 1 }, { unique: true }),
    db.collection('staff_login_attempts').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    db.collection('organizations').createIndex({ organizationKey: 1 }, { unique: true }),
    db.collection('email_messages').createIndex({ providerId: 1 }, { unique: true, sparse: true }),
    db.collection('email_messages').createIndex({ idempotencyKey: 1 }, { unique: true }),
    db.collection('email_messages').createIndex({ customerId: 1, createdAt: -1 })
  ]);

  // Legacy versions stored the bootstrap administrator as a manager. Promote only
  // the oldest manager when the organization has no explicit administrator.
  if (await db.collection('staff_users').countDocuments({ role: 'admin' }) === 0) {
    const bootstrapManager = await db.collection('staff_users').findOne(
      { role: 'manager', active: true },
      { sort: { createdAt: 1 } }
    );
    if (bootstrapManager) {
      await db.collection('staff_users').updateOne(
        { _id: bootstrapManager._id, role: 'manager' },
        { $set: { role: 'admin', reportingManagerId: null, updatedAt: new Date() } }
      );
    }
  }
};

export const closeDatabase = async () => {
  await client?.close();
  client = undefined;
  database = undefined;
};

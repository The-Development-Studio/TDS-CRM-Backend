import cors from 'cors';
import express from 'express';
import { config } from './config.js';
import { getDatabase } from './database.js';
import { asyncHandler, errorHandler } from './http.js';
import { createCrudRouter } from './routes/crud.js';
import { customer360Router } from './routes/customers.js';
import { emailRouter, resendWebhookHandler } from './routes/emails.js';
import { customerPortalRouter } from './routes/customerPortal.js';
import { staffAuthRouter } from './routes/staffAuth.js';
import { staffDataRouter } from './routes/staffData.js';
import { documentsRouter } from './routes/documents.js';
import { resourceSchemas } from './schemas.js';
import { requireStaffAnyPage, requireStaffPage, requireStaffSession } from './staffAuth.js';

export const app = express();

app.disable('x-powered-by');
app.use(cors({ origin: config.CLIENT_ORIGIN.split(',').map((origin) => origin.trim()), credentials: true }));

// Signature verification requires the exact body received from Resend.
app.post('/api/webhooks/resend', express.text({ type: 'application/json', limit: '1mb' }), resendWebhookHandler);
app.use(express.json({ limit: '2mb' }));

app.get('/api/health', asyncHandler(async (_request, response) => {
  const startedAt = Date.now();
  let database = 'not-configured';
  if (config.MONGODB_URI) {
    await (await getDatabase()).command({ ping: 1 });
    database = 'connected';
  }
  response.json({
    status: database === 'connected' ? 'ok' : 'configuration-required',
    database,
    resend: config.RESEND_API_KEY && config.RESEND_FROM_EMAIL ? 'configured' : 'not-configured',
    documents: config.R2_ACCOUNT_ID && config.R2_ACCESS_KEY_ID && config.R2_SECRET_ACCESS_KEY && config.R2_BUCKET
      ? 'configured'
      : 'not-configured',
    responseTimeMs: Date.now() - startedAt
  });
}));

app.use('/api/staff-auth', staffAuthRouter);
app.use('/api/customer-portal', customerPortalRouter);
app.use('/api', requireStaffSession);

app.use('/api/customers', requireStaffPage('customers'), customer360Router);
app.use('/api/staff-data', staffDataRouter);

const resourcePageAccess: Record<string, string[]> = {
  customers: ['customers', 'portal', 'costing'],
  leads: ['leads', 'portal', 'reports'],
  activities: ['activities', 'reports'],
  opportunities: ['pipeline', 'reports'],
  proposals: ['quotations', 'costing'],
  invoices: ['proforma', 'invoices', 'payments', 'costing'],
  payments: ['payments', 'invoices'],
  contracts: ['amc', 'portal'],
  projects: ['customers', 'portal'],
  documents: ['documents'],
  organizations: ['org-setup']
};

for (const [resource, schema] of Object.entries(resourceSchemas)) {
  if (resource === 'documents') {
    app.use('/api/documents', requireStaffPage('documents'), documentsRouter);
    continue;
  }
  const searchFields = resource === 'customers'
    ? ['companyName', 'customerCode', 'primaryContact', 'email']
    : resource === 'leads'
      ? ['name', 'company', 'email']
      : [];
  app.use(`/api/${resource}`, requireStaffAnyPage(resourcePageAccess[resource]), createCrudRouter({
    resource: resource as keyof typeof resourceSchemas,
    schema,
    searchFields,
    userOwnershipField: resource === 'leads'
      ? 'leadOwner'
      : resource === 'activities'
        ? 'user'
        : resource === 'opportunities'
          ? 'owner'
          : undefined,
    userOwnershipIdField: resource === 'leads'
      ? 'leadOwnerId'
      : resource === 'activities'
        ? 'activityOwnerId'
        : resource === 'opportunities'
          ? 'ownerId'
          : undefined
  }));
}

app.use('/api/emails', emailRouter);
app.use((_request, response) => response.status(404).json({ error: 'Route not found' }));
app.use(errorHandler);

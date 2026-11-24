import { Router } from 'express';
import { CreateEmailOptions, Resend } from 'resend';
import { z } from 'zod';
import { config, requireConfig } from '../config.js';
import { getDatabase } from '../database.js';
import { asyncHandler, HttpError, serializeDocument } from '../http.js';

const sendEmailSchema = z.object({
  to: z.union([z.email(), z.array(z.email()).min(1)]),
  cc: z.union([z.email(), z.array(z.email())]).optional(),
  bcc: z.union([z.email(), z.array(z.email())]).optional(),
  replyTo: z.union([z.email(), z.array(z.email())]).optional(),
  subject: z.string().trim().min(1).max(998),
  html: z.string().min(1).optional(),
  text: z.string().min(1).optional(),
  customerId: z.string().optional(),
  relatedEntityType: z.enum(['lead', 'proposal', 'invoice', 'contract', 'customer', 'other']).default('other'),
  relatedEntityId: z.string().optional(),
  idempotencyKey: z.string().trim().min(8).max(256)
}).refine((value) => value.html || value.text, { message: 'Either html or text is required' });

const resend = new Resend(config.RESEND_API_KEY ?? 're_not_configured');
export const emailRouter = Router();

emailRouter.get('/', asyncHandler(async (request, response) => {
  const db = await getDatabase();
  const customerId = typeof request.query.customerId === 'string' ? request.query.customerId : '';
  const filter = customerId
    ? { customerId, tenantId: request.staffUser?.tenantId }
    : { tenantId: request.staffUser?.tenantId };
  const messages = await db.collection('email_messages').find(filter).sort({ createdAt: -1 }).limit(200).toArray();
  response.json({ data: messages.map(serializeDocument), count: messages.length });
}));

emailRouter.post('/send', asyncHandler(async (request, response) => {
  const values = sendEmailSchema.parse(request.body);
  const db = await getDatabase();
  const existing = await db.collection('email_messages').findOne({ idempotencyKey: values.idempotencyKey, tenantId: request.staffUser?.tenantId });
  if (existing) {
    response.status(existing.status === 'failed' ? 409 : 200).json({ data: serializeDocument(existing), duplicate: true });
    return;
  }

  const apiKey = requireConfig('RESEND_API_KEY');
  const from = requireConfig('RESEND_FROM_EMAIL');
  const now = new Date();
  const auditRecord = {
    ...values,
    tenantId: request.staffUser?.tenantId,
    from,
    status: 'sending',
    createdAt: now,
    updatedAt: now
  };
  const insertResult = await db.collection('email_messages').insertOne(auditRecord);

  try {
    const client = apiKey === config.RESEND_API_KEY ? resend : new Resend(apiKey);
    const emailContent = values.html ? { html: values.html } : { text: values.text as string };
    const emailOptions: CreateEmailOptions = {
      from,
      to: values.to,
      cc: values.cc,
      bcc: values.bcc,
      replyTo: values.replyTo,
      subject: values.subject,
      html: values.html,
      text: values.text,
      tags: [
        { name: 'entity_type', value: values.relatedEntityType },
        ...(values.customerId ? [{ name: 'customer_id', value: values.customerId }] : [])
      ],
      ...emailContent
    };
    const result = await client.emails.send(emailOptions, { idempotencyKey: values.idempotencyKey });

    if (result.error) throw new HttpError(502, result.error.message);

    const updated = await db.collection('email_messages').findOneAndUpdate(
      { _id: insertResult.insertedId },
      { $set: { providerId: result.data?.id, status: 'sent', sentAt: new Date(), updatedAt: new Date() } },
      { returnDocument: 'after' }
    );

    if (values.customerId) {
      await db.collection('activities').insertOne({
        tenantId: request.staffUser?.tenantId,
        customerId: values.customerId,
        type: 'Email',
        title: values.subject,
        description: `Email sent to ${Array.isArray(values.to) ? values.to.join(', ') : values.to}`,
        date: new Date().toISOString().slice(0, 10),
        time: new Date().toISOString().slice(11, 16),
        user: 'TDS CRM',
        priority: 'Medium',
        status: 'Completed',
        category: 'Today',
        emailMessageId: insertResult.insertedId.toHexString(),
        createdAt: new Date(),
        updatedAt: new Date()
      });
    }

    response.status(202).json({ data: serializeDocument(updated) });
  } catch (error) {
    await db.collection('email_messages').updateOne(
      { _id: insertResult.insertedId },
      { $set: { status: 'failed', error: error instanceof Error ? error.message : 'Unknown Resend error', updatedAt: new Date() } }
    );
    throw error;
  }
}));

export const resendWebhookHandler = asyncHandler(async (request, response) => {
  const webhookSecret = requireConfig('RESEND_WEBHOOK_SECRET');
  const headerValue = (name: string) => {
    const value = request.header(name);
    if (!value) throw new HttpError(400, `Missing ${name} header`);
    return value;
  };

  let event;
  try {
    event = resend.webhooks.verify({
      payload: request.body as string,
      headers: {
        id: headerValue('svix-id'),
        timestamp: headerValue('svix-timestamp'),
        signature: headerValue('svix-signature')
      },
      webhookSecret
    });
  } catch {
    throw new HttpError(400, 'Invalid webhook signature');
  }

  const db = await getDatabase();
  await db.collection('email_events').updateOne(
    { eventId: headerValue('svix-id') },
    { $setOnInsert: { eventId: headerValue('svix-id'), event, receivedAt: new Date() } },
    { upsert: true }
  );

  if ('email_id' in event.data) {
    const status = event.type.replace('email.', '');
    await db.collection('email_messages').updateOne(
      { providerId: event.data.email_id },
      { $set: { status, lastEventAt: new Date(event.created_at), updatedAt: new Date() } }
    );
  }

  response.status(200).json({ received: true });
});

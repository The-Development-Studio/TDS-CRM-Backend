import { createHash } from 'node:crypto';
import { NextFunction, Request, Response } from 'express';
import { ObjectId } from 'mongodb';
import { getDatabase } from './database.js';
import { asyncHandler, HttpError } from './http.js';

export const staffSessionCookie = 'tds_staff_session';
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
export type StaffRole = 'admin' | 'manager' | 'user';

export const normalizeStaffRole = (role: unknown): StaffRole =>
  role === 'admin' ? 'admin' : role === 'manager' ? 'manager' : 'user';

export const readStaffSession = async (request: Request) => {
  const cookieHeader = request.header('cookie') ?? '';
  const cookie = cookieHeader.split(';').map((part) => part.trim())
    .find((part) => part.startsWith(`${staffSessionCookie}=`));
  if (!cookie) return null;

  const db = await getDatabase();
  const session = await db.collection('staff_sessions').findOne({
    tokenHash: digest(cookie.slice(staffSessionCookie.length + 1)),
    expiresAt: { $gt: new Date() }
  });
  if (!session) return null;

  const user = await db.collection('staff_users').findOne({ _id: session.userId, active: true });
  if (!user) return null;
  const role = normalizeStaffRole(user.role);
  const storedPageAccess = Array.isArray(user.pageAccess)
    ? user.pageAccess.filter((page): page is string => typeof page === 'string' && (role === 'admin' || page !== 'admin'))
    : [];
  return {
    id: String(user._id),
    email: user.email as string,
    name: user.name as string,
    role,
    reportingManagerId: user.reportingManagerId instanceof ObjectId ? String(user.reportingManagerId) : null,
    pageAccess: role === 'admin' || role === 'manager' ? storedPageAccess : [...new Set(['dashboard', 'reports', ...storedPageAccess])]
  };
};

export const requireStaffSession = (
  request: Request,
  _response: Response,
  next: NextFunction
) => {
  void readStaffSession(request)
    .then((session) => {
      if (!session) {
        next(new HttpError(401, 'Staff sign-in required'));
        return;
      }
      request.staffUser = session;
      next();
    })
    .catch(next);
};

export const staffRoute = asyncHandler(async (request, _response, next) => {
  const session = request.staffUser ?? await readStaffSession(request);
  if (!session) throw new HttpError(401, 'Staff sign-in required');
  request.staffUser = session;
  next();
});

export const requireStaffAdmin = asyncHandler(async (request, _response, next) => {
  const session = await readStaffSession(request);
  if (!session) throw new HttpError(401, 'Staff sign-in required');
  const db = await getDatabase();
  const user = await db.collection('staff_users').findOne({ _id: new ObjectId(session.id) });
  if (!user || normalizeStaffRole(user.role) !== 'admin') throw new HttpError(403, 'Administrator access required');
  request.staffUser = session;
  next();
});

export const requireStaffPage = (page: string) => asyncHandler(async (request, _response, next) => {
  const session = request.staffUser ?? await readStaffSession(request);
  if (!session) throw new HttpError(401, 'Staff sign-in required');
  if (session.role !== 'admin' && !(session.role === 'manager' && page !== 'admin') && !session.pageAccess.includes(page)) {
    throw new HttpError(403, 'You do not have access to this area');
  }
  request.staffUser = session;
  next();
});

export const requireStaffAnyPage = (pages: string[]) => asyncHandler(async (request, _response, next) => {
  const session = request.staffUser ?? await readStaffSession(request);
  if (!session) throw new HttpError(401, 'Staff sign-in required');
  if (session.role !== 'admin' && !(session.role === 'manager' && pages.some((page) => page !== 'admin')) && !pages.some((page) => session.pageAccess.includes(page))) {
    throw new HttpError(403, 'You do not have access to this area');
  }
  request.staffUser = session;
  next();
});

export const hashStaffSessionToken = digest;

export const requireStaffManager = asyncHandler(async (request, _response, next) => {
  const session = request.staffUser ?? await readStaffSession(request);
  if (!session) throw new HttpError(401, 'Staff sign-in required');
  if (session.role === 'user') throw new HttpError(403, 'Manager access required');
  request.staffUser = session;
  next();
});

declare global {
  namespace Express {
    interface Request {
      staffUser?: { id: string; email: string; name: string; role: StaffRole; reportingManagerId: string | null; pageAccess: string[] };
    }
  }
}

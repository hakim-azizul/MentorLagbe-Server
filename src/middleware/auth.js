import { ObjectId } from "mongodb";
import { collections } from "../db.js";

/** Better Auth session cookie names (http + https prefixed variants). */
const SESSION_COOKIE_NAMES = [
  "better-auth.session_token",
  "__Secure-better-auth.session_token",
];

/** Minimal cookie header parser (no extra dependency needed). */
export function parseCookies(cookieHeader = "") {
  const jar = {};
  for (const pair of cookieHeader.split(";")) {
    const index = pair.indexOf("=");
    if (index === -1) continue;
    const key = pair.slice(0, index).trim();
    const value = pair.slice(index + 1).trim();
    if (!key) continue;
    try {
      jar[key] = decodeURIComponent(value);
    } catch {
      jar[key] = value;
    }
  }
  return jar;
}

import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Better Auth signs session cookies as `<token>.<base64 HMAC-SHA256(secret, token)>`.
 * The `session` collection stores only the raw token, so the signature must be
 * stripped before the lookup — and verified when BETTER_AUTH_SECRET is set,
 * so a tampered token can never be accepted.
 */
function unwrapSignedToken(value) {
  const sigStart = value.lastIndexOf(".");
  if (sigStart < 1) return { token: value, valid: true };

  const token = value.slice(0, sigStart);
  const signature = value.slice(sigStart + 1);

  // Raw tokens never contain a dot; anything that does must carry a real signature.
  if (signature.length !== 44 || !signature.endsWith("=")) {
    return { token: value, valid: false };
  }

  const secret = process.env.BETTER_AUTH_SECRET;
  if (!secret) return { token, valid: true };

  const expected = createHmac("sha256", secret).update(token).digest("base64");
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  return { token, valid: a.length === b.length && timingSafeEqual(a, b) };
}

function toObjectId(value) {
  if (value instanceof ObjectId) return value;
  if (typeof value === "string" && /^[a-f\d]{24}$/i.test(value)) {
    return new ObjectId(value);
  }
  return null;
}

/**
 * Resolves the signed-in Better Auth user from the `session` + `user`
 * collections. Returns `null` when the cookie is missing, expired or unknown.
 */
export async function getAuthUser(req) {
  const cookies = parseCookies(req.headers.cookie || "");
  const rawToken = SESSION_COOKIE_NAMES.map((name) => cookies[name]).find(Boolean);
  if (!rawToken) return null;

  const { token, valid } = unwrapSignedToken(rawToken);
  if (!valid) return null;

  const session = await collections.sessions().findOne({ token });
  if (!session) return null;
  if (session.expiresAt && new Date(session.expiresAt) < new Date()) return null;

  const userId = toObjectId(session.userId);
  const user = await collections
    .users()
    .findOne(userId ? { _id: userId } : { _id: session.userId });
  if (!user) return null;

  return {
    id: String(user._id),
    name: user.name || "",
    email: user.email || "",
    role: user.role || "student",
    plan: user.plan || "free",
  };
}

/**
 * requireRole("admin") | requireRole("student", "admin")
 * Attaches the resolved user to `req.user`.
 */
export function requireRole(...roles) {
  return async (req, res, next) => {
    try {
      const user = await getAuthUser(req);
      if (!user) {
        return res
          .status(401)
          .json({ message: "You are not authenticated. Please sign in again." });
      }
      if (roles.length > 0 && !roles.includes(user.role)) {
        return res
          .status(403)
          .json({ message: `Access denied. ${roles.join(" or ")} only.` });
      }
      req.user = user;
      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * When an endpoint is scoped by `?email=`, make sure the caller is not
 * reading someone else's data (admins can read anything).
 */
export function requireSelfOrAdmin(req, res, next) {
  const requested = req.query.email;
  if (
    requested &&
    req.user?.role !== "admin" &&
    String(requested).toLowerCase() !== req.user.email.toLowerCase()
  ) {
    return res.status(403).json({ message: "You cannot access this data." });
  }
  next();
}

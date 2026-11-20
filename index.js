/**
 * MentorLagbe — Express REST API (single file).
 *
 * Everything lives here: MongoDB access, Better Auth JWT verification (JWKS),
 * shared helpers, all route groups and the bootstrap. Database: `MentorLagbeDb`.
 *
 * Auth flow: mentor-client (Better Auth `jwt` plugin) fetches a session JWT
 * (GET :3000/api/auth/token) and sends it as `Authorization: Bearer <jwt>`;
 * `verifyToken` checks it against the JWKS (GET :3000/api/auth/jwks), syncs
 * the user into MongoDB, attaches `req.user`, then a role gate
 * (verifyStudent / verifyTutor / verifyAdmin) runs before the controller.
 *
 * Routes are registered directly on the Express `app` (no express.Router).
 *
 * Route groups:
 *   GET    /                        welcome
 *   /api/dashboard/*                role stats (student | tutor | admin)
 *   GET    /api/tuitions            public: approved & active (filter + sort query params)
 *   GET    /api/tuitions/:id        public: single tuition + tutor summary
 *   POST   /api/tuitions            tutor/admin: create a tuition post
 *   GET    /api/tuitions/tutor       tutor/admin: my posts
 *   PATCH  /api/tuitions/:id         tutor/admin: edit / toggle isActive
 *   DELETE /api/tuitions/:id         tutor/admin: delete (+ its applications)
 *   GET    /api/applications/check   public: { hasApplied } helper
 *   POST   /api/applications         public: student applies (role checked by email)
 *   GET    /api/applications/student  student: my applications
 *   GET    /api/applications/tutor    tutor: applicants on my tuitions
 *   PATCH  /api/applications/:id/status  tutor/admin: accept / reject
 *   DELETE /api/applications/:id     student: cancel a pending application
 *   GET    /api/profile              authenticated: full profile for the edit form
 *   PATCH  /api/profile              authenticated: update name/email/image/phone/bio
 *   /api/admin/*                     admin: users, tuitions, transactions
 */
import "dotenv/config";
import { createRemoteJWKSet, jwtVerify } from "jose";
import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";

/* -------------------------------------------------------------------------- */
/* MongoDB                                                                     */
/* -------------------------------------------------------------------------- */

const DB_NAME = "MentorLagbeDb";

const client = new MongoClient(process.env.DB_URI);

async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
    throw err;
  }
}

function getDb() {
  return client.db(DB_NAME);
}

/**
 * Better Auth (mongo adapter) stores auth data in singular collections:
 * `user`, `session`, `account`, `verification`.
 * Business data uses plural collections.
 */
const collections = {
  users: () => getDb().collection("user"),
  sessions: () => getDb().collection("session"),
  tuitions: () => getDb().collection("tuitions"),
  applications: () => getDb().collection("applications"),
  payments: () => getDb().collection("payments"),
};

/* -------------------------------------------------------------------------- */
/* Shared helpers                                                              */
/* -------------------------------------------------------------------------- */

/** Standard { message } error helper. */
function fail(res, status, message) {
  return res.status(status).json({ message });
}

/** Reads and validates a MongoDB ObjectId from the route params. */
function getObjectId(req, res) {
  const { id } = req.params;
  if (!/^[a-f\d]{24}$/i.test(id)) {
    res.status(400).json({ message: "Invalid id." });
    return null;
  }
  return new ObjectId(id);
}

/** Returns the list of missing keys from a request body. */
function missingFields(body, fields) {
  return fields.filter((field) => {
    const value = body?.[field];
    return value === undefined || value === null || String(value).trim() === "";
  });
}

/**
 * `tuitionId` is stored as a string (see tApplication), but we also match the
 * ObjectId form so older/other writes keep working.
 */
function tuitionIdIn(ids) {
  const variants = [];
  for (const id of ids) {
    variants.push(String(id));
    if (/^[a-f\d]{24}$/i.test(String(id)))
      variants.push(new ObjectId(String(id)));
  }
  return variants;
}

/** Escapes user input before building a RegExp (public search filter). */
function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/* -------------------------------------------------------------------------- */
/* Better Auth JWT verification (JWKS) + role middleware                                              */
/* -------------------------------------------------------------------------- */

/**
 * mentor-client hands the browser two credentials:
 *   • HTTP-only session cookie → Next.js (/api/auth/*) — not read here
 *   • JWT (GET :3000/api/auth/token) → sent here as `Authorization: Bearer <jwt>`
 *
 * The JWT is verified against the plugin's public key set
 * (`GET :3000/api/auth/jwks`): signature, issuer, audience, expiry — so this
 * server never needs the Better Auth secret. issuer/audience must match the
 * `jwt({ ... })` options in mentor-client/src/lib/auth.ts; the env overrides
 * below default to the same values as that file.
 */
const JWT_ISSUER = (
  process.env.JWT_ISSUER ||
  process.env.BETTER_AUTH_URL ||
  "http://localhost:3000"
).replace(/\/+$/, "");
const JWT_AUDIENCE = (
  process.env.JWT_AUDIENCE || `http://localhost:${process.env.PORT || 5000}`
).replace(/\/+$/, "");
const JWKS_URL = process.env.JWKS_URL || `${JWT_ISSUER}/api/auth/jwks`;

/** Remote JWK set — jose caches it (10 min) and throttles refetches (30 s). */
const remoteJwks = createRemoteJWKSet(new URL(JWKS_URL), {
  timeoutDuration: 5_000,
  cooldownDuration: 30_000,
  cacheMaxAge: 10 * 60_000,
});

function toObjectId(value) {
  if (value instanceof ObjectId) return value;
  if (typeof value === "string" && /^[a-f\d]{24}$/i.test(value)) {
    return new ObjectId(value);
  }
  return null;
}

/**
 * JWT claims → `users` document (created on first sight) → `req.user` shape.
 *
 * The database is authoritative for `role`/`plan`: an existing user's values
 * are never overwritten from token claims, so demoting a user in the admin
 * panel takes effect immediately even though their 15-minute JWT still
 * carries the old role. Claims only seed the fields of a brand-new user.
 */
async function syncUserFromClaims(payload) {
  const users = collections.users();
  const userId = toObjectId(payload.sub);
  const email = typeof payload.email === "string" ? payload.email.trim() : "";

  let user = userId ? await users.findOne({ _id: userId }) : null;
  if (!user && email) user = await users.findOne({ email });

  if (!user) {
    const now = new Date();
    const fresh = {
      _id: userId || new ObjectId(),
      name: typeof payload.name === "string" ? payload.name : "",
      email,
      emailVerified: Boolean(payload.emailVerified),
      image: typeof payload.image === "string" ? payload.image : "",
      role: ["student", "tutor", "admin"].includes(payload.role)
        ? payload.role
        : "student",
      phone: typeof payload.phone === "string" ? payload.phone : "",
      bio: typeof payload.bio === "string" ? payload.bio : "",
      plan: payload.plan === "pro" ? "pro" : "free",
      createdAt: payload.createdAt ? new Date(payload.createdAt) : now,
      updatedAt: now,
    };
    try {
      await users.insertOne(fresh);
      user = fresh;
    } catch (error) {
      // Two parallel requests created the same user — read the winner instead.
      if (error?.code !== 11000) throw error;
      user = userId
        ? await users.findOne({ _id: userId })
        : await users.findOne({ email });
    }
  }

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
 * First guard on every protected route: `Authorization: Bearer <jwt>` →
 * jose `jwtVerify` against the remote JWKS (signature + iss + aud + exp) →
 * user sync → `req.user`.
 *
 * 401 = header missing, or token malformed / expired / tampered / wrong
 *      issuer / wrong audience; 503 = JWKS unreachable (Next.js down).
 */
async function verifyToken(req, res, next) {
  try {
    const [scheme, token] = String(req.headers.authorization || "").split(" ");
    if (scheme !== "Bearer" || !token) {
      return res
        .status(401)
        .json({ message: "You are not authenticated. Please sign in again." });
    }

    let payload;
    try {
      ({ payload } = await jwtVerify(token, remoteJwks, {
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      }));
    } catch (error) {
      const code = error?.code || "";
      const badToken =
        code.startsWith("ERR_JWT") ||
        code.startsWith("ERR_JWS") ||
        code === "ERR_JWKS_NO_MATCHING_KEY" ||
        code === "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
      if (badToken) {
        return res.status(401).json({
          message: "Your session is invalid or expired. Please sign in again.",
        });
      }
      // Not a token problem — JWKS fetch failed / timed out / non-200.
      console.error("[auth] JWKS verification unavailable:", JWKS_URL, error);
      return res.status(503).json({
        message: "Authentication service is unavailable. Please try again.",
      });
    }

    const user = await syncUserFromClaims(payload);
    if (!user) {
      return res
        .status(401)
        .json({ message: "You are not authenticated. Please sign in again." });
    }
    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

/**
 * Role gate — runs after `verifyToken` (which sets `req.user`):
 * `verifyStudent` | `verifyTutor` | `verifyAdmin`.
 * The student/tutor gates also admit admins (same contract as the old
 * `requireRole("student", "admin")` helper).
 */
function verifyRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res
        .status(401)
        .json({ message: "You are not authenticated. Please sign in again." });
    }
    if (!roles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ message: `Access denied. ${roles.join(" or ")} only.` });
    }
    next();
  };
}

const verifyStudent = verifyRole("student", "admin");
const verifyTutor = verifyRole("tutor", "admin");
const verifyAdmin = verifyRole("admin");

/**
 * When an endpoint is scoped by `?email=`, make sure the caller is not
 * reading someone else's data (admins can read anything).
 */
function requireSelfOrAdmin(req, res, next) {
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

/* -------------------------------------------------------------------------- */
/* App + CORS                                                                  */
/* -------------------------------------------------------------------------- */

/** Comma separated list of allowed browser origins (credentials enabled). */
const DEFAULT_ORIGINS = ["http://localhost:3000", "http://localhost:5173"];
const allowedOrigins = (process.env.CLIENT_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const originAllowList = allowedOrigins.length
  ? allowedOrigins
  : DEFAULT_ORIGINS;

const app = express();

app.use(
  cors({
    origin(origin, callback) {
      // নন-ব্রাউজার রিকোয়েস্ট (Postman/curl) বা অনুমোদিত অরিজিন
      if (!origin || originAllowList.includes(origin)) {
        return callback(null, origin || false);
      }
      callback(new Error(`Origin ${origin} is not allowed by CORS.`));
    },
    credentials: true,
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
  }),
);

app.use(express.json({ limit: "1mb" }));

app.get("/", (_req, res) => {
  res.send("Welcome to MentorLagbe server");
});

/* -------------------------------------------------------------------------- */
/* Dashboard stats — GET /api/dashboard/{student|tutor|admin}/stats            */
/* -------------------------------------------------------------------------- */

/** GET /api/dashboard/student/stats?email= */
app.get(
  "/api/dashboard/student/stats",
  verifyToken,
  verifyStudent,
  requireSelfOrAdmin,
  async (req, res, next) => {
    try {
      const email = String(req.query.email).toLowerCase();

      const user = await collections.users().findOne({ email });
      if (!user) return fail(res, 404, "User not found.");

      const filter = { studentEmail: email };
      const [totalApplied, acceptedCount, pendingCount] = await Promise.all([
        collections.applications().countDocuments(filter),
        collections
          .applications()
          .countDocuments({ ...filter, status: "accepted" }),
        collections
          .applications()
          .countDocuments({ ...filter, status: "pending" }),
      ]);

      res.json({
        totalApplied,
        acceptedCount,
        pendingCount,
        plan: user.plan || "free",
      });
    } catch (error) {
      next(error);
    }
  },
);

/** GET /api/dashboard/tutor/stats?email= */
app.get(
  "/api/dashboard/tutor/stats",
  verifyToken,
  verifyTutor,
  requireSelfOrAdmin,
  async (req, res, next) => {
    try {
      const email = String(req.query.email).toLowerCase();

      const user = await collections.users().findOne({ email });
      if (!user) return fail(res, 404, "User not found.");

      const tuitionFilter = { tutorEmail: email };
      const [totalPosted, approvedCount, tuitions] = await Promise.all([
        collections.tuitions().countDocuments(tuitionFilter),
        collections.tuitions().countDocuments({
          ...tuitionFilter,
          approvalStatus: "approved",
        }),
        collections
          .tuitions()
          .find(tuitionFilter, { projection: { _id: 1 } })
          .toArray(),
      ]);

      const tuitionIds = tuitionIdIn(tuitions.map((tuition) => tuition._id));
      const totalApplicants = tuitionIds.length
        ? await collections.applications().countDocuments({
            tuitionId: { $in: tuitionIds },
          })
        : 0;

      res.json({
        totalPosted,
        approvedCount,
        totalApplicants,
        plan: user.plan || "free",
      });
    } catch (error) {
      next(error);
    }
  },
);

/** GET /api/dashboard/admin/stats */
app.get(
  "/api/dashboard/admin/stats",
  verifyToken,
  verifyAdmin,
  async (_req, res, next) => {
    try {
      const [
        totalUsers,
        totalTutors,
        pendingTuitions,
        approvedTuitions,
        revenue,
      ] = await Promise.all([
        collections.users().countDocuments(),
        collections.users().countDocuments({ role: "tutor" }),
        collections.tuitions().countDocuments({ approvalStatus: "pending" }),
        collections.tuitions().countDocuments({ approvalStatus: "approved" }),
        collections
          .payments()
          .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
          .toArray(),
      ]);

      res.json({
        totalUsers,
        totalTutors,
        pendingTuitions,
        approvedTuitions,
        totalRevenue: revenue[0]?.total || 0,
      });
    } catch (error) {
      next(error);
    }
  },
);

/* -------------------------------------------------------------------------- */
/* Tuitions — /api/tuitions                                                    */
/* -------------------------------------------------------------------------- */

const MODES = ["Online", "Offline", "Hybrid"];

/** Whitelisted `sort` values for GET /api/tuitions — anything else = newest. */
const TUITION_SORTS = {
  newest: { createdAt: -1 },
  oldest: { createdAt: 1 },
  fee_asc: { monthlyFee: 1 },
  fee_desc: { monthlyFee: -1 },
};

/** Fields a tutor may edit on their own tuition post. */
const UPDATABLE_FIELDS = [
  "title",
  "subject",
  "classLevel",
  "mode",
  "location",
  "monthlyFee",
  "daysPerWeek",
  "description",
  "bannerImage",
];

/** Loads a tuition and makes sure the caller owns it (admins pass). */
async function loadOwnTuition(req, res) {
  const _id = getObjectId(req, res);
  if (!_id) return null;

  const tuition = await collections.tuitions().findOne({ _id });
  if (!tuition) {
    fail(res, 404, "Tuition not found.");
    return null;
  }
  if (req.user.role !== "admin" && tuition.tutorEmail !== req.user.email) {
    fail(res, 403, "You are not allowed to modify this tuition.");
    return null;
  }
  return tuition;
}

/**
 * Tutor profile summary attached to tuition payloads — the list
 * (`GET /api/tuitions`) and the detail page (`GET /api/tuitions/:id`)
 * share this exact shape, so cards and details render identically.
 * Falls back to the denormalized fields stored on the tuition document
 * when the tutor's user document is missing.
 */
function tutorSummary(tutorUser, tuition) {
  return {
    name: tutorUser?.name || tuition.tutorName || "",
    email: tutorUser?.email || tuition.tutorEmail || "",
    image: tutorUser?.image || "",
    bio: tutorUser?.bio || "",
    plan: tutorUser?.plan || "free",
  };
}

/** POST /api/tuitions — creates a post with approvalStatus: 'pending'. */
app.post("/api/tuitions", verifyToken, verifyTutor, async (req, res, next) => {
  try {
    const body = req.body || {};
    const required = [
      "title",
      "subject",
      "classLevel",
      "mode",
      "monthlyFee",
      "daysPerWeek",
      "description",
    ];
    const missing = missingFields(body, required);
    if (missing.length) {
      return fail(res, 400, `Please fill in: ${missing.join(", ")}.`);
    }

    if (!MODES.includes(body.mode)) {
      return fail(res, 400, "Mode must be Online, Offline or Hybrid.");
    }

    const monthlyFee = Number(body.monthlyFee);
    const daysPerWeek = Number(body.daysPerWeek);
    if (!Number.isFinite(monthlyFee) || monthlyFee <= 0) {
      return fail(res, 400, "Monthly fee must be a positive number.");
    }
    if (!Number.isInteger(daysPerWeek) || daysPerWeek < 1 || daysPerWeek > 7) {
      return fail(res, 400, "Days per week must be between 1 and 7.");
    }

    // ফ্রি প্ল্যানে সর্বোচ্চ ২টি টিউশন পোস্ট করা যাবে
    const user = await collections.users().findOne({ email: req.user.email });
    const plan = user?.plan || "free";
    const posted = await collections.tuitions().countDocuments({
      tutorEmail: req.user.email,
    });
    if (plan === "free" && posted >= 2) {
      return fail(
        res,
        403,
        "Free plan tutors can only post up to 2 tuitions. Upgrade to Pro for unlimited posts.",
      );
    }

    const doc = {
      title: String(body.title).trim(),
      subject: String(body.subject).trim(),
      classLevel: String(body.classLevel).trim(),
      mode: body.mode,
      location: body.location ? String(body.location).trim() : "",
      monthlyFee,
      daysPerWeek,
      description: String(body.description).trim(),
      bannerImage: body.bannerImage ? String(body.bannerImage).trim() : "",
      tutorName: req.user.name || "",
      tutorEmail: req.user.email,
      approvalStatus: "pending",
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await collections.tuitions().insertOne(doc);
    res.status(201).json({ ...doc, _id: String(result.insertedId) });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/tuitions — public catalogue of approved & active tuitions.
 * Filters: `search` (case-insensitive regex on title/subject), `subject`,
 * `classLevel`, `mode`. Sort: `sort` = newest | oldest | fee_asc | fee_desc
 * (default newest), applied in the database query. No auth required.
 * Every item carries a `tutor` profile summary (name, email, image, bio,
 * plan) from the `user` collection — same shape as GET /api/tuitions/:id.
 */
app.get("/api/tuitions", async (req, res, next) => {
  try {
    const { search, subject, classLevel, mode, sort } = req.query;

    const filter = { approvalStatus: "approved", isActive: true };

    const term = String(search ?? "").trim();
    if (term) {
      const pattern = new RegExp(escapeRegExp(term), "i");
      filter.$or = [{ title: pattern }, { subject: pattern }];
    }
    if (String(subject ?? "").trim()) filter.subject = String(subject).trim();
    if (String(classLevel ?? "").trim())
      filter.classLevel = String(classLevel).trim();
    if (String(mode ?? "").trim()) filter.mode = String(mode).trim();

    const sortSpec =
      TUITION_SORTS[String(sort ?? "").trim()] || TUITION_SORTS.newest;

    const tuitions = await collections
      .tuitions()
      .find(filter)
      .sort(sortSpec)
      .toArray();

    // টিউশনার ইউজার ডকুমেন্ট একটিই কোয়েরিতে — কার্ডে অ্যাভাটার/নাম দেখানোর জন্য
    const tutorEmails = [
      ...new Set(tuitions.map((tuition) => tuition.tutorEmail).filter(Boolean)),
    ];
    const tutorDocs = tutorEmails.length
      ? await collections
          .users()
          .find(
            { email: { $in: tutorEmails } },
            { projection: { email: 1, name: 1, image: 1, bio: 1, plan: 1 } },
          )
          .toArray()
      : [];
    const tutorByEmail = new Map(tutorDocs.map((doc) => [doc.email, doc]));

    res.json(
      tuitions.map((tuition) => ({
        ...tuition,
        _id: String(tuition._id),
        tutor: tutorSummary(tutorByEmail.get(tuition.tutorEmail), tuition),
      })),
    );
  } catch (error) {
    next(error);
  }
});

/** GET /api/tuitions/tutor?email= — every tuition created by this tutor. */
app.get(
  "/api/tuitions/tutor",
  verifyToken,
  verifyTutor,
  requireSelfOrAdmin,
  async (req, res, next) => {
    try {
      const email = String(req.query.email).toLowerCase();
      const tuitions = await collections
        .tuitions()
        .find({ tutorEmail: email })
        .sort({ createdAt: -1 })
        .toArray();

      res.json(
        tuitions.map((tuition) => ({ ...tuition, _id: String(tuition._id) })),
      );
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /api/tuitions/:id — public tuition details with the tutor's profile
 * summary (`name`, `email`, `image`, `bio`, `plan`) from the `user` collection.
 * Registered after `/tutor` so that literal path keeps winning.
 */
app.get("/api/tuitions/:id", async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!/^[a-f\d]{24}$/i.test(id)) {
      return fail(res, 404, "Tuition not found.");
    }

    const tuition = await collections
      .tuitions()
      .findOne({ _id: new ObjectId(id) });
    if (!tuition) return fail(res, 404, "Tuition not found.");

    const tutorUser = await collections
      .users()
      .findOne(
        { email: tuition.tutorEmail },
        { projection: { name: 1, email: 1, image: 1, bio: 1, plan: 1 } },
      );

    // টিউশনের ডকুমেন্টে নাম থাকলেও প্রোফাইল সামারি ইউজার কালেকশন থেকেই আসে
    res.json({
      ...tuition,
      _id: String(tuition._id),
      tutor: tutorSummary(tutorUser, tuition),
    });
  } catch (error) {
    next(error);
  }
});

/** PATCH /api/tuitions/:id — update details and/or toggle isActive. */
app.patch(
  "/api/tuitions/:id",
  verifyToken,
  verifyTutor,
  async (req, res, next) => {
    try {
      const tuition = await loadOwnTuition(req, res);
      if (!tuition) return;

      const body = req.body || {};
      const updates = {};

      for (const field of UPDATABLE_FIELDS) {
        if (body[field] !== undefined) {
          updates[field] =
            typeof body[field] === "string" ? body[field].trim() : body[field];
        }
      }

      if (body.monthlyFee !== undefined) {
        const fee = Number(body.monthlyFee);
        if (!Number.isFinite(fee) || fee <= 0) {
          return fail(res, 400, "Monthly fee must be a positive number.");
        }
        updates.monthlyFee = fee;
      }
      if (body.daysPerWeek !== undefined) {
        const days = Number(body.daysPerWeek);
        if (!Number.isInteger(days) || days < 1 || days > 7) {
          return fail(res, 400, "Days per week must be between 1 and 7.");
        }
        updates.daysPerWeek = days;
      }
      if (body.mode !== undefined && !MODES.includes(body.mode)) {
        return fail(res, 400, "Mode must be Online, Offline or Hybrid.");
      }
      // isActive: true / false (status switch on the dashboard)
      if (body.isActive !== undefined) {
        if (typeof body.isActive !== "boolean") {
          return fail(res, 400, "isActive must be true or false.");
        }
        updates.isActive = body.isActive;
      }

      if (Object.keys(updates).length === 0) {
        return fail(res, 400, "Nothing to update.");
      }

      updates.updatedAt = new Date();

      const result = await collections
        .tuitions()
        .findOneAndUpdate(
          { _id: tuition._id },
          { $set: updates },
          { returnDocument: "after" },
        );

      res.json({ ...result, _id: String(result._id) });
    } catch (error) {
      next(error);
    }
  },
);

/** DELETE /api/tuitions/:id */
app.delete(
  "/api/tuitions/:id",
  verifyToken,
  verifyTutor,
  async (req, res, next) => {
    try {
      const tuition = await loadOwnTuition(req, res);
      if (!tuition) return;

      await collections.tuitions().deleteOne({ _id: tuition._id });
      // টিউশন মুছে ফেললে তার পুরনো আবেদনগুলো এডার না রেখে মুছে ফেলা হচ্ছে
      await collections.applications().deleteMany({
        $or: [
          { tuitionId: String(tuition._id) },
          { tuitionId: new ObjectId(tuition._id) },
        ],
      });

      res.json({ message: "Tuition deleted successfully." });
    } catch (error) {
      next(error);
    }
  },
);

/* -------------------------------------------------------------------------- */
/* Applications — /api/applications                                            */
/* -------------------------------------------------------------------------- */

const STATUSES = ["pending", "accepted", "rejected"];

/** Fields the public apply form must send (tApplication storage names below). */
const APPLICATION_FIELDS = [
  "tuitionId",
  "studentEmail",
  "studentName",
  "phone",
  "preferredSchedule",
  "note",
];

/** Fills tuition based fields (title, tutor, fee) onto an application. */
async function withTuitionDetails(applications) {
  const ids = [
    ...new Set(
      applications.map((app) => String(app.tuitionId)).filter((id) => id),
    ),
  ];
  const tuitions = ids.length
    ? await collections
        .tuitions()
        .find({ _id: { $in: tuitionIdIn(ids) } })
        .toArray()
    : [];
  const byId = new Map(
    tuitions.map((tuition) => [String(tuition._id), tuition]),
  );

  return applications.map((application) => {
    const tuition = byId.get(String(application.tuitionId));
    return {
      ...application,
      _id: String(application._id),
      tuitionId: String(application.tuitionId),
      tuitionTitle: tuition?.title ?? application.tuitionTitle ?? "",
      subject: tuition?.subject ?? application.subject ?? "",
      tutorName: tuition?.tutorName ?? application.tutorName ?? "",
      tutorEmail: tuition?.tutorEmail ?? application.tutorEmail ?? "",
      monthlyFee: tuition?.monthlyFee ?? application.monthlyFee ?? 0,
      appliedAt: application.appliedAt ?? application.createdAt ?? null,
      status: application.status || "pending",
    };
  });
}

/**
 * GET /api/applications/check?tuitionId=&email= — instant "already applied?"
 * helper for the public tuition details page. No auth required.
 */
app.get("/api/applications/check", async (req, res, next) => {
  try {
    const tuitionId = String(req.query.tuitionId ?? "").trim();
    const email = String(req.query.email ?? "")
      .trim()
      .toLowerCase();

    if (!tuitionId || !email) {
      return fail(res, 400, "tuitionId and email are required.");
    }

    const existing = await collections.applications().findOne({
      tuitionId: { $in: tuitionIdIn([tuitionId]) },
      studentEmail: email,
    });

    res.json({ hasApplied: Boolean(existing) });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/applications — student applies for a tuition.
 * The session cookie is not required: the applicant's role is verified against
 * the `user` collection using the submitted `studentEmail`.
 */
app.post("/api/applications", async (req, res, next) => {
  try {
    const body = req.body || {};
    const missing = missingFields(body, APPLICATION_FIELDS);
    if (missing.length) {
      return fail(res, 400, `Please fill in: ${missing.join(", ")}.`);
    }

    const tuitionId = String(body.tuitionId).trim();
    const studentEmail = String(body.studentEmail).trim().toLowerCase();

    // শুধু student রোলের অ্যাকাউন্টই আবেদন করতে পারবে
    const student = await collections.users().findOne({ email: studentEmail });
    if (!student || student.role !== "student") {
      return fail(res, 403, "Only students can apply for tuitions.");
    }

    // একই টিউশনে একজন শিক্ষার্থী একবারই আবেদন করতে পারবে
    const existing = await collections.applications().findOne({
      tuitionId: { $in: tuitionIdIn([tuitionId]) },
      studentEmail,
    });
    if (existing) {
      return fail(res, 409, "You have already applied for this tuition.");
    }

    const appliedAt = new Date();
    const doc = {
      tuitionId,
      studentName: String(body.studentName).trim(),
      studentEmail,
      studentPhone: String(body.phone).trim(),
      preferredSchedule: String(body.preferredSchedule).trim(),
      studentNote: String(body.note).trim(),
      status: "pending",
      appliedAt,
      createdAt: appliedAt,
    };

    const result = await collections.applications().insertOne(doc);
    res.status(201).json({ ...doc, _id: String(result.insertedId) });
  } catch (error) {
    next(error);
  }
});

/** GET /api/applications/student?email= — my applications (with tuition info). */
app.get(
  "/api/applications/student",
  verifyToken,
  verifyStudent,
  requireSelfOrAdmin,
  async (req, res, next) => {
    try {
      const email = String(req.query.email).toLowerCase();
      const applications = await collections
        .applications()
        .find({ studentEmail: email })
        .sort({ appliedAt: -1 })
        .toArray();

      res.json(await withTuitionDetails(applications));
    } catch (error) {
      next(error);
    }
  },
);

/** GET /api/applications/tutor?email= — applicants on my tuitions. */
app.get(
  "/api/applications/tutor",
  verifyToken,
  verifyTutor,
  requireSelfOrAdmin,
  async (req, res, next) => {
    try {
      const email = String(req.query.email).toLowerCase();
      const tuitions = await collections
        .tuitions()
        .find({ tutorEmail: email })
        .toArray();
      const tuitionIds = tuitionIdIn(tuitions.map((tuition) => tuition._id));

      const applications = tuitionIds.length
        ? await collections
            .applications()
            .find({ tuitionId: { $in: tuitionIds } })
            .sort({ appliedAt: -1 })
            .toArray()
        : [];

      res.json(await withTuitionDetails(applications));
    } catch (error) {
      next(error);
    }
  },
);

/** PATCH /api/applications/:id/status — accept / reject an applicant. */
app.patch(
  "/api/applications/:id/status",
  verifyToken,
  verifyTutor,
  async (req, res, next) => {
    try {
      const _id = getObjectId(req, res);
      if (!_id) return;

      const status = req.body?.status;
      if (!STATUSES.includes(status)) {
        return fail(res, 400, "Status must be pending, accepted or rejected.");
      }

      const application = await collections.applications().findOne({ _id });
      if (!application) return fail(res, 404, "Application not found.");

      const tuition = await collections.tuitions().findOne({
        _id: { $in: tuitionIdIn([application.tuitionId]) },
      });
      if (!tuition) return fail(res, 404, "Tuition not found.");
      if (req.user.role !== "admin" && tuition.tutorEmail !== req.user.email) {
        return fail(
          res,
          403,
          "You are not allowed to update this application.",
        );
      }

      const updated = await collections
        .applications()
        .findOneAndUpdate(
          { _id },
          { $set: { status, updatedAt: new Date() } },
          { returnDocument: "after" },
        );

      const [result] = await withTuitionDetails([updated]);
      res.json(result);
    } catch (error) {
      next(error);
    }
  },
);

/** DELETE /api/applications/:id — student cancels a pending application. */
app.delete(
  "/api/applications/:id",
  verifyToken,
  verifyStudent,
  async (req, res, next) => {
    try {
      const _id = getObjectId(req, res);
      if (!_id) return;

      const application = await collections.applications().findOne({ _id });
      if (!application) return fail(res, 404, "Application not found.");

      if (
        req.user.role !== "admin" &&
        application.studentEmail !== req.user.email
      ) {
        return fail(
          res,
          403,
          "You are not allowed to cancel this application.",
        );
      }

      // শুধু pending আবেদন বাতিল করা যাবে
      if (application.status !== "pending") {
        return fail(res, 400, "Only pending applications can be cancelled.");
      }

      await collections.applications().deleteOne({ _id });
      res.json({ message: "Application cancelled successfully." });
    } catch (error) {
      next(error);
    }
  },
);

/* -------------------------------------------------------------------------- */
/* Profile — /api/profile (any authenticated role, no role gate)              */
/* -------------------------------------------------------------------------- */

/** Shape sent to the client: the editable tUserEdit fields + display context. */
function toProfileDoc(user) {
  return {
    _id: String(user._id),
    name: user.name || "",
    email: user.email || "",
    image: user.image || "",
    phone: user.phone || "",
    bio: user.bio || "",
    role: user.role || "student",
    plan: user.plan || "free",
    createdAt: user.createdAt || null,
  };
}

/** GET /api/profile — the caller's own document (phone/bio are not in the session). */
app.get("/api/profile", verifyToken, async (req, res, next) => {
  try {
    const user = await collections
      .users()
      .findOne({ _id: toObjectId(req.user.id) });
    if (!user) return fail(res, 404, "User not found.");
    res.json(toProfileDoc(user));
  } catch (error) {
    next(error);
  }
});

/**
 * PATCH /api/profile — update the caller's own profile.
 *
 * Identity always comes from `verifyToken` (`req.user.id`), never the body,
 * and only the whitelisted `tUserEdit` fields are written — so role/plan
 * cannot be escalated through this endpoint. A changed email is checked for
 * uniqueness (case-insensitive, excluding this user) before saving.
 */
app.patch("/api/profile", verifyToken, async (req, res, next) => {
  try {
    const body = req.body || {};
    const users = collections.users();
    const userId = toObjectId(req.user.id);

    const name = typeof body.name === "string" ? body.name.trim() : "";
    const email = typeof body.email === "string" ? body.email.trim() : "";
    const image = typeof body.image === "string" ? body.image.trim() : "";
    const phone = typeof body.phone === "string" ? body.phone.trim() : "";
    const bio = typeof body.bio === "string" ? body.bio.trim() : "";

    const missing = missingFields({ name, email }, ["name", "email"]);
    if (missing.length > 0) {
      return fail(res, 400, `Please fill in: ${missing.join(", ")}`);
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return fail(res, 400, "Please provide a valid email address.");
    }

    const current = await users.findOne({ _id: userId });
    if (!current) return fail(res, 404, "User not found.");

    // ইমেইল বদলালে অন্য অ্যাকাউন্টের সাথে কনফ্লিক্ট করতে পারবে না (case-insensitive)
    if (email.toLowerCase() !== String(current.email || "").toLowerCase()) {
      const clash = await users.findOne({
        email: { $regex: `^${escapeRegExp(email)}$`, $options: "i" },
        _id: { $ne: userId },
      });
      if (clash) {
        return fail(
          res,
          409,
          "That email address is already in use by another account.",
        );
      }
    }

    await users.updateOne(
      { _id: userId },
      { $set: { name, email, image, phone, bio, updatedAt: new Date() } },
    );

    const updated = await users.findOne({ _id: userId });
    if (!updated) return fail(res, 404, "User not found.");
    res.json(toProfileDoc(updated));
  } catch (error) {
    next(error);
  }
});

/* -------------------------------------------------------------------------- */
/* Admin — /api/admin                                                          */
/* -------------------------------------------------------------------------- */

const ROLES = ["student", "tutor", "admin"];
const APPROVALS = ["approved", "rejected"];

/** GET /api/admin/users — everyone registered on the platform. */
app.get(
  "/api/admin/users",
  verifyToken,
  verifyAdmin,
  async (_req, res, next) => {
    try {
      const users = await collections
        .users()
        .find({}, { projection: { emailVerified: 0, updatedAt: 0 } })
        .sort({ createdAt: -1 })
        .toArray();

      res.json(users.map((user) => ({ ...user, _id: String(user._id) })));
    } catch (error) {
      next(error);
    }
  },
);

/** PATCH /api/admin/users/:id/role — student | tutor | admin */
app.patch(
  "/api/admin/users/:id/role",
  verifyToken,
  verifyAdmin,
  async (req, res, next) => {
    try {
      const _id = getObjectId(req, res);
      if (!_id) return;

      const { role } = req.body || {};
      if (!ROLES.includes(role)) {
        return fail(res, 400, "Role must be student, tutor or admin.");
      }
      if (String(_id) === req.user.id) {
        return fail(res, 400, "You cannot change your own role.");
      }

      const user = await collections.users().findOne({ _id });
      if (!user) return fail(res, 404, "User not found.");

      const updated = await collections
        .users()
        .findOneAndUpdate(
          { _id },
          { $set: { role } },
          { returnDocument: "after" },
        );

      res.json({ ...updated, _id: String(updated._id) });
    } catch (error) {
      next(error);
    }
  },
);

/** GET /api/admin/tuitions — every tuition post on the platform. */
app.get(
  "/api/admin/tuitions",
  verifyToken,
  verifyAdmin,
  async (_req, res, next) => {
    try {
      const tuitions = await collections
        .tuitions()
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      res.json(
        tuitions.map((tuition) => ({ ...tuition, _id: String(tuition._id) })),
      );
    } catch (error) {
      next(error);
    }
  },
);

/** PATCH /api/admin/tuitions/:id/approval — approved | rejected */
app.patch(
  "/api/admin/tuitions/:id/approval",
  verifyToken,
  verifyAdmin,
  async (req, res, next) => {
    try {
      const _id = getObjectId(req, res);
      if (!_id) return;

      const { approvalStatus } = req.body || {};
      if (!APPROVALS.includes(approvalStatus)) {
        return fail(res, 400, "approvalStatus must be approved or rejected.");
      }

      const tuition = await collections.tuitions().findOne({ _id });
      if (!tuition) return fail(res, 404, "Tuition not found.");

      const updated = await collections
        .tuitions()
        .findOneAndUpdate(
          { _id },
          { $set: { approvalStatus, updatedAt: new Date() } },
          { returnDocument: "after" },
        );

      res.json({ ...updated, _id: String(updated._id) });
    } catch (error) {
      next(error);
    }
  },
);

/** GET /api/admin/transactions — all Stripe payment records. */
app.get(
  "/api/admin/transactions",
  verifyToken,
  verifyAdmin,
  async (_req, res, next) => {
    try {
      const payments = await collections
        .payments()
        .find({})
        .sort({ paidAt: -1 })
        .toArray();

      res.json(
        payments.map((payment) => ({ ...payment, _id: String(payment._id) })),
      );
    } catch (error) {
      next(error);
    }
  },
);

/* -------------------------------------------------------------------------- */
/* payments with stripe related api's                       */
/* -------------------------------------------------------------------------- */

app.post("/payments/checkout-verify", async (req, res) => {
  const { sessionId } = req.body;

  if (!sessionId) {
    return res.send({ success: false, message: "Session ID is required" });
  }

  const { status, payment_status, customer_email, metadata, payment_intent } =
    await stripe.checkout.sessions.retrieve(sessionId);

  // 1. is used new session
  // 2. check is the session id for the currently logged in user
  // 3. insert sessionId into the payment Collection
  // 4. update user information as premium user

  if (status === "complete" && payment_status === "paid") {
    const sessionQuery = { sessionId };
    const existingPayment = await payments.findOne(sessionQuery);
    if (existingPayment) {
      return res.send({ success: false, message: "Payment already verified" });
    }
    const payment = {
      sessionId,
      status,
      payment_status,
      customer_email,
      userId: metadata.userId,
      payment_date: new Date(),
      payment_intent,
    };

    const result = await payments.insertOne(payment);

    // update the user table
    const query = { _id: new ObjectId(metadata.userId) };

    const updatedDoc = {
      $set: {
        premium: true,
      },
    };
    const updateResult = await users.updateOne(query, updatedDoc);
    res.send({ success: true, result, updateResult });
    return;
  }
  res.send({ success: false, message: "Payment verification failed" });
});

/* -------------------------------------------------------------------------- */
/* 404 + error fallbacks (registered after every route)                        */
/* -------------------------------------------------------------------------- */

// রাউট না পেলে
app.use((_req, res) => {
  res.status(404).json({ message: "Route not found." });
});

// গ্লোবাল এরর হ্যান্ডলার
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(err.status || 500).json({
    message: err.message || "Something went wrong on the server.",
  });
});

/* -------------------------------------------------------------------------- */
/* Bootstrap                                                                   */
/* -------------------------------------------------------------------------- */

const port = process.env.PORT || 5000;

await connectToMongoDB();

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});

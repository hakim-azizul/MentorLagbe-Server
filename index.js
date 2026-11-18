/**
 * MentorLagbe — Express REST API (single file).
 *
 * Everything lives here: MongoDB access, Better Auth session middleware,
 * shared helpers, all route groups and the bootstrap. Database: `MentorLagbeDb`.
 *
 * Route groups:
 *   GET    /                        welcome
 *   /api/dashboard/*                role stats (student | tutor | admin)
 *   GET    /api/tuitions            public: approved & active tuitions (filterable)
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
 *   /api/admin/*                     admin: users, tuitions, transactions
 */
import "dotenv/config";
import { createHmac, timingSafeEqual } from "node:crypto";
import express, { Router } from "express";
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
    if (/^[a-f\d]{24}$/i.test(String(id))) variants.push(new ObjectId(String(id)));
  }
  return variants;
}

/** Escapes user input before building a RegExp (public search filter). */
function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/* -------------------------------------------------------------------------- */
/* Better Auth session middleware                                              */
/* -------------------------------------------------------------------------- */

/** Better Auth session cookie names (http + https prefixed variants). */
const SESSION_COOKIE_NAMES = [
  "better-auth.session_token",
  "__Secure-better-auth.session_token",
];

/** Minimal cookie header parser (no extra dependency needed). */
function parseCookies(cookieHeader = "") {
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
async function getAuthUser(req) {
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
function requireRole(...roles) {
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
const originAllowList = allowedOrigins.length ? allowedOrigins : DEFAULT_ORIGINS;

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
  })
);

app.use(express.json({ limit: "1mb" }));

app.get("/", (_req, res) => {
  res.send("Welcome to MentorLagbe server");
});

/* -------------------------------------------------------------------------- */
/* Dashboard stats — GET /api/dashboard/{student|tutor|admin}/stats            */
/* -------------------------------------------------------------------------- */

const dashboardRouter = Router();

/** GET /api/dashboard/student/stats?email= */
dashboardRouter.get(
  "/student/stats",
  requireRole("student", "admin"),
  requireSelfOrAdmin,
  async (req, res, next) => {
    try {
      const email = String(req.query.email).toLowerCase();

      const user = await collections.users().findOne({ email });
      if (!user) return fail(res, 404, "User not found.");

      const filter = { studentEmail: email };
      const [totalApplied, acceptedCount, pendingCount] = await Promise.all([
        collections.applications().countDocuments(filter),
        collections.applications().countDocuments({ ...filter, status: "accepted" }),
        collections.applications().countDocuments({ ...filter, status: "pending" }),
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
  }
);

/** GET /api/dashboard/tutor/stats?email= */
dashboardRouter.get(
  "/tutor/stats",
  requireRole("tutor", "admin"),
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
        collections.tuitions().find(tuitionFilter, { projection: { _id: 1 } }).toArray(),
      ]);

      const tuitionIds = tuitionIdIn(tuitions.map((tuition) => tuition._id));
      const totalApplicants = tuitionIds.length
        ? await collections.applications().countDocuments({
            tuitionId: { $in: tuitionIds },
          })
        : 0;

      res.json({ totalPosted, approvedCount, totalApplicants, plan: user.plan || "free" });
    } catch (error) {
      next(error);
    }
  }
);

/** GET /api/dashboard/admin/stats */
dashboardRouter.get("/admin/stats", requireRole("admin"), async (_req, res, next) => {
  try {
    const [totalUsers, totalTutors, pendingTuitions, approvedTuitions, revenue] =
      await Promise.all([
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
});

/* -------------------------------------------------------------------------- */
/* Tuitions — /api/tuitions                                                    */
/* -------------------------------------------------------------------------- */

const tuitionsRouter = Router();

const MODES = ["Online", "Offline", "Hybrid"];

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

/** POST /api/tuitions — creates a post with approvalStatus: 'pending'. */
tuitionsRouter.post("/", requireRole("tutor", "admin"), async (req, res, next) => {
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
        "Free plan tutors can only post up to 2 tuitions. Upgrade to Pro for unlimited posts."
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
 * Optional filters: `search` (case-insensitive regex on title/subject),
 * `subject`, `classLevel`, `mode`. Sorted newest first. No auth required.
 */
tuitionsRouter.get("/", async (req, res, next) => {
  try {
    const { search, subject, classLevel, mode } = req.query;

    const filter = { approvalStatus: "approved", isActive: true };

    const term = String(search ?? "").trim();
    if (term) {
      const pattern = new RegExp(escapeRegExp(term), "i");
      filter.$or = [{ title: pattern }, { subject: pattern }];
    }
    if (String(subject ?? "").trim()) filter.subject = String(subject).trim();
    if (String(classLevel ?? "").trim()) filter.classLevel = String(classLevel).trim();
    if (String(mode ?? "").trim()) filter.mode = String(mode).trim();

    const tuitions = await collections
      .tuitions()
      .find(filter)
      .sort({ createdAt: -1 })
      .toArray();

    res.json(
      tuitions.map((tuition) => ({ ...tuition, _id: String(tuition._id) }))
    );
  } catch (error) {
    next(error);
  }
});

/** GET /api/tuitions/tutor?email= — every tuition created by this tutor. */
tuitionsRouter.get(
  "/tutor",
  requireRole("tutor", "admin"),
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
        tuitions.map((tuition) => ({ ...tuition, _id: String(tuition._id) }))
      );
    } catch (error) {
      next(error);
    }
  }
);

/**
 * GET /api/tuitions/:id — public tuition details with the tutor's profile
 * summary (`name`, `email`, `image`, `bio`, `plan`) from the `user` collection.
 * Registered after `/tutor` so that literal path keeps winning.
 */
tuitionsRouter.get("/:id", async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!/^[a-f\d]{24}$/i.test(id)) {
      return fail(res, 404, "Tuition not found.");
    }

    const tuition = await collections.tuitions().findOne({ _id: new ObjectId(id) });
    if (!tuition) return fail(res, 404, "Tuition not found.");

    const tutorUser = await collections.users().findOne(
      { email: tuition.tutorEmail },
      { projection: { _id: 0, name: 1, email: 1, image: 1, bio: 1, plan: 1 } }
    );

    res.json({
      ...tuition,
      _id: String(tuition._id),
      // টিউশনের ডকুমেন্টে নাম থাকলেও প্রোফাইল সামারি ইউজার কালেকশন থেকেই আসে
      tutor: {
        name: tutorUser?.name || tuition.tutorName || "",
        email: tutorUser?.email || tuition.tutorEmail || "",
        image: tutorUser?.image || "",
        bio: tutorUser?.bio || "",
        plan: tutorUser?.plan || "free",
      },
    });
  } catch (error) {
    next(error);
  }
});

/** PATCH /api/tuitions/:id — update details and/or toggle isActive. */
tuitionsRouter.patch("/:id", requireRole("tutor", "admin"), async (req, res, next) => {
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
        { returnDocument: "after" }
      );

    res.json({ ...result, _id: String(result._id) });
  } catch (error) {
    next(error);
  }
});

/** DELETE /api/tuitions/:id */
tuitionsRouter.delete("/:id", requireRole("tutor", "admin"), async (req, res, next) => {
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
});

/* -------------------------------------------------------------------------- */
/* Applications — /api/applications                                            */
/* -------------------------------------------------------------------------- */

const applicationsRouter = Router();

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
      applications.map((app) => String(app.tuitionId)).filter((id) => id)
    ),
  ];
  const tuitions = ids.length
    ? await collections
        .tuitions()
        .find({ _id: { $in: tuitionIdIn(ids) } })
        .toArray()
    : [];
  const byId = new Map(tuitions.map((tuition) => [String(tuition._id), tuition]));

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
applicationsRouter.get("/check", async (req, res, next) => {
  try {
    const tuitionId = String(req.query.tuitionId ?? "").trim();
    const email = String(req.query.email ?? "").trim().toLowerCase();

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
applicationsRouter.post("/", async (req, res, next) => {
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
applicationsRouter.get(
  "/student",
  requireRole("student", "admin"),
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
  }
);

/** GET /api/applications/tutor?email= — applicants on my tuitions. */
applicationsRouter.get(
  "/tutor",
  requireRole("tutor", "admin"),
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
  }
);

/** PATCH /api/applications/:id/status — accept / reject an applicant. */
applicationsRouter.patch(
  "/:id/status",
  requireRole("tutor", "admin"),
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
        return fail(res, 403, "You are not allowed to update this application.");
      }

      const updated = await collections
        .applications()
        .findOneAndUpdate(
          { _id },
          { $set: { status, updatedAt: new Date() } },
          { returnDocument: "after" }
        );

      const [result] = await withTuitionDetails([updated]);
      res.json(result);
    } catch (error) {
      next(error);
    }
  }
);

/** DELETE /api/applications/:id — student cancels a pending application. */
applicationsRouter.delete(
  "/:id",
  requireRole("student", "admin"),
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
        return fail(res, 403, "You are not allowed to cancel this application.");
      }

      // শুধু pending আবেদন বাতিল করা যাবে
      if (application.status !== "pending") {
        return fail(
          res,
          400,
          "Only pending applications can be cancelled."
        );
      }

      await collections.applications().deleteOne({ _id });
      res.json({ message: "Application cancelled successfully." });
    } catch (error) {
      next(error);
    }
  }
);

/* -------------------------------------------------------------------------- */
/* Admin — /api/admin                                                          */
/* -------------------------------------------------------------------------- */

const adminRouter = Router();

const ROLES = ["student", "tutor", "admin"];
const APPROVALS = ["approved", "rejected"];

/** GET /api/admin/users — everyone registered on the platform. */
adminRouter.get("/users", requireRole("admin"), async (_req, res, next) => {
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
});

/** PATCH /api/admin/users/:id/role — student | tutor | admin */
adminRouter.patch("/users/:id/role", requireRole("admin"), async (req, res, next) => {
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
        { returnDocument: "after" }
      );

    res.json({ ...updated, _id: String(updated._id) });
  } catch (error) {
    next(error);
  }
});

/** GET /api/admin/tuitions — every tuition post on the platform. */
adminRouter.get("/tuitions", requireRole("admin"), async (_req, res, next) => {
  try {
    const tuitions = await collections
      .tuitions()
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    res.json(tuitions.map((tuition) => ({ ...tuition, _id: String(tuition._id) })));
  } catch (error) {
    next(error);
  }
});

/** PATCH /api/admin/tuitions/:id/approval — approved | rejected */
adminRouter.patch(
  "/tuitions/:id/approval",
  requireRole("admin"),
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
          { returnDocument: "after" }
        );

      res.json({ ...updated, _id: String(updated._id) });
    } catch (error) {
      next(error);
    }
  }
);

/** GET /api/admin/transactions — all Stripe payment records. */
adminRouter.get("/transactions", requireRole("admin"), async (_req, res, next) => {
  try {
    const payments = await collections
      .payments()
      .find({})
      .sort({ paidAt: -1 })
      .toArray();

    res.json(payments.map((payment) => ({ ...payment, _id: String(payment._id) })));
  } catch (error) {
    next(error);
  }
});

/* -------------------------------------------------------------------------- */
/* Mount + fallbacks                                                           */
/* -------------------------------------------------------------------------- */

app.use("/api/dashboard", dashboardRouter);
app.use("/api/tuitions", tuitionsRouter);
app.use("/api/applications", applicationsRouter);
app.use("/api/admin", adminRouter);

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

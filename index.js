import "dotenv/config";
import { createRemoteJWKSet, jwtVerify } from "jose";
import express from "express";
import cors from "cors";
import Stripe from "stripe";
import { MongoClient, ObjectId } from "mongodb";

/* MongoDB */

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

const collections = {
  users: () => getDb().collection("user"),
  sessions: () => getDb().collection("session"),
  tuitions: () => getDb().collection("tuitions"),
  applications: () => getDb().collection("applications"),
  payments: () => getDb().collection("payments"),
  savedTuitions: () => getDb().collection("saveduitions"),
};

/* Shared helpers */

function fail(res, status, message) {
  return res.status(status).json({ message });
}

function getObjectId(req, res) {
  const { id } = req.params;
  if (!/^[a-f\d]{24}$/i.test(id)) {
    res.status(400).json({ message: "Invalid id." });
    return null;
  }
  return new ObjectId(id);
}

function missingFields(body, fields) {
  return fields.filter((field) => {
    const value = body?.[field];
    return value === undefined || value === null || String(value).trim() === "";
  });
}

function tuitionIdIn(ids) {
  const variants = [];
  for (const id of ids) {
    variants.push(String(id));
    if (/^[a-f\d]{24}$/i.test(String(id)))
      variants.push(new ObjectId(String(id)));
  }
  return variants;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function positiveInt(value, fallback, max) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed) || parsed < 1) return fallback;
  return Math.min(parsed, max);
}

/* Stripe */

// Lazily create Stripe so the API boots without credentials; Stripe routes throw a clear 500.
let stripeClient = null;

function getStripe() {
  const secretKey = process.env.STRIPE_SECRET_KEY;
  if (!secretKey) {
    const error = new Error("STRIPE_SECRET_KEY is not configured.");
    error.status = 500;
    throw error;
  }
  if (!stripeClient) stripeClient = new Stripe(secretKey);
  return stripeClient;
}

function isValidObjectId(value) {
  return /^[a-f\d]{24}$/i.test(String(value ?? ""));
}

// Shared by verify + webhook; idempotent via unique payments.stripeSessionId.
async function syncProPlan(session) {
  const userId = String(session?.metadata?.userId ?? "").trim();

  if (!isValidObjectId(userId)) {
    return {
      ok: false,
      status: 400,
      message: "Checkout session is missing a valid userId.",
    };
  }

  const user = await collections.users().findOne({ _id: new ObjectId(userId) });
  if (!user) {
    return {
      ok: false,
      status: 404,
      message: "The user for this payment no longer exists.",
    };
  }

  // Metadata role is authoritative; stored role is a fallback for legacy sessions.
  const metadataRole = String(session?.metadata?.role ?? "").trim();
  const role = ["student", "tutor"].includes(metadataRole)
    ? metadataRole
    : user.role;

  if (role !== "student" && role !== "tutor") {
    return {
      ok: false,
      status: 400,
      message: "Pro plan is only available to students and tutors.",
    };
  }

  const paymentIntentId =
    typeof session.payment_intent === "string"
      ? session.payment_intent
      : session.payment_intent?.id;

  const paymentDoc = {
    userId,
    userName: user.name || session.customer_details?.name || "MentorLagbe user",
    userEmail:
      user.email ||
      session.customer_details?.email ||
      session.customer_email ||
      "",
    userRole: role,
    planName: "pro",
    // amount is stored in major units (15, not 1500).
    amount: Number(session.amount_total ?? 0) / 100,
    currency: String(session.currency || "usd").toUpperCase(),
    transactionId: paymentIntentId || session.id,
    stripeSessionId: session.id,
    paymentStatus: "paid",
    paidAt: new Date((session.created ?? Math.floor(Date.now() / 1000)) * 1000),
    createdAt: new Date(),
  };

  let duplicate = false;
  try {
    const result = await collections.payments().updateOne(
      { stripeSessionId: session.id },
      { $setOnInsert: paymentDoc },
      { upsert: true },
    );
    duplicate = result.upsertedCount === 0;
  } catch (error) {
    // Duplicate key = webhook/verify race; treat as already recorded.
    if (error?.code === 11000) duplicate = true;
    else throw error;
  }

  // Re-assert Pro so a replay repairs a partially failed first run.
  await collections.users().updateOne(
    { _id: new ObjectId(userId) },
    { $set: { plan: "pro", updatedAt: new Date() } },
  );

  return { ok: true, duplicate, role };
}

async function ensurePaymentIndexes() {
  try {
    await collections.payments().createIndex(
      { stripeSessionId: 1 },
      {
        unique: true,
        name: "uniq_stripeSessionId",
        partialFilterExpression: { stripeSessionId: { $type: "string" } },
      },
    );
  } catch (error) {
    console.warn(
      `[payments] Could not create unique stripeSessionId index: ${error.message}`,
    );
  }
}

// One bookmark per student+tuition, enforced by MongoDB.
async function ensureSavedTuitionIndexes() {
  try {
    await collections.savedTuitions().createIndex(
      { student: 1, tuition: 1 },
      { unique: true, name: "uniq_saved_student_tuition" },
    );
  } catch (error) {
    console.warn(
      `[saveduitions] Could not create unique student+tuition index: ${error.message}`,
    );
  }
}

/* Better Auth JWT verification (JWKS) + role middleware */

const JWT_ISSUER = (
  process.env.JWT_ISSUER ||
  process.env.BETTER_AUTH_URL ||
  "http://localhost:3000"
).replace(/\/+$/, "");
const JWT_AUDIENCE = (
  process.env.JWT_AUDIENCE || `http://localhost:${process.env.PORT || 5000}`
).replace(/\/+$/, "");
const JWKS_URL = process.env.JWKS_URL || `${JWT_ISSUER}/api/auth/jwks`;

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

// DB is authoritative for role/plan: token claims only seed brand-new users.
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
      // Duplicate-key race: another request created this user first.
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
      // Token problem vs JWKS fetch failure — the latter is a 503.
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

// Role gates run after verifyToken; student/tutor gates also admit admins.
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

/* App + CORS */

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
      if (!origin || originAllowList.includes(origin)) {
        return callback(null, origin || false);
      }
      callback(new Error(`Origin ${origin} is not allowed by CORS.`));
    },
    credentials: true,
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    exposedHeaders: [
      "X-Page",
      "X-Limit",
      "X-Total-Items",
      "X-Total-Pages",
      "X-Has-Next-Page",
      "X-Has-Prev-Page",
    ],
  }),
);

// Webhook MUST precede express.json() — Stripe signs the exact raw bytes.
app.post(
  "/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const signature = req.headers["stripe-signature"];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!signature) {
      return res.status(400).json({ message: "Missing stripe-signature header." });
    }
    if (!webhookSecret) {
      console.error("[stripe] STRIPE_WEBHOOK_SECRET is not configured.");
      return res.status(500).json({ message: "Webhook secret is not configured." });
    }

    let event;
    try {
      event = getStripe().webhooks.constructEvent(
        req.body,
        signature,
        webhookSecret,
      );
    } catch (error) {
      console.error(
        `[stripe] Webhook signature verification failed: ${error.message}`,
      );
      return res.status(400).json({ message: "Invalid webhook signature." });
    }

    try {
      if (
        event.type === "checkout.session.completed" ||
        event.type === "checkout.session.async_payment_succeeded"
      ) {
        const session = event.data.object;
        if (session.payment_status === "paid") {
          const result = await syncProPlan(session);
          if (!result.ok) {
            console.error(
              `[stripe] Could not activate Pro for session ${session.id}: ${result.message}`,
            );
          }
        }
      }
    } catch (error) {
      // Non-2xx makes Stripe retry the event.
      console.error(`[stripe] Webhook handler failed: ${error.message}`);
      return res.status(500).json({ message: "Webhook handler failed." });
    }

    res.json({ received: true });
  },
);

app.use(express.json({ limit: "1mb" }));

app.get("/", (_req, res) => {
  res.send("Welcome to MentorLagbe server");
});

/* Dashboard stats — GET /api/dashboard/{student|tutor|admin}/stats */

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

/* Tuitions — /api/tuitions */

const MODES = ["Online", "Offline", "Hybrid"];

const TUITION_SORTS = {
  newest: { createdAt: -1 },
  oldest: { createdAt: 1 },
  fee_asc: { monthlyFee: 1 },
  fee_desc: { monthlyFee: -1 },
};

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

function tutorSummary(tutorUser, tuition) {
  return {
    name: tutorUser?.name || tuition.tutorName || "",
    email: tutorUser?.email || tuition.tutorEmail || "",
    image: tutorUser?.image || "",
    bio: tutorUser?.bio || "",
    plan: tutorUser?.plan || "free",
  };
}

async function withSavedTuitionDetails(savedDocs) {
  const tuitionIds = [
    ...new Set(savedDocs.map((doc) => doc.tuition).filter(Boolean)),
  ];
  const tuitions = tuitionIds.length
    ? await collections
        .tuitions()
        .find({ _id: { $in: tuitionIds } })
        .toArray()
    : [];
  const byId = new Map(tuitions.map((tuition) => [String(tuition._id), tuition]));

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

  return savedDocs.flatMap((saved) => {
    const tuition = byId.get(String(saved.tuition));
    if (!tuition) return [];
    return [
      {
        ...tuition,
        _id: String(tuition._id),
        tutor: tutorSummary(tutorByEmail.get(tuition.tutorEmail), tuition),
        savedAt: saved.createdAt ?? null,
      },
    ];
  });
}

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

    // Free plan: at most 2 tuition posts.
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

// GET /api/tuitions: array by default; ?meta=1 adds pagination; X-* headers always.
app.get("/api/tuitions", async (req, res, next) => {
  try {
    const {
      search,
      subject,
      classLevel,
      mode,
      sort,
      page: pageQuery,
      limit: limitQuery,
      meta,
    } = req.query;

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

    const limit = positiveInt(limitQuery, 12, 50);
    const totalItems = await collections.tuitions().countDocuments(filter);
    const totalPages = Math.max(1, Math.ceil(totalItems / limit));
    const requestedPage = positiveInt(pageQuery, 1, Number.MAX_SAFE_INTEGER);
    // Clamp stale out-of-range ?page to the last page.
    const page = Math.min(requestedPage, totalPages);
    const hasNextPage = page < totalPages;
    const hasPrevPage = page > 1;

    const tuitions = await collections
      .tuitions()
      .find(filter)
      .sort(sortSpec)
      .skip((page - 1) * limit)
      .limit(limit)
      .toArray();

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

    const items = tuitions.map((tuition) => ({
      ...tuition,
      _id: String(tuition._id),
      tutor: tutorSummary(tutorByEmail.get(tuition.tutorEmail), tuition),
    }));
    const pagination = {
      page,
      limit,
      totalItems,
      totalPages,
      hasNextPage,
      hasPrevPage,
    };

    res.set({
      "X-Page": String(page),
      "X-Limit": String(limit),
      "X-Total-Items": String(totalItems),
      "X-Total-Pages": String(totalPages),
      "X-Has-Next-Page": String(hasNextPage),
      "X-Has-Prev-Page": String(hasPrevPage),
    });

    if (String(meta ?? "") === "1") {
      return res.json({ items, ...pagination });
    }
    res.json(items);
  } catch (error) {
    next(error);
  }
});

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

// Keep /tutor registered before /:id so the literal path wins.
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

    res.json({
      ...tuition,
      _id: String(tuition._id),
      tutor: tutorSummary(tutorUser, tuition),
    });
  } catch (error) {
    next(error);
  }
});

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

app.delete(
  "/api/tuitions/:id",
  verifyToken,
  verifyTutor,
  async (req, res, next) => {
    try {
      const tuition = await loadOwnTuition(req, res);
      if (!tuition) return;

      await collections.tuitions().deleteOne({ _id: tuition._id });
      await collections.applications().deleteMany({
        $or: [
          { tuitionId: String(tuition._id) },
          { tuitionId: new ObjectId(tuition._id) },
        ],
      });
      await collections.savedTuitions().deleteMany({ tuition: tuition._id });

      res.json({ message: "Tuition deleted successfully." });
    } catch (error) {
      next(error);
    }
  },
);

/* Applications — /api/applications */

const STATUSES = ["pending", "accepted", "rejected"];

const APPLICATION_FIELDS = [
  "tuitionId",
  "studentEmail",
  "studentName",
  "phone",
  "preferredSchedule",
  "note",
];

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

app.post("/api/applications", async (req, res, next) => {
  try {
    const body = req.body || {};
    const missing = missingFields(body, APPLICATION_FIELDS);
    if (missing.length) {
      return fail(res, 400, `Please fill in: ${missing.join(", ")}.`);
    }

    const tuitionId = String(body.tuitionId).trim();
    const studentEmail = String(body.studentEmail).trim().toLowerCase();

    const student = await collections.users().findOne({ email: studentEmail });
    if (!student || student.role !== "student") {
      return fail(res, 403, "Only students can apply for tuitions.");
    }

    // Tuition lookup supplies the tutor link and display fields.
    const tuition = await collections.tuitions().findOne({
      _id: { $in: tuitionIdIn([tuitionId]) },
    });
    if (!tuition) return fail(res, 404, "Tuition not found.");

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
      tutorEmail: tuition.tutorEmail || "",
      tutorName: tuition.tutorName || "",
      tuitionTitle: tuition.title || "",
      subject: tuition.subject || "",
      monthlyFee: Number(tuition.monthlyFee || 0),
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

      // Only pending applications may be cancelled.
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

/* Saved tuitions — /api/saved-tuitions (authenticated students) */

// Free students: 5 bookmarks; Pro: unlimited.
const FREE_SAVED_TUITION_LIMIT = 5;

app.get(
  "/api/saved-tuitions/ids",
  verifyToken,
  verifyStudent,
  async (req, res, next) => {
    try {
      const studentId = toObjectId(req.user.id);
      if (!studentId) return fail(res, 400, "Invalid student account.");

      const docs = await collections
        .savedTuitions()
        .find({ student: studentId }, { projection: { tuition: 1 } })
        .toArray();

      res.json({ savedIds: docs.map((doc) => String(doc.tuition)) });
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/saved-tuitions",
  verifyToken,
  verifyStudent,
  async (req, res, next) => {
    try {
      const studentId = toObjectId(req.user.id);
      if (!studentId) return fail(res, 400, "Invalid student account.");

      const docs = await collections
        .savedTuitions()
        .find({ student: studentId })
        .sort({ createdAt: -1 })
        .toArray();

      res.json(await withSavedTuitionDetails(docs));
    } catch (error) {
      next(error);
    }
  },
);

// Toggle identity comes from the verified user, never the request body.
app.post(
  "/api/saved-tuitions/toggle",
  verifyToken,
  verifyStudent,
  async (req, res, next) => {
    try {
      const studentId = toObjectId(req.user.id);
      if (!studentId) return fail(res, 400, "Invalid student account.");

      const tuitionId = toObjectId(req.body?.tuitionId);
      if (!tuitionId) return fail(res, 400, "A valid tuitionId is required.");

      const tuition = await collections.tuitions().findOne({ _id: tuitionId });
      if (!tuition) return fail(res, 404, "Tuition not found.");

      const saved = await collections
        .savedTuitions()
        .findOne({ student: studentId, tuition: tuitionId });

      if (saved) {
        await collections.savedTuitions().deleteOne({ _id: saved._id });
        return res.json({ saved: false });
      }

      // Free plan cap: 5 saves; unsaving is never capped.
      if (req.user.plan !== "pro") {
        const savedCount = await collections
          .savedTuitions()
          .countDocuments({ student: studentId });
        if (savedCount >= FREE_SAVED_TUITION_LIMIT) {
          return fail(
            res,
            403,
            `Free students can save up to ${FREE_SAVED_TUITION_LIMIT} tuitions. Upgrade to Pro for unlimited bookmarks.`,
          );
        }
      }

      const now = new Date();
      try {
        const result = await collections.savedTuitions().insertOne({
          student: studentId,
          tuition: tuitionId,
          createdAt: now,
          updatedAt: now,
        });
        return res
          .status(201)
          .json({ saved: true, _id: String(result.insertedId) });
      } catch (error) {
        // Duplicate key = concurrent save; already bookmarked.
        if (error?.code === 11000) return res.json({ saved: true });
        throw error;
      }
    } catch (error) {
      next(error);
    }
  },
);

/* Profile — /api/profile (any authenticated role, no role gate) */

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

// PATCH /api/profile: DB identity + whitelisted fields only; role/plan cannot be escalated.
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

    // Changed email must not clash with another account (case-insensitive).
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

/* Admin — /api/admin */

const ROLES = ["student", "tutor", "admin"];
const APPROVALS = ["approved", "rejected"];

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

/* Payments / Stripe */

app.post("/payments/checkout-verify", async (req, res, next) => {
  try {
    const sessionId = String(req.body?.sessionId ?? "").trim();

    if (!sessionId) return fail(res, 400, "sessionId is required.");

    let session;
    try {
      session = await getStripe().checkout.sessions.retrieve(sessionId);
    } catch (error) {
      if (error?.code === "resource_missing") {
        return fail(res, 404, "Checkout session not found.");
      }
      throw error;
    }

    if (session.status !== "complete" || session.payment_status !== "paid") {
      return fail(res, 400, "Checkout is not complete or has not been paid.");
    }

    const result = await syncProPlan(session);
    if (!result.ok) return fail(res, result.status, result.message);

    res.json({
      success: true,
      duplicate: result.duplicate,
      plan: "pro",
      role: result.role,
      message: result.duplicate
        ? "Payment already verified — your Pro plan is active."
        : "Payment verified — your Pro plan is now active.",
    });
  } catch (error) {
    next(error);
  }
});

/* 404 + error fallbacks (registered after every route) */

app.use((_req, res) => {
  res.status(404).json({ message: "Route not found." });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(err.status || 500).json({
    message: err.message || "Something went wrong on the server.",
  });
});

/* Bootstrap */

const port = process.env.PORT || 5000;

await connectToMongoDB();
await ensurePaymentIndexes();
await ensureSavedTuitionIndexes();

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});

export default app;
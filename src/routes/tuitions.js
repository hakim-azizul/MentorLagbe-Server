import { Router } from "express";
import { collections, ObjectId } from "../db.js";
import { requireRole, requireSelfOrAdmin } from "../middleware/auth.js";
import { fail, getObjectId, missingFields } from "../utils.js";

const router = Router();

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
router.post("/", requireRole("tutor", "admin"), async (req, res, next) => {
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

/** GET /api/tuitions/tutor?email= — every tuition created by this tutor. */
router.get(
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

/** PATCH /api/tuitions/:id — update details and/or toggle isActive. */
router.patch("/:id", requireRole("tutor", "admin"), async (req, res, next) => {
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
router.delete("/:id", requireRole("tutor", "admin"), async (req, res, next) => {
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

export default router;

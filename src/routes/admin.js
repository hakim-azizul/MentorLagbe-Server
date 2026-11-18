import { Router } from "express";
import { collections } from "../db.js";
import { requireRole } from "../middleware/auth.js";
import { fail, getObjectId } from "../utils.js";

const router = Router();

const ROLES = ["student", "tutor", "admin"];
const APPROVALS = ["approved", "rejected"];

/** GET /api/admin/users — everyone registered on the platform. */
router.get("/users", requireRole("admin"), async (_req, res, next) => {
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
router.patch("/users/:id/role", requireRole("admin"), async (req, res, next) => {
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
router.get("/tuitions", requireRole("admin"), async (_req, res, next) => {
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
router.patch(
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
router.get("/transactions", requireRole("admin"), async (_req, res, next) => {
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

export default router;

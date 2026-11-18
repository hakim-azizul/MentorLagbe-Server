import { Router } from "express";
import { collections } from "../db.js";
import { requireRole, requireSelfOrAdmin } from "../middleware/auth.js";
import { fail, tuitionIdIn } from "../utils.js";

const router = Router();

/** GET /api/dashboard/student/stats?email= */
router.get(
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
router.get(
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
router.get("/admin/stats", requireRole("admin"), async (_req, res, next) => {
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

export default router;

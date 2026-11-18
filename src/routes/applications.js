import { Router } from "express";
import { collections } from "../db.js";
import { requireRole, requireSelfOrAdmin } from "../middleware/auth.js";
import { fail, getObjectId, tuitionIdIn } from "../utils.js";

const router = Router();

const STATUSES = ["pending", "accepted", "rejected"];

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

/** GET /api/applications/student?email= — my applications (with tuition info). */
router.get(
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
router.patch(
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
router.delete(
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

export default router;

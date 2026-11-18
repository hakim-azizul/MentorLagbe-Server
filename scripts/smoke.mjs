import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";

const API = "http://localhost:5000";
const STUDENT_EMAIL = "goza@indo.com";
const ADMIN_EMAIL = "smoke-admin@local.test";
const TUTOR_EMAIL = "smoke-tutor@local.test";
const TUTOR2_EMAIL = "smoke-tutor2@local.test";
const TARGET_EMAIL = "smoke-target@local.test";
const TEST_PREFIX = "[SMOKE]";

const ADMIN_TOKEN = "smoketestadmintoken0123456789ab";
const TUTOR_TOKEN = "smoketesttutortoken0123456789abc";
const TUTOR2_TOKEN = "smoketesttutor2token0123456789abc";
const STUDENT_TOKEN = "smoketeststudenttoken0123456789";

let failures = 0;
const client = new MongoClient(process.env.DB_URI);

function check(name, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${name}`);
  } else {
    failures += 1;
    console.log(`  FAIL  ${name} ${detail}`);
  }
}

async function call(path, { method = "GET", token, body } = {}) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Cookie: `better-auth.session_token=${token}` } : {}),
      Origin: "http://localhost:3000",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let payload = null;
  try {
    payload = await res.json();
  } catch {
    payload = null;
  }
  return { status: res.status, body: payload };
}

async function main() {
  await client.connect();
  const db = client.db("MentorLagbeDb");
  const users = db.collection("user");
  const sessions = db.collection("session");
  const tuitions = db.collection("tuitions");
  const applications = db.collection("applications");

  // ---- fixtures: a pro admin, a free tutor, a role-change target ---------
  const makeUser = (email, name, role, plan) => {
    const _id = new ObjectId();
    return {
      _id,
      doc: {
        _id,
        name,
        email,
        emailVerified: true,
        image: "",
        role,
        phone: "",
        bio: "",
        plan,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    };
  };

  const admin = makeUser(ADMIN_EMAIL, "Smoke Admin", "admin", "pro");
  const tutor = makeUser(TUTOR_EMAIL, "Smoke Tutor", "tutor", "free");
  const tutor2 = makeUser(TUTOR2_EMAIL, "Smoke Tutor Two", "tutor", "free");
  const target = makeUser(TARGET_EMAIL, "Smoke Target", "student", "free");
  await users.insertMany([admin.doc, tutor.doc, tutor2.doc, target.doc]);

  const studentDoc = await users.findOne({ email: STUDENT_EMAIL });
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
  await sessions.insertMany([
    { token: ADMIN_TOKEN, userId: admin._id, createdAt: new Date(), expiresAt },
    { token: TUTOR_TOKEN, userId: tutor._id, createdAt: new Date(), expiresAt },
    { token: TUTOR2_TOKEN, userId: tutor2._id, createdAt: new Date(), expiresAt },
    { token: STUDENT_TOKEN, userId: studentDoc._id, createdAt: new Date(), expiresAt },
  ]);

  const post = (n) =>
    call("/api/tuitions", {
      method: "POST",
      token: TUTOR_TOKEN,
      body: {
        title: `${TEST_PREFIX} Tuition ${n}`,
        subject: "Physics",
        classLevel: "Class 9",
        mode: "Online",
        monthlyFee: 2500,
        daysPerWeek: 3,
        description: "Automated smoke test post.",
        bannerImage: "https://i.ibb.co/demo.png",
      },
    });

  try {
    // ---- auth ------------------------------------------------------------
    console.log("\nAUTH");
    const noAuth = await call(`/api/dashboard/tutor/stats?email=${TUTOR_EMAIL}`);
    check("401 without session cookie", noAuth.status === 401);

    // ---- tutor: tuition CRUD + free plan limit ---------------------------
    console.log("\nTUTOR TUITIONS");
    const t1 = await post(1);
    check("POST /api/tuitions -> 201", t1.status === 201, JSON.stringify(t1.body));
    check(
      "new tuition is pending + active",
      t1.body?.approvalStatus === "pending" && t1.body?.isActive === true
    );
    const t2 = await post(2);
    check("second free post -> 201", t2.status === 201);

    const limited = await post(3);
    check("third free post -> 403", limited.status === 403, JSON.stringify(limited.body));
    check(
      "free plan limit message",
      limited.body?.message ===
        "Free plan tutors can only post up to 2 tuitions. Upgrade to Pro for unlimited posts."
    );

    const invalidBody = await call("/api/tuitions", {
      method: "POST",
      token: TUTOR_TOKEN,
      body: { title: "x" },
    });
    check("POST with missing fields -> 400", invalidBody.status === 400);

    const badMode = await call("/api/tuitions", {
      method: "POST",
      token: TUTOR_TOKEN,
      body: {
        title: "x", subject: "y", classLevel: "z", mode: "Hybridish",
        monthlyFee: 1, daysPerWeek: 1, description: "d",
      },
    });
    check("POST invalid mode -> 400", badMode.status === 400);

    const list = await call(`/api/tuitions/tutor?email=${TUTOR_EMAIL}`, {
      token: TUTOR_TOKEN,
    });
    check(
      "GET /api/tuitions/tutor returns my posts",
      list.status === 200 && Array.isArray(list.body) && list.body.length === 2,
      JSON.stringify(list.body?.length)
    );

    const wrongEmail = await call(`/api/tuitions/tutor?email=${STUDENT_EMAIL}`, {
      token: TUTOR_TOKEN,
    });
    check("cross-account email -> 403", wrongEmail.status === 403);

    const patched = await call(`/api/tuitions/${t1.body._id}`, {
      method: "PATCH",
      token: TUTOR_TOKEN,
      body: { isActive: false, monthlyFee: 3000 },
    });
    check(
      "PATCH toggles isActive + fee",
      patched.status === 200 &&
        patched.body?.isActive === false &&
        patched.body?.monthlyFee === 3000,
      JSON.stringify(patched.body)
    );

    const badPatch = await call(`/api/tuitions/${t1.body._id}`, {
      method: "PATCH",
      token: TUTOR_TOKEN,
      body: { isActive: "nope" },
    });
    check("PATCH non-boolean isActive -> 400", badPatch.status === 400);

    const foreignPatch = await call(`/api/tuitions/${t1.body._id}`, {
      method: "PATCH",
      token: TUTOR2_TOKEN,
      body: { title: "hijacked" },
    });
    check("another tutor cannot edit my tuition -> 403", foreignPatch.status === 403);

    const stats = await call(`/api/dashboard/tutor/stats?email=${TUTOR_EMAIL}`, {
      token: TUTOR_TOKEN,
    });
    check(
      "GET /api/dashboard/tutor/stats",
      stats.status === 200 &&
        stats.body?.totalPosted === 2 &&
        stats.body?.approvedCount === 0 &&
        stats.body?.totalApplicants === 0 &&
        stats.body?.plan === "free",
      JSON.stringify(stats.body)
    );

    // ---- applications ----------------------------------------------------
    console.log("\nAPPLICATIONS");
    const pendingId = new ObjectId();
    const otherId = new ObjectId();
    const makeApplication = (_id, schedule, status) => ({
      _id,
      tuitionId: String(t1.body._id),
      tuitionTitle: "stale title",
      subject: "stale subject",
      monthlyFee: 1,
      tutorEmail: TUTOR_EMAIL,
      tutorName: "stale tutor",
      studentName: "Smoke Student",
      studentEmail: STUDENT_EMAIL,
      studentPhone: "01700000000",
      preferredSchedule: schedule,
      studentNote: "hello",
      status,
      appliedAt: new Date(),
    });
    await applications.insertMany([
      makeApplication(pendingId, "Fri 5pm", "pending"),
      makeApplication(otherId, "Sat 10am", "pending"),
    ]);

    const studentList = await call(
      `/api/applications/student?email=${STUDENT_EMAIL}`,
      { token: STUDENT_TOKEN }
    );
    const joined = studentList.body?.find((a) => a._id === String(pendingId));
    check(
      "GET /api/applications/student -> 200 array",
      studentList.status === 200 && studentList.body?.length === 2,
      JSON.stringify(studentList.body?.length)
    );
    check(
      "application populated with tuition details",
      joined?.tuitionTitle === `${TEST_PREFIX} Tuition 1` &&
        joined?.tutorName === "Smoke Tutor" &&
        joined?.tutorEmail === TUTOR_EMAIL &&
        joined?.monthlyFee === 3000,
      JSON.stringify(joined)
    );

    const tutorList = await call(`/api/applications/tutor?email=${TUTOR_EMAIL}`, {
      token: TUTOR_TOKEN,
    });
    check(
      "GET /api/applications/tutor returns applicants",
      tutorList.status === 200 && tutorList.body?.length === 2,
      JSON.stringify(tutorList.body?.length)
    );

    const cancelPending = await call(`/api/applications/${pendingId}`, {
      method: "DELETE",
      token: STUDENT_TOKEN,
    });
    check("DELETE pending application -> 200", cancelPending.status === 200);

    const studentStats = await call(
      `/api/dashboard/student/stats?email=${STUDENT_EMAIL}`,
      { token: STUDENT_TOKEN }
    );
    check(
      "GET /api/dashboard/student/stats",
      studentStats.status === 200 &&
        studentStats.body?.totalApplied === 1 &&
        studentStats.body?.acceptedCount === 0 &&
        studentStats.body?.pendingCount === 1 &&
        studentStats.body?.plan === "free",
      JSON.stringify(studentStats.body)
    );

    const statusOk = await call(`/api/applications/${otherId}/status`, {
      method: "PATCH",
      token: TUTOR_TOKEN,
      body: { status: "accepted" },
    });
    check(
      "PATCH status -> accepted",
      statusOk.status === 200 && statusOk.body?.status === "accepted",
      JSON.stringify(statusOk.body)
    );

    const badStatus = await call(`/api/applications/${otherId}/status`, {
      method: "PATCH",
      token: TUTOR_TOKEN,
      body: { status: "maybe" },
    });
    check("PATCH invalid status -> 400", badStatus.status === 400);

    const cancelAccepted = await call(`/api/applications/${otherId}`, {
      method: "DELETE",
      token: STUDENT_TOKEN,
    });
    check(
      "DELETE accepted application -> 400",
      cancelAccepted.status === 400 && /pending/i.test(cancelAccepted.body?.message || ""),
      JSON.stringify(cancelAccepted.body)
    );

    const crossCancel = await call(`/api/applications/${otherId}`, {
      method: "DELETE",
      token: STUDENT_TOKEN,
    });
    check("student cancel of own app is status-guarded", crossCancel.status === 400);

    const tutorCantCancel = await call(`/api/applications/${otherId}`, {
      method: "DELETE",
      token: TUTOR_TOKEN,
    });
    check("tutor cannot cancel applications -> 403", tutorCantCancel.status === 403);

    const badId = await call("/api/applications/not-an-id", {
      method: "DELETE",
      token: STUDENT_TOKEN,
    });
    check("DELETE invalid id -> 400", badId.status === 400);

    const wrongTutorStatus = await call(`/api/applications/${otherId}/status`, {
      method: "PATCH",
      token: TUTOR2_TOKEN,
      body: { status: "rejected" },
    });
    check(
      "another tutor cannot change status -> 403",
      wrongTutorStatus.status === 403,
      JSON.stringify(wrongTutorStatus.body)
    );

    // ---- role guards -----------------------------------------------------
    console.log("\nROLE GUARDS");
    const asStudentAdmin = await call("/api/dashboard/admin/stats", {
      token: STUDENT_TOKEN,
    });
    check("student cannot read admin stats", asStudentAdmin.status === 403);
    const studentPosting = await call("/api/tuitions", {
      method: "POST",
      token: STUDENT_TOKEN,
      body: {
        title: "x", subject: "y", classLevel: "z", mode: "Online",
        monthlyFee: 1, daysPerWeek: 1, description: "d",
      },
    });
    check("student cannot post tuition", studentPosting.status === 403);
    const tutorOnAdmin = await call("/api/admin/users", { token: TUTOR_TOKEN });
    check("tutor cannot read admin users", tutorOnAdmin.status === 403);
    const tutorOnAdminList = await call("/api/admin/tuitions", { token: TUTOR_TOKEN });
    check("tutor cannot read admin tuitions", tutorOnAdminList.status === 403);

    // ---- admin -----------------------------------------------------------
    console.log("\nADMIN");
    const adminStats = await call("/api/dashboard/admin/stats", { token: ADMIN_TOKEN });
    check(
      "GET /api/dashboard/admin/stats",
      adminStats.status === 200 &&
        typeof adminStats.body?.totalUsers === "number" &&
        typeof adminStats.body?.totalTutors === "number" &&
        typeof adminStats.body?.pendingTuitions === "number" &&
        typeof adminStats.body?.approvedTuitions === "number" &&
        typeof adminStats.body?.totalRevenue === "number",
      JSON.stringify(adminStats.body)
    );

    const allUsers = await call("/api/admin/users", { token: ADMIN_TOKEN });
    check(
      "GET /api/admin/users",
      allUsers.status === 200 && allUsers.body?.length >= 4,
      JSON.stringify(allUsers.body?.length)
    );

    const roleChange = await call(`/api/admin/users/${target._id}/role`, {
      method: "PATCH",
      token: ADMIN_TOKEN,
      body: { role: "tutor" },
    });
    check(
      "PATCH /api/admin/users/:id/role",
      roleChange.status === 200 && roleChange.body?.role === "tutor",
      JSON.stringify(roleChange.body)
    );

    const selfRole = await call(`/api/admin/users/${admin._id}/role`, {
      method: "PATCH",
      token: ADMIN_TOKEN,
      body: { role: "student" },
    });
    check("cannot change own role -> 400", selfRole.status === 400);

    const badRole = await call(`/api/admin/users/${target._id}/role`, {
      method: "PATCH",
      token: ADMIN_TOKEN,
      body: { role: "superuser" },
    });
    check("invalid role -> 400", badRole.status === 400);

    const adminTuitions = await call("/api/admin/tuitions", { token: ADMIN_TOKEN });
    check(
      "GET /api/admin/tuitions",
      adminTuitions.status === 200 && adminTuitions.body?.length >= 2,
      JSON.stringify(adminTuitions.body?.length)
    );

    const approval = await call(`/api/admin/tuitions/${t2.body._id}/approval`, {
      method: "PATCH",
      token: ADMIN_TOKEN,
      body: { approvalStatus: "approved" },
    });
    check(
      "PATCH /api/admin/tuitions/:id/approval",
      approval.status === 200 && approval.body?.approvalStatus === "approved",
      JSON.stringify(approval.body)
    );

    const badApproval = await call(`/api/admin/tuitions/${t2.body._id}/approval`, {
      method: "PATCH",
      token: ADMIN_TOKEN,
      body: { approvalStatus: "maybe" },
    });
    check("invalid approvalStatus -> 400", badApproval.status === 400);

    const approvedStats = await call(`/api/dashboard/tutor/stats?email=${TUTOR_EMAIL}`, {
      token: TUTOR_TOKEN,
    });
    check(
      "approvedCount reflects approval",
      approvedStats.body?.approvedCount === 1,
      JSON.stringify(approvedStats.body)
    );

    const transactions = await call("/api/admin/transactions", { token: ADMIN_TOKEN });
    check(
      "GET /api/admin/transactions -> array",
      transactions.status === 200 && Array.isArray(transactions.body),
      JSON.stringify(transactions.body)
    );

    // ---- delete ----------------------------------------------------------
    console.log("\nDELETE");
    const crossDelete = await call(`/api/tuitions/${t2.body._id}`, {
      method: "DELETE",
      token: STUDENT_TOKEN,
    });
    check("student cannot delete tuition -> 403", crossDelete.status === 403);

    // t2 তে একটি আবেদন রেখে ডিলিট করলে সেটিও মুছে যাবে কিনা দেখা
    const onT2Id = new ObjectId();
    await applications.insertOne({
      ...makeApplication(onT2Id, "Sun 8am", "pending"),
      tuitionId: String(t2.body._id),
    });
    const orphanBefore = await applications.findOne({ _id: onT2Id });
    check("fixture application exists on t2", orphanBefore !== null);

    const tutor2Delete = await call(`/api/tuitions/${t1.body._id}`, {
      method: "DELETE",
      token: TUTOR2_TOKEN,
    });
    check("another tutor cannot delete my tuition -> 403", tutor2Delete.status === 403);

    const del = await call(`/api/tuitions/${t2.body._id}`, {
      method: "DELETE",
      token: TUTOR_TOKEN,
    });
    check("DELETE /api/tuitions/:id -> 200", del.status === 200, JSON.stringify(del.body));

    const orphan = await applications.findOne({ _id: onT2Id });
    check("deleting a tuition removes its applications", orphan === null);

    const keptOrphan = await applications.findOne({ _id: otherId });
    check("applications of other tuitions are untouched", keptOrphan !== null);

    const unknown = await call(`/api/tuitions/${t2.body._id}`, {
      method: "DELETE",
      token: TUTOR_TOKEN,
    });
    check("DELETE missing tuition -> 404", unknown.status === 404);
  } finally {
    // ---- cleanup ---------------------------------------------------------
    await tuitions.deleteMany({ title: { $regex: "^\\[SMOKE\\]" } });
    await applications.deleteMany({ studentName: "Smoke Student" });
    await users.deleteMany({
      email: { $in: [ADMIN_EMAIL, TUTOR_EMAIL, TUTOR2_EMAIL, TARGET_EMAIL] },
    });
    await sessions.deleteMany({ token: { $regex: "^smoketest" } });
    await client.close();
  }

  console.log(
    failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`
  );
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

import "dotenv/config";
import { createHmac } from "node:crypto";
import { MongoClient, ObjectId } from "mongodb";

const API = "http://localhost:5000";
// Better Auth (Next.js) issues the JWTs — same origin as JWT_ISSUER.
const AUTH = (process.env.JWT_ISSUER || "http://localhost:3000").replace(/\/+$/, "");
const STUDENT_EMAIL = "goza@indo.com";
const ADMIN_EMAIL = "smoke-admin@local.test";
const TUTOR_EMAIL = "smoke-tutor@local.test";
const TUTOR2_EMAIL = "smoke-tutor2@local.test";
const TARGET_EMAIL = "smoke-target@local.test";
const TEST_PREFIX = "[SMOKE]";

// Session fixtures inserted into the `session` collection; each one is traded
// for a real JWT via `GET :3000/api/auth/token` (see mintJwt).
const ADMIN_TOKEN = "smoketestadmintoken0123456789ab";
const TUTOR_TOKEN = "smoketesttutortoken0123456789abc";
const TUTOR2_TOKEN = "smoketesttutor2token0123456789abc";
const STUDENT_TOKEN = "smoketeststudenttoken0123456789";
const TARGET_TOKEN = "smoketesttargettoken0123456789abc";

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

/**
 * Signs a session token the way Better Auth signs its cookie
 * (`<token>.<base64 HMAC-SHA256(BETTER_AUTH_SECRET, token)>`), then trades
 * the cookie for the JWT that mentor-server expects as `Bearer <jwt>`.
 * Requires the Next.js dev server on :3000 — fails loudly when it is down.
 */
async function mintJwt(sessionToken) {
  const secret = process.env.BETTER_AUTH_SECRET;
  if (!secret) {
    throw new Error("BETTER_AUTH_SECRET missing — cannot sign the session cookie.");
  }
  const signature = createHmac("sha256", secret).update(sessionToken).digest("base64");
  const cookie = `better-auth.session_token=${sessionToken}.${signature}`;

  let res;
  try {
    res = await fetch(`${AUTH}/api/auth/token`, {
      headers: { Cookie: cookie },
    });
  } catch (error) {
    throw new Error(
      `Cannot reach ${AUTH}/api/auth/token — start the Next.js dev server ` +
        `(npm run dev in mentor-client, port 3000) before running the smoke suite. ` +
        `(${error.message})`
    );
  }
  const body = await res.json().catch(() => null);
  if (!res.ok || !body?.token) {
    throw new Error(
      `GET ${AUTH}/api/auth/token -> ${res.status} ${JSON.stringify(body)}. ` +
        `Check that the Next.js dev server runs on port 3000 and that ` +
        `BETTER_AUTH_SECRET matches between mentor-client/.env and mentor-server/.env.`
    );
  }
  return body.token;
}

/** Sends a request to mentor-server with an optional `Authorization: Bearer`. */
async function call(path, { method = "GET", jwt, body } = {}) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(jwt ? { Authorization: `Bearer ${jwt}` } : {}),
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
    { token: TARGET_TOKEN, userId: target._id, createdAt: new Date(), expiresAt },
  ]);

  // Trade each fixture session for a real Better Auth JWT (Bearer for API calls).
  const adminJwt = await mintJwt(ADMIN_TOKEN);
  const tutorJwt = await mintJwt(TUTOR_TOKEN);
  const tutor2Jwt = await mintJwt(TUTOR2_TOKEN);
  const studentJwt = await mintJwt(STUDENT_TOKEN);
  const targetJwt = await mintJwt(TARGET_TOKEN);

  const post = (n) =>
    call("/api/tuitions", {
      method: "POST",
      jwt: tutorJwt,
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
    const jwksRes = await fetch(`${AUTH}/api/auth/jwks`);
    const jwksBody = await jwksRes.json().catch(() => null);
    check(
      "GET :3000/api/auth/jwks exposes signing keys",
      jwksRes.status === 200 &&
        Array.isArray(jwksBody?.keys) &&
        jwksBody.keys.length > 0,
      `status ${jwksRes.status}`
    );

    const noAuth = await call(`/api/dashboard/tutor/stats?email=${TUTOR_EMAIL}`);
    check("401 without Authorization header", noAuth.status === 401);

    const garbage = await call(`/api/dashboard/tutor/stats?email=${TUTOR_EMAIL}`, {
      jwt: "not-a-jwt.at-all",
    });
    check("401 with malformed token", garbage.status === 401, JSON.stringify(garbage.body));

    const tamperedJwt = `${studentJwt.split(".").slice(0, 2).join(".")}.${"A".repeat(44)}`;
    const tampered = await call(`/api/dashboard/tutor/stats?email=${TUTOR_EMAIL}`, {
      jwt: tamperedJwt,
    });
    check("401 with tampered signature", tampered.status === 401, JSON.stringify(tampered.body));

    const wrongRole = await call(`/api/tuitions/tutor?email=${STUDENT_EMAIL}`, {
      jwt: studentJwt,
    });
    check("403 student token on tutor-only route", wrongRole.status === 403);

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
      jwt: tutorJwt,
      body: { title: "x" },
    });
    check("POST with missing fields -> 400", invalidBody.status === 400);

    const badMode = await call("/api/tuitions", {
      method: "POST",
      jwt: tutorJwt,
      body: {
        title: "x", subject: "y", classLevel: "z", mode: "Hybridish",
        monthlyFee: 1, daysPerWeek: 1, description: "d",
      },
    });
    check("POST invalid mode -> 400", badMode.status === 400);

    const list = await call(`/api/tuitions/tutor?email=${TUTOR_EMAIL}`, {
      jwt: tutorJwt,
    });
    check(
      "GET /api/tuitions/tutor returns my posts",
      list.status === 200 && Array.isArray(list.body) && list.body.length === 2,
      JSON.stringify(list.body?.length)
    );

    const wrongEmail = await call(`/api/tuitions/tutor?email=${STUDENT_EMAIL}`, {
      jwt: tutorJwt,
    });
    check("cross-account email -> 403", wrongEmail.status === 403);

    const patched = await call(`/api/tuitions/${t1.body._id}`, {
      method: "PATCH",
      jwt: tutorJwt,
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
      jwt: tutorJwt,
      body: { isActive: "nope" },
    });
    check("PATCH non-boolean isActive -> 400", badPatch.status === 400);

    const foreignPatch = await call(`/api/tuitions/${t1.body._id}`, {
      method: "PATCH",
      jwt: tutor2Jwt,
      body: { title: "hijacked" },
    });
    check("another tutor cannot edit my tuition -> 403", foreignPatch.status === 403);

    const stats = await call(`/api/dashboard/tutor/stats?email=${TUTOR_EMAIL}`, {
      jwt: tutorJwt,
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
      { jwt: studentJwt }
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
      jwt: tutorJwt,
    });
    check(
      "GET /api/applications/tutor returns applicants",
      tutorList.status === 200 && tutorList.body?.length === 2,
      JSON.stringify(tutorList.body?.length)
    );

    const cancelPending = await call(`/api/applications/${pendingId}`, {
      method: "DELETE",
      jwt: studentJwt,
    });
    check("DELETE pending application -> 200", cancelPending.status === 200);

    const studentStats = await call(
      `/api/dashboard/student/stats?email=${STUDENT_EMAIL}`,
      { jwt: studentJwt }
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
      jwt: tutorJwt,
      body: { status: "accepted" },
    });
    check(
      "PATCH status -> accepted",
      statusOk.status === 200 && statusOk.body?.status === "accepted",
      JSON.stringify(statusOk.body)
    );

    const badStatus = await call(`/api/applications/${otherId}/status`, {
      method: "PATCH",
      jwt: tutorJwt,
      body: { status: "maybe" },
    });
    check("PATCH invalid status -> 400", badStatus.status === 400);

    const cancelAccepted = await call(`/api/applications/${otherId}`, {
      method: "DELETE",
      jwt: studentJwt,
    });
    check(
      "DELETE accepted application -> 400",
      cancelAccepted.status === 400 && /pending/i.test(cancelAccepted.body?.message || ""),
      JSON.stringify(cancelAccepted.body)
    );

    const crossCancel = await call(`/api/applications/${otherId}`, {
      method: "DELETE",
      jwt: studentJwt,
    });
    check("student cancel of own app is status-guarded", crossCancel.status === 400);

    const tutorCantCancel = await call(`/api/applications/${otherId}`, {
      method: "DELETE",
      jwt: tutorJwt,
    });
    check("tutor cannot cancel applications -> 403", tutorCantCancel.status === 403);

    const badId = await call("/api/applications/not-an-id", {
      method: "DELETE",
      jwt: studentJwt,
    });
    check("DELETE invalid id -> 400", badId.status === 400);

    const wrongTutorStatus = await call(`/api/applications/${otherId}/status`, {
      method: "PATCH",
      jwt: tutor2Jwt,
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
      jwt: studentJwt,
    });
    check("student cannot read admin stats", asStudentAdmin.status === 403);
    const studentPosting = await call("/api/tuitions", {
      method: "POST",
      jwt: studentJwt,
      body: {
        title: "x", subject: "y", classLevel: "z", mode: "Online",
        monthlyFee: 1, daysPerWeek: 1, description: "d",
      },
    });
    check("student cannot post tuition", studentPosting.status === 403);
    const tutorOnAdmin = await call("/api/admin/users", { jwt: tutorJwt });
    check("tutor cannot read admin users", tutorOnAdmin.status === 403);
    const tutorOnAdminList = await call("/api/admin/tuitions", { jwt: tutorJwt });
    check("tutor cannot read admin tuitions", tutorOnAdminList.status === 403);

    // ---- profile ---------------------------------------------------------
    console.log("\nPROFILE");
    const noProfileAuth = await call("/api/profile");
    check("401 GET /api/profile without token", noProfileAuth.status === 401);

    const ownProfile = await call("/api/profile", { jwt: targetJwt });
    check(
      "GET /api/profile -> own document",
      ownProfile.status === 200 && ownProfile.body?.email === TARGET_EMAIL,
      JSON.stringify(ownProfile.body)
    );

    const saveProfile = await call("/api/profile", {
      method: "PATCH",
      jwt: targetJwt,
      body: {
        name: "Smoke Target Renamed",
        email: TARGET_EMAIL,
        image: "https://i.ibb.co/smoke-avatar.png",
        phone: "01711111111",
        bio: "Updated by the smoke suite.",
      },
    });
    check(
      "PATCH /api/profile -> 200 with updated fields",
      saveProfile.status === 200 &&
        saveProfile.body?.name === "Smoke Target Renamed" &&
        saveProfile.body?.phone === "01711111111" &&
        saveProfile.body?.bio === "Updated by the smoke suite." &&
        saveProfile.body?.image === "https://i.ibb.co/smoke-avatar.png",
      JSON.stringify(saveProfile.body)
    );

    const rereadProfile = await call("/api/profile", { jwt: targetJwt });
    check(
      "PATCH persists (GET reflects changes)",
      rereadProfile.status === 200 &&
        rereadProfile.body?.name === "Smoke Target Renamed",
      JSON.stringify(rereadProfile.body)
    );

    const emailClash = await call("/api/profile", {
      method: "PATCH",
      jwt: targetJwt,
      body: {
        name: "Smoke Target Renamed",
        email: TUTOR_EMAIL,
        image: "",
        phone: "",
        bio: "",
      },
    });
    check(
      "email used by another account -> 409",
      emailClash.status === 409,
      JSON.stringify(emailClash.body)
    );

    const badEmail = await call("/api/profile", {
      method: "PATCH",
      jwt: targetJwt,
      body: { name: "x", email: "not-an-email", image: "", phone: "", bio: "" },
    });
    check("invalid email -> 400", badEmail.status === 400, JSON.stringify(badEmail.body));

    const emptyName = await call("/api/profile", {
      method: "PATCH",
      jwt: targetJwt,
      body: { name: "   ", email: TARGET_EMAIL, image: "", phone: "", bio: "" },
    });
    check("empty name -> 400", emptyName.status === 400);

    const roleTamper = await call("/api/profile", {
      method: "PATCH",
      jwt: targetJwt,
      body: {
        name: "Smoke Target Renamed",
        email: TARGET_EMAIL,
        image: "",
        phone: "",
        bio: "",
        role: "admin",
        plan: "pro",
      },
    });
    check(
      "role/plan in body are ignored (whitelist)",
      roleTamper.status === 200 &&
        roleTamper.body?.role === "student" &&
        roleTamper.body?.plan === "free",
      JSON.stringify({ role: roleTamper.body?.role, plan: roleTamper.body?.plan })
    );

    // ---- admin -----------------------------------------------------------
    console.log("\nADMIN");
    const adminStats = await call("/api/dashboard/admin/stats", { jwt: adminJwt });
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

    const allUsers = await call("/api/admin/users", { jwt: adminJwt });
    check(
      "GET /api/admin/users",
      allUsers.status === 200 && allUsers.body?.length >= 4,
      JSON.stringify(allUsers.body?.length)
    );

    const roleChange = await call(`/api/admin/users/${target._id}/role`, {
      method: "PATCH",
      jwt: adminJwt,
      body: { role: "tutor" },
    });
    check(
      "PATCH /api/admin/users/:id/role",
      roleChange.status === 200 && roleChange.body?.role === "tutor",
      JSON.stringify(roleChange.body)
    );

    const selfRole = await call(`/api/admin/users/${admin._id}/role`, {
      method: "PATCH",
      jwt: adminJwt,
      body: { role: "student" },
    });
    check("cannot change own role -> 400", selfRole.status === 400);

    const badRole = await call(`/api/admin/users/${target._id}/role`, {
      method: "PATCH",
      jwt: adminJwt,
      body: { role: "superuser" },
    });
    check("invalid role -> 400", badRole.status === 400);

    const adminTuitions = await call("/api/admin/tuitions", { jwt: adminJwt });
    check(
      "GET /api/admin/tuitions",
      adminTuitions.status === 200 && adminTuitions.body?.length >= 2,
      JSON.stringify(adminTuitions.body?.length)
    );

    const approval = await call(`/api/admin/tuitions/${t2.body._id}/approval`, {
      method: "PATCH",
      jwt: adminJwt,
      body: { approvalStatus: "approved" },
    });
    check(
      "PATCH /api/admin/tuitions/:id/approval",
      approval.status === 200 && approval.body?.approvalStatus === "approved",
      JSON.stringify(approval.body)
    );

    const badApproval = await call(`/api/admin/tuitions/${t2.body._id}/approval`, {
      method: "PATCH",
      jwt: adminJwt,
      body: { approvalStatus: "maybe" },
    });
    check("invalid approvalStatus -> 400", badApproval.status === 400);

    const approvedStats = await call(`/api/dashboard/tutor/stats?email=${TUTOR_EMAIL}`, {
      jwt: tutorJwt,
    });
    check(
      "approvedCount reflects approval",
      approvedStats.body?.approvedCount === 1,
      JSON.stringify(approvedStats.body)
    );

    const transactions = await call("/api/admin/transactions", { jwt: adminJwt });
    check(
      "GET /api/admin/transactions -> array",
      transactions.status === 200 && Array.isArray(transactions.body),
      JSON.stringify(transactions.body)
    );

    // ---- public list: filter/sort/tutor summary -------------------------
    console.log("\nPUBLIC LIST");
    const publicList = await call("/api/tuitions");
    check(
      "GET /api/tuitions -> approved + active only",
      publicList.status === 200 &&
        Array.isArray(publicList.body) &&
        publicList.body.length >= 1 &&
        publicList.body.every(
          (tuition) =>
            tuition.approvalStatus === "approved" && tuition.isActive === true
        ),
      JSON.stringify(publicList.body?.length)
    );

    const listed = publicList.body?.find(
      (tuition) => tuition._id === String(t2.body._id)
    );
    check(
      "list item carries the tutor profile summary",
      typeof listed?.tutor?.name === "string" &&
        listed.tutor.name.length > 0 &&
        listed.tutor.email === TUTOR_EMAIL,
      JSON.stringify(listed?.tutor)
    );

    check(
      "list item tutor.image is a string",
      typeof listed?.tutor?.image === "string",
      JSON.stringify(listed?.tutor?.image)
    );

    const smokeSearch = await call("/api/tuitions?search=smoke");
    check(
      "search=smoke filters titles (case-insensitive)",
      smokeSearch.status === 200 &&
        smokeSearch.body?.length >= 1 &&
        smokeSearch.body.every((tuition) => /smoke/i.test(tuition.title)),
      JSON.stringify(smokeSearch.body?.map((tuition) => tuition.title))
    );

    const feeAsc = await call("/api/tuitions?sort=fee_asc");
    check(
      "sort=fee_asc -> monthlyFee ascending",
      feeAsc.status === 200 &&
        feeAsc.body?.length >= 1 &&
        feeAsc.body.every(
          (tuition, index) =>
            index === 0 ||
            feeAsc.body[index - 1].monthlyFee <= tuition.monthlyFee
        ),
      JSON.stringify(
        feeAsc.body?.slice(0, 3).map((tuition) => tuition.monthlyFee)
      )
    );

    const feeDesc = await call("/api/tuitions?sort=fee_desc");
    check(
      "sort=fee_desc -> monthlyFee descending",
      feeDesc.status === 200 &&
        feeDesc.body?.length >= 1 &&
        feeDesc.body.every(
          (tuition, index) =>
            index === 0 ||
            feeDesc.body[index - 1].monthlyFee >= tuition.monthlyFee
        ),
      JSON.stringify(
        feeDesc.body?.slice(0, 3).map((tuition) => tuition.monthlyFee)
      )
    );

    const bogusSort = await call("/api/tuitions?sort=bogus");
    check(
      "unknown sort falls back to newest",
      bogusSort.status === 200 &&
        bogusSort.body?.length === publicList.body?.length &&
        bogusSort.body?.[0]?._id === publicList.body?.[0]?._id,
      JSON.stringify(bogusSort.body?.[0]?._id)
    );

    // ---- delete ----------------------------------------------------------
    console.log("\nDELETE");
    const crossDelete = await call(`/api/tuitions/${t2.body._id}`, {
      method: "DELETE",
      jwt: studentJwt,
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
      jwt: tutor2Jwt,
    });
    check("another tutor cannot delete my tuition -> 403", tutor2Delete.status === 403);

    const del = await call(`/api/tuitions/${t2.body._id}`, {
      method: "DELETE",
      jwt: tutorJwt,
    });
    check("DELETE /api/tuitions/:id -> 200", del.status === 200, JSON.stringify(del.body));

    const orphan = await applications.findOne({ _id: onT2Id });
    check("deleting a tuition removes its applications", orphan === null);

    const keptOrphan = await applications.findOne({ _id: otherId });
    check("applications of other tuitions are untouched", keptOrphan !== null);

    const unknown = await call(`/api/tuitions/${t2.body._id}`, {
      method: "DELETE",
      jwt: tutorJwt,
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

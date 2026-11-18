import "dotenv/config";
import { MongoClient } from "mongodb";

const AUTH = "http://localhost:3000";
const API = "http://localhost:5000";
const EMAIL = "e2e-bearer@local.test";
const PASSWORD = "e2e-password-123456";

let failures = 0;
function check(name, condition, detail = "") {
  console.log(`  ${condition ? "PASS" : "FAIL"}  ${name}${condition ? "" : " " + detail}`);
  if (!condition) failures += 1;
}

async function call(path, { method = "GET", jwt, body } = {}) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(jwt ? { Authorization: `Bearer ${jwt}` } : {}),
      Origin: AUTH,
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
  const client = new MongoClient(process.env.DB_URI);
  await client.connect();
  const db = client.db("MentorLagbeDb");
  const users = db.collection("user");
  const sessions = db.collection("session");
  const accounts = db.collection("account");

  // clean slate from any previous run
  const stale = await users.find({ email: EMAIL }).toArray();
  const staleIds = stale.map((u) => u._id);
  if (staleIds.length) {
    await sessions.deleteMany({ userId: { $in: staleIds.map(String) } });
    await accounts.deleteMany({ userId: { $in: staleIds.map(String) } });
    await users.deleteMany({ email: EMAIL });
  }

  try {
    console.log("\nE2E BEARER MATRIX (real better-auth sign-up)");
    const signup = await fetch(`${AUTH}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: AUTH },
      body: JSON.stringify({
        email: EMAIL,
        password: PASSWORD,
        name: "E2E Bearer",
        role: "student",
        plan: "free",
      }),
    });
    const signupBody = await signup.json().catch(() => null);
    check("POST /api/auth/sign-up/email -> 200", signup.status === 200, JSON.stringify(signupBody));

    const setCookie = signup.headers.getSetCookie().find((c) =>
      c.startsWith("better-auth.session_token=")
    );
    const rawCookie = setCookie ? setCookie.split(";")[0] : null;
    check("sign-up set a session cookie", Boolean(rawCookie));

    const tokenRes = await fetch(`${AUTH}/api/auth/token`, {
      headers: { Cookie: rawCookie || "" },
    });
    const tokenBody = await tokenRes.json().catch(() => null);
    const jwt = tokenBody?.token;
    check("GET /api/auth/token -> JWT", tokenRes.status === 200 && Boolean(jwt), JSON.stringify(tokenBody));

    const claims = jwt
      ? JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString())
      : {};
    check(
      "claims carry iss/aud/sub/email",
      claims.iss === "http://localhost:3000" &&
        claims.aud === "http://localhost:5000" &&
        claims.sub &&
        claims.email === EMAIL,
      JSON.stringify({ iss: claims.iss, aud: claims.aud, sub: claims.sub })
    );

    const none = await call(`/api/dashboard/student/stats?email=${EMAIL}`);
    check("no Authorization -> 401", none.status === 401, JSON.stringify(none.body));

    const garbage = await call(`/api/dashboard/student/stats?email=${EMAIL}`, {
      jwt: "garbage.token.value",
    });
    check("garbage token -> 401", garbage.status === 401, JSON.stringify(garbage.body));

    const own = await call(`/api/dashboard/student/stats?email=${EMAIL}`, { jwt });
    check("student route 200 with own student token", own.status === 200, JSON.stringify(own.body));

    // user sync: delete the doc — verifyToken must recreate it from claims
    await users.deleteMany({ email: EMAIL });
    const resync = await call(`/api/dashboard/student/stats?email=${EMAIL}`, { jwt });
    const recreated = await users.findOne({ email: EMAIL });
    check("user recreated from JWT claims -> 200", resync.status === 200, JSON.stringify(resync.body));
    check("recreated doc matches sub _id", recreated?._id?.toString() === claims.sub);

    // DB-authoritative role: token says "student", DB says otherwise
    await users.updateOne({ email: EMAIL }, { $set: { role: "tutor" } });
    const asTutor = await call(`/api/tuitions/tutor?email=${EMAIL}`, { jwt });
    check("DB role=tutor opens tutor route (token still student)", asTutor.status === 200, JSON.stringify(asTutor.body));
    const tutorBlockedFromAdmin = await call("/api/dashboard/admin/stats", { jwt });
    check("DB role=tutor still blocked from admin -> 403", tutorBlockedFromAdmin.status === 403);

    await users.updateOne({ email: EMAIL }, { $set: { role: "admin" } });
    const asAdmin = await call("/api/dashboard/admin/stats", { jwt });
    check("DB role=admin opens admin route -> 200", asAdmin.status === 200, JSON.stringify(asAdmin.body));
    const adminOnStudent = await call(`/api/dashboard/student/stats?email=${EMAIL}`, { jwt });
    check("DB role=admin passes student gate -> 200", adminOnStudent.status === 200, JSON.stringify(adminOnStudent.body));

    // cross-account guard still applies for admins? (admins bypass self-or-admin)
    const selfGate = await call(`/api/tuitions/tutor?email=goza@indo.com`, { jwt });
    check("admin reading another account -> 200 (admin bypass)", selfGate.status === 200, JSON.stringify(selfGate.body));
  } finally {
    const leftover = await users.find({ email: EMAIL }).toArray();
    const ids = leftover.map((u) => u._id);
    await sessions.deleteMany({ userId: { $in: ids.map(String) } });
    await accounts.deleteMany({ userId: { $in: ids.map(String) } });
    await users.deleteMany({ email: EMAIL });
    await client.close();
  }

  console.log(failures === 0 ? "\nE2E PASSED" : `\n${failures} E2E CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

import "dotenv/config";
import { MongoClient } from "mongodb";

const client = new MongoClient(process.env.DB_URI);
await client.connect();
const db = client.db("MentorLagbeDb");
const tuitions = await db.collection("tuitions").deleteMany({ title: /^\[SMOKE\]/ });
const applications = await db.collection("applications").deleteMany({ studentName: "Smoke Student" });
const users = await db.collection("user").deleteMany({ email: /^smoke-/ });
const sessions = await db.collection("session").deleteMany({ token: /^smoketest/ });
console.log("tuitions:", tuitions.deletedCount);
console.log("applications:", applications.deletedCount);
console.log("users:", users.deletedCount);
console.log("sessions:", sessions.deletedCount);
console.log("remaining tuitions:", await db.collection("tuitions").countDocuments());
console.log("remaining users:", await db.collection("user").countDocuments({}));
await client.close();

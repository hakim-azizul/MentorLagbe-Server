import { MongoClient } from "mongodb";

const DB_NAME = "MentorLagbeDb";

const client = new MongoClient(process.env.DB_URI);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
    throw err;
  }
}

export function getDb() {
  return client.db(DB_NAME);
}

/**
 * Better Auth (mongo adapter) stores auth data in singular collections:
 * `user`, `session`, `account`, `verification`.
 * Business data uses plural collections.
 */
export const collections = {
  users: () => getDb().collection("user"),
  sessions: () => getDb().collection("session"),
  tuitions: () => getDb().collection("tuitions"),
  applications: () => getDb().collection("applications"),
  payments: () => getDb().collection("payments"),
};

export { ObjectId } from "mongodb";

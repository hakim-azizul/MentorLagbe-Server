import express from "express";
import cors from "cors";
import 'dotenv/config';

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.DB_URI);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}

const connectedClient = await connectToMongoDB();
const database = connectedClient.db("MentorLagbeDb");


app.get("/", (req, res) => {
  res.send("Welcome to MentorLagbe server");
});

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
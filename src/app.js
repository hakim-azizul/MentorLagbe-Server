import express from "express";
import cors from "cors";
import dashboardRouter from "./routes/dashboard.js";
import tuitionsRouter from "./routes/tuitions.js";
import applicationsRouter from "./routes/applications.js";
import adminRouter from "./routes/admin.js";

/** Comma separated list of allowed browser origins (credentials enabled). */
const DEFAULT_ORIGINS = ["http://localhost:3000", "http://localhost:5173"];
const allowedOrigins = (process.env.CLIENT_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const originAllowList = allowedOrigins.length ? allowedOrigins : DEFAULT_ORIGINS;

export function createApp() {
  const app = express();

  app.use(
    cors({
      origin(origin, callback) {
        // নন-ব্রাউজার রিকোয়েস্ট (Postman/curl) বা অনুমোদিত অরিজিন
        if (!origin || originAllowList.includes(origin)) {
          return callback(null, origin || false);
        }
        callback(new Error(`Origin ${origin} is not allowed by CORS.`));
      },
      credentials: true,
      methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    })
  );

  app.use(express.json({ limit: "1mb" }));

  app.get("/", (_req, res) => {
    res.send("Welcome to MentorLagbe server");
  });

  app.use("/api/dashboard", dashboardRouter);
  app.use("/api/tuitions", tuitionsRouter);
  app.use("/api/applications", applicationsRouter);
  app.use("/api/admin", adminRouter);

  // রাউট না পেলে
  app.use((_req, res) => {
    res.status(404).json({ message: "Route not found." });
  });

  // গ্লোবাল এরর হ্যান্ডলার
  app.use((err, _req, res, _next) => {
    console.error(err);
    res.status(err.status || 500).json({
      message: err.message || "Something went wrong on the server.",
    });
  });

  return app;
}

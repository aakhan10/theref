import "dotenv/config"; // ESM-safe env preload

import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import { pool } from "./db.js";
import authRoutes from "./routes_auth.js"; 

const app = express();

app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// CORS so React app can call API
app.use(
  cors({
    origin: process.env.CLIENT_ORIGIN,
    credentials: true,
  })
);

// rate limit auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
});

// apply limiter to /auth only
app.use("/auth", authLimiter);

// routes
app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/db-test", async (req, res) => {
  try {
    const result = await pool.query("select now()");
    res.json({ now: result.rows[0].now });
  } catch (e) {
    console.error("DB ERROR:", e);
    res.status(500).json({
      error: e?.message || e?.toString() || "unknown db error",
      code: e?.code || null,
    });
  }
});

// mount auth routes
app.use("/auth", authRoutes);

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`API running on http://localhost:${port}`);
});
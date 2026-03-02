import { Router } from "express";
import { z } from "zod";
import argon2 from "argon2";
import crypto from "crypto";
import { pool } from "./db.js";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "./auth.js";

const router = Router();

const registerSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(8).max(128),
});

const loginSchema = registerSchema;

function setRefreshCookie(res, token) {
  const isProd = process.env.NODE_ENV === "production";

  res.cookie("refresh_token", token, {
    httpOnly: true,
    secure: isProd,          // in dev on localhost, this must be false
    sameSite: "lax",
    path: "/auth",           // cookie only sent to /auth endpoints
    maxAge: Number(process.env.REFRESH_TOKEN_TTL_DAYS || 7) * 24 * 60 * 60 * 1000,
  });
}

function clearRefreshCookie(res) {
  res.clearCookie("refresh_token", { path: "/auth" });
}

function sha256(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

router.post("/register", async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input", details: parsed.error.issues });

  const { email, password } = parsed.data;

  const password_hash = await argon2.hash(password, { type: argon2.argon2id });

  try {
    const result = await pool.query(
      `insert into public.users (email, password_hash)
       values ($1, $2)
       returning id, email, role`,
      [email.toLowerCase(), password_hash]
    );

    return res.status(201).json({ user: result.rows[0] });
  } catch (e) {
    // unique violation
    if (e?.code === "23505") return res.status(409).json({ error: "Email already registered" });
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

router.post("/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input", details: parsed.error.issues });

  const { email, password } = parsed.data;

  const userRes = await pool.query(
    `select id, email, role, password_hash from public.users where email = $1`,
    [email.toLowerCase()]
  );

  const user = userRes.rows[0];
  // generic message to avoid leaking which part failed
  if (!user) return res.status(401).json({ error: "Invalid email or password" });

  const ok = await argon2.verify(user.password_hash, password);
  if (!ok) return res.status(401).json({ error: "Invalid email or password" });

  const accessToken = signAccessToken({ sub: user.id, email: user.email, role: user.role });
  const refreshToken = signRefreshToken({ sub: user.id });

  // store hashed refresh token in DB
  const tokenHash = sha256(refreshToken);
  const days = Number(process.env.REFRESH_TOKEN_TTL_DAYS || 7);
  const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

  await pool.query(
    `insert into public.refresh_tokens (user_id, token_hash, expires_at)
     values ($1, $2, $3)`,
    [user.id, tokenHash, expiresAt.toISOString()]
  );

  setRefreshCookie(res, refreshToken);
  return res.json({ accessToken, user: { id: user.id, email: user.email, role: user.role } });
});

router.post("/refresh", async (req, res) => {
  const token = req.cookies?.refresh_token;
  if (!token) return res.status(401).json({ error: "Missing refresh token" });

  let decoded;
  try {
    decoded = verifyRefreshToken(token);
  } catch {
    return res.status(401).json({ error: "Invalid refresh token" });
  }

  const tokenHash = sha256(token);

  // ensure token exists + not revoked + not expired
  const dbRes = await pool.query(
    `select id, user_id, revoked, expires_at
     from public.refresh_tokens
     where token_hash = $1`,
    [tokenHash]
  );

  const row = dbRes.rows[0];
  if (!row || row.revoked) return res.status(401).json({ error: "Refresh token revoked" });
  if (new Date(row.expires_at).getTime() < Date.now()) return res.status(401).json({ error: "Refresh token expired" });

  // rotate: revoke old, issue new refresh
  await pool.query(`update public.refresh_tokens set revoked = true where id = $1`, [row.id]);

  const userRes = await pool.query(`select id, email, role from public.users where id = $1`, [row.user_id]);
  const user = userRes.rows[0];
  if (!user) return res.status(401).json({ error: "User not found" });

  const newAccess = signAccessToken({ sub: user.id, email: user.email, role: user.role });
  const newRefresh = signRefreshToken({ sub: user.id });

  const newHash = sha256(newRefresh);
  const days = Number(process.env.REFRESH_TOKEN_TTL_DAYS || 7);
  const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

  await pool.query(
    `insert into public.refresh_tokens (user_id, token_hash, expires_at)
     values ($1, $2, $3)`,
    [user.id, newHash, expiresAt.toISOString()]
  );

  setRefreshCookie(res, newRefresh);
  return res.json({ accessToken: newAccess });
});

router.post("/logout", async (req, res) => {
  const token = req.cookies?.refresh_token;
  if (token) {
    const tokenHash = sha256(token);
    await pool.query(`update public.refresh_tokens set revoked = true where token_hash = $1`, [tokenHash]);
  }
  clearRefreshCookie(res);
  return res.json({ ok: true });
});

export default router;
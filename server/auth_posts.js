import express from "express";
import { pool } from "./db.js";
import { authRequired } from "./auth.js";

const router = express.Router();

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const role = req.user?.role;

    if (!role || !allowedRoles.includes(role)) {
      return res.status(403).json({
        error: "Only admins and moderators can create posts",
      });
    }

    next();
  };
}

// GET all posts
router.get("/", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        p.id,
        p.user_id,
        p.title,
        p.sport,
        p.description,
        p.video_url,
        p.thumbnail_url,
        p.created_at
      FROM posts p
      ORDER BY p.created_at DESC
    `);

    res.json(result.rows);
  } catch (err) {
    console.error("Load posts error:", err);
    res.status(500).json({ error: "Failed to load posts" });
  }
});

// CREATE post - admin/moderator only
router.post(
  "/",
  authRequired,
  requireRole("admin", "moderator"),
  async (req, res) => {
    try {
      const { title, sport, description, video_url, thumbnail_url } = req.body;

      if (!title || !sport || !description) {
        return res.status(400).json({
          error: "Title, sport, and description are required",
        });
      }

      const result = await pool.query(
        `
        INSERT INTO posts 
          (user_id, title, sport, description, video_url, thumbnail_url)
        VALUES 
          ($1, $2, $3, $4, $5, $6)
        RETURNING *
        `,
        [
          req.user.sub,
          title.trim(),
          sport.trim(),
          description.trim(),
          video_url?.trim() || null,
          thumbnail_url?.trim() || null,
        ]
      );

      res.status(201).json(result.rows[0]);
    } catch (err) {
      console.error("Create post error:", err);
      res.status(500).json({ error: "Failed to create post" });
    }
  }
);

export default router;
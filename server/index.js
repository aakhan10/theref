import "dotenv/config"; // ESM-safe env preload

import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import { pool } from "./db.js";
import authRoutes from "./routes_auth.js";
import postRoutes from "./auth_posts.js";
import { authRequired, verifyAccessToken } from "./auth.js";

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

// Optional auth for GET /posts.
// Guests can still view posts, but logged-in users get their own userVote/userLiked values.
function optionalAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const [type, token] = auth.split(" ");

  if (type === "Bearer" && token) {
    try {
      req.user = verifyAccessToken(token);
    } catch {
      req.user = null;
    }
  }

  next();
}

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

// GET posts with votes, post likes, comments, and comment likes
app.get("/posts", optionalAuth, async (req, res) => {
  try {
    const userId = req.user?.sub || null;

    const result = await pool.query(
      `
      select
        p.*,

        count(distinct v.user_id) filter (where v.value = 1) as upvotes,
        count(distinct v.user_id) filter (where v.value = -1) as downvotes,

        count(distinct pl.user_id) as heart_likes,

        (
          select v2.value
          from public.votes v2
          where v2.post_id = p.id
            and v2.user_id = $1
          limit 1
        ) as user_vote,

        exists (
          select 1
          from public.post_likes pl2
          where pl2.post_id = p.id
            and pl2.user_id = $1
        ) as user_liked,

        coalesce(
          json_agg(
            distinct jsonb_build_object(
              'id', c.id,
              'text', c.body,
              'parent_comment_id', c.parent_comment_id,
              'user_id', c.user_id,
              'user_email', u.email,
              'username', coalesce(u.username, split_part(u.email, '@', 1)),
              'likes', (
                select count(*)
                from public.comment_likes cl
                where cl.comment_id = c.id
              ),
              'user_liked', exists (
                select 1
                from public.comment_likes cl2
                where cl2.comment_id = c.id
                  and cl2.user_id = $1
              )
            )
          ) filter (where c.id is not null),
          '[]'
        ) as comments

      from public.posts p
      left join public.votes v on v.post_id = p.id
      left join public.post_likes pl on pl.post_id = p.id
      left join public.comments c on c.post_id = p.id
      left join public.users u on u.id = c.user_id
      group by p.id
      order by p.created_at desc;
      `,
      [userId]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("POSTS ERROR:", err);
    res.status(500).json({ error: "Failed to fetch posts" });
  }
});

// POST /posts comes from auth_posts.js
app.use("/posts", postRoutes);

// Save/update/remove a post vote.
// value = 1 means upvote, value = -1 means downvote.
app.post("/votes", authRequired, async (req, res) => {
  try {
    const { post_id, value } = req.body;

    if (!post_id || ![1, -1].includes(value)) {
      return res.status(400).json({
        error: "post_id and value are required. value must be 1 or -1.",
      });
    }

    const existingVote = await pool.query(
      `
      select value
      from public.votes
      where post_id = $1 and user_id = $2
      `,
      [post_id, req.user.sub]
    );

    // If user clicks the same vote again, remove it
    if (
      existingVote.rows.length > 0 &&
      Number(existingVote.rows[0].value) === value
    ) {
      await pool.query(
        `
        delete from public.votes
        where post_id = $1 and user_id = $2
        `,
        [post_id, req.user.sub]
      );
    } else {
      // Otherwise insert or update their vote
      await pool.query(
        `
        insert into public.votes (user_id, post_id, value)
        values ($1, $2, $3)
        on conflict (user_id, post_id)
        do update set value = excluded.value
        `,
        [req.user.sub, post_id, value]
      );
    }

    const counts = await pool.query(
      `
      select
        count(*) filter (where value = 1) as upvotes,
        count(*) filter (where value = -1) as downvotes,
        (
          select value
          from public.votes
          where post_id = $1 and user_id = $2
        ) as user_vote
      from public.votes
      where post_id = $1
      `,
      [post_id, req.user.sub]
    );

    const row = counts.rows[0];

    res.json({
      upvotes: Number(row.upvotes || 0),
      downvotes: Number(row.downvotes || 0),
      userVote:
        Number(row.user_vote) === 1
          ? "up"
          : Number(row.user_vote) === -1
          ? "down"
          : null,
    });
  } catch (err) {
    console.error("VOTE ERROR:", err);
    res.status(500).json({ error: "Failed to save vote" });
  }
});

// Save/remove a heart like on a post.
// One like per user per post.
app.post("/likes", authRequired, async (req, res) => {
  try {
    const { post_id } = req.body;

    if (!post_id) {
      return res.status(400).json({
        error: "post_id is required",
      });
    }

    const existingLike = await pool.query(
      `
      select 1
      from public.post_likes
      where post_id = $1 and user_id = $2
      `,
      [post_id, req.user.sub]
    );

    let userLiked;

    if (existingLike.rows.length > 0) {
      await pool.query(
        `
        delete from public.post_likes
        where post_id = $1 and user_id = $2
        `,
        [post_id, req.user.sub]
      );

      userLiked = false;
    } else {
      await pool.query(
        `
        insert into public.post_likes (user_id, post_id)
        values ($1, $2)
        on conflict (user_id, post_id)
        do nothing
        `,
        [req.user.sub, post_id]
      );

      userLiked = true;
    }

    const countResult = await pool.query(
      `
      select count(*) as likes
      from public.post_likes
      where post_id = $1
      `,
      [post_id]
    );

    res.json({
      likes: Number(countResult.rows[0].likes || 0),
      userLiked,
    });
  } catch (err) {
    console.error("LIKE ERROR:", err);
    res.status(500).json({ error: "Failed to save like" });
  }
});

// Save/remove a like on a comment or reply.
// One comment-like per user per comment.
app.post("/comment-likes", authRequired, async (req, res) => {
  try {
    const { comment_id } = req.body;

    if (!comment_id) {
      return res.status(400).json({
        error: "comment_id is required",
      });
    }

    const existingLike = await pool.query(
      `
      select 1
      from public.comment_likes
      where comment_id = $1 and user_id = $2
      `,
      [comment_id, req.user.sub]
    );

    let userLiked;

    if (existingLike.rows.length > 0) {
      await pool.query(
        `
        delete from public.comment_likes
        where comment_id = $1 and user_id = $2
        `,
        [comment_id, req.user.sub]
      );

      userLiked = false;
    } else {
      await pool.query(
        `
        insert into public.comment_likes (user_id, comment_id)
        values ($1, $2)
        on conflict (user_id, comment_id)
        do nothing
        `,
        [req.user.sub, comment_id]
      );

      userLiked = true;
    }

    const countResult = await pool.query(
      `
      select count(*) as likes
      from public.comment_likes
      where comment_id = $1
      `,
      [comment_id]
    );

    res.json({
      likes: Number(countResult.rows[0].likes || 0),
      userLiked,
    });
  } catch (err) {
    console.error("COMMENT LIKE ERROR:", err);
    res.status(500).json({ error: "Failed to save comment like" });
  }
});

app.post("/comments", authRequired, async (req, res) => {
  try {
    const { post_id, body, parent_comment_id } = req.body;

    if (!post_id || !body) {
      return res.status(400).json({ error: "post_id and body are required" });
    }

    const result = await pool.query(
      `
      insert into public.comments (post_id, user_id, body, parent_comment_id)
      values ($1, $2, $3, $4)
      returning id, post_id, user_id, body, parent_comment_id, created_at
      `,
      [post_id, req.user.sub, body, parent_comment_id || null]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("COMMENTS ERROR:", err);
    res.status(500).json({ error: "Failed to save comment" });
  }
});

// Admin can delete any comment/reply.
// Regular users can only delete their own comment/reply.
app.delete("/comments/:id", authRequired, async (req, res) => {
  try {
    const { id } = req.params;

    let result;

    if (req.user.role === "admin") {
      result = await pool.query(
        `
        delete from public.comments
        where id = $1
        returning id
        `,
        [id]
      );
    } else {
      result = await pool.query(
        `
        delete from public.comments
        where id = $1 and user_id = $2
        returning id
        `,
        [id, req.user.sub]
      );
    }

    if (result.rowCount === 0) {
      return res.status(403).json({
        error: "You can only delete your own comments",
      });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error("DELETE COMMENT ERROR:", err);
    res.status(500).json({ error: "Failed to delete comment" });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`API running on http://localhost:${port}`);
});
import jwt from "jsonwebtoken";

export function signAccessToken(payload) {
  const minutes = Number(process.env.ACCESS_TOKEN_TTL_MIN || 15);
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, { expiresIn: `${minutes}m` });
}

export function signRefreshToken(payload) {
  const days = Number(process.env.REFRESH_TOKEN_TTL_DAYS || 7);
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: `${days}d` });
}

export function verifyAccessToken(token) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
}

export function verifyRefreshToken(token) {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
}

export function authRequired(req, res, next) {
  const auth = req.headers.authorization || "";
  const [type, token] = auth.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({ error: "Missing Bearer token" });
  }

  try {
    req.user = verifyAccessToken(token); // { sub, email, role, iat, exp }
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired access token" });
  }
}
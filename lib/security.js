const crypto = require("crypto");

const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const ADMIN_KEY = () => process.env.ADMIN_KEY || "";

function securityMiddleware(_req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "script-src 'self'; " +
    "img-src 'self' data:; " +
    "connect-src 'self'; " +
    "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
  );
  next();
}

const buckets = new Map();
function rateLimit({ windowMs, max }) {
  return function (req, res, next) {
    const key = (req.ip || "?") + "|" + req.baseUrl + "|" + (req.path || "");
    const now = Date.now();
    let b = buckets.get(key);
    if (!b || now > b.reset) {
      b = { count: 0, reset: now + windowMs };
      buckets.set(key, b);
    }
    b.count++;
    if (b.count > max) {
      res.setHeader("Retry-After", Math.ceil((b.reset - now) / 1000));
      return res.status(429).json({ error: "slow down" });
    }
    next();
  };
}

function requireAdmin(req, res, next) {
  const expected = ADMIN_KEY();
  if (!expected) return res.status(503).json({ error: "admin disabled" });
  const got = String(req.headers["x-admin-key"] || "");
  const a = Buffer.from(got);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: "no" });
  }
  next();
}

function sanitize(v, max = 256) {
  if (typeof v !== "string") return "";
  return v.trim().replace(/[\u0000-\u001F\u007F]/g, "").slice(0, max);
}

function isEmail(v) {
  return typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

function issueChallenge() {
  const a = 2 + Math.floor(Math.random() * 8);
  const b = 2 + Math.floor(Math.random() * 8);
  const exp = Date.now() + 5 * 60_000;
  const b64 = Buffer.from(JSON.stringify({ a, b, exp })).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(b64).digest("base64url");
  return { id: b64 + "." + sig, question: `${a} + ${b}` };
}

function verifyChallenge(id, answer) {
  if (typeof id !== "string" || typeof answer !== "string") return false;
  const [b64, sig] = id.split(".");
  if (!b64 || !sig) return false;
  const expect = crypto.createHmac("sha256", SESSION_SECRET).update(b64).digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  let data;
  try { data = JSON.parse(Buffer.from(b64, "base64url").toString()); }
  catch { return false; }
  if (!data || typeof data.exp !== "number" || Date.now() > data.exp) return false;
  return String(data.a + data.b) === answer.trim();
}

function readCookie(req, name) {
  const raw = req.headers.cookie;
  if (!raw) return null;
  for (const p of raw.split(";")) {
    const i = p.indexOf("=");
    if (i < 0) continue;
    if (p.slice(0, i).trim() === name) return decodeURIComponent(p.slice(i + 1).trim());
  }
  return null;
}

module.exports = {
  SESSION_SECRET,
  securityMiddleware,
  rateLimit,
  requireAdmin,
  sanitize,
  isEmail,
  issueChallenge,
  verifyChallenge,
  readCookie,
};

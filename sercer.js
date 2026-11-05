const path = require("path");
const express = require("express");
const crypto = require("crypto");
const { securityMiddleware, rateLimit, requireAdmin, readCookie } = require("./lib/security");
const store = require("./lib/store");
const publicApi = require("./routes/public");
const adminApi = require("./routes/admin");

if (!process.env.ADMIN_KEY) {
  process.env.ADMIN_KEY = crypto.randomBytes(24).toString("hex");
  console.log("[gate] ADMIN_KEY generated:", process.env.ADMIN_KEY);
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "16kb" }));
app.use(securityMiddleware);

// ---- page routes (server-side session gate on /main) ----
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/subscribe", (_req, res) => res.sendFile(path.join(__dirname, "public", "subscribe.html")));
app.get("/main", (req, res) => {
  const sess = store.verifySession(readCookie(req, "sess"));
  if (!sess || !sess.member) return res.redirect("/subscribe");
  res.sendFile(path.join(__dirname, "public", "main.html"));
});

// ---- api divisions ----
app.use("/api/public", rateLimit({ windowMs: 60_000, max: 30 }), publicApi);
app.use("/api/admin",  rateLimit({ windowMs: 60_000, max: 120 }), requireAdmin, adminApi);

// ---- static assets (styles, js) ----
app.use(express.static(path.join(__dirname, "public"), { index: false, maxAge: "1h" }));

app.use((_req, res) => res.status(404).send("not found"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`[gate] http://localhost:${PORT}`));

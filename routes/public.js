const express = require("express");
const router = express.Router();
const store = require("../lib/store");
const {
  sanitize, isEmail, issueChallenge, verifyChallenge, readCookie,
} = require("../lib/security");

// ---- humanity challenge ----
router.post("/challenge", (_req, res) => {
  res.json(issueChallenge());
});

// ---- gate check: session-based, no enumeration ----
router.post("/gate-check", (req, res) => {
  const sess = store.verifySession(readCookie(req, "sess"));
  if (!sess || !sess.member) return res.json({ member: false });
  const user = store.findByEmail(sess.email);
  return res.json({ member: !!(user && user.member) });
});

// ---- subscribe / login (merged: register if new, log in if exists) ----
router.post("/subscribe", (req, res) => {
  const body = req.body || {};

  // honeypot: must be empty. silent success, no session.
  if (typeof body._hp === "string" && body._hp.trim().length > 0) {
    return res.json({ ok: true });
  }

  const name = sanitize(body.name, 64);
  const email = sanitize(body.email, 254).toLowerCase();
  const password = typeof body.password === "string" ? body.password : "";

  if (!verifyChallenge(body.challenge, body.answer)) {
    return res.status(400).json({ error: "human check failed — try again" });
  }
  if (!isEmail(email)) return res.status(400).json({ error: "invalid email" });
  if (name.length < 1) return res.status(400).json({ error: "first name required" });
  if (password.length < 8 || password.length > 256) {
    return res.status(400).json({ error: "password must be 8–256 characters" });
  }

  let user = store.findByEmail(email);
  if (!user) {
    user = store.createUser({ name, email, password, member: true });
  } else {
    if (!store.verifyPassword(password, user.hash)) {
      return res.status(401).json({ error: "wrong password for this email" });
    }
    if (name && name !== user.name) {
      store.updateUser(email, { name });
      user.name = name;
    }
  }

  const token = store.sessionFor(user);
  res.cookie("sess", token, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 3600 * 1000,
    path: "/",
  });
  res.json({ ok: true });
});

// ---- current session identity ----
router.get("/me", (req, res) => {
  const sess = store.verifySession(readCookie(req, "sess"));
  if (!sess) return res.json({ member: false });
  const user = store.findByEmail(sess.email);
  if (!user) return res.json({ member: false });
  res.json({ name: user.name, email: user.email, member: !!user.member });
});

// ---- logout ----
router.post("/logout", (req, res) => {
  res.clearCookie("sess", { path: "/" });
  res.json({ ok: true });
});

module.exports = router;

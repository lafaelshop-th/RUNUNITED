const express = require("express");
const router = express.Router();
const store = require("../lib/store");
const { sanitize, isEmail } = require("../lib/security");

router.get("/users", (_req, res) => {
  res.json({ users: store.listUsers() });
});

router.get("/users/:email", (req, res) => {
  const email = sanitize(req.params.email, 254).toLowerCase();
  const u = store.findByEmail(email);
  if (!u) return res.status(404).json({ error: "not found" });
  res.json(store.publicView(u));
});

router.patch("/users/:email", (req, res) => {
  const email = sanitize(req.params.email, 254).toLowerCase();
  const patch = {};
  if (typeof req.body.member === "boolean") patch.member = req.body.member;
  if (typeof req.body.name === "string") patch.name = sanitize(req.body.name, 64);
  const u = store.updateUser(email, patch);
  if (!u) return res.status(404).json({ error: "not found" });
  res.json(store.publicView(u));
});

router.delete("/users/:email", (req, res) => {
  const email = sanitize(req.params.email, 254).toLowerCase();
  if (!isEmail(email)) return res.status(400).json({ error: "bad email" });
  const ok = store.deleteUser(email);
  res.json({ ok });
});

module.exports = router;

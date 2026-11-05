const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { SESSION_SECRET } = require("./security");

const DATA_DIR = path.join(__dirname, "..", "data");
const DB_PATH = path.join(DATA_DIR, "users.json");

function ensure() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_PATH)) fs.writeFileSync(DB_PATH, JSON.stringify({ users: [] }, null, 2));
}
function load() { ensure(); return JSON.parse(fs.readFileSync(DB_PATH, "utf8")); }
function save(db) { fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2)); }

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 64);
  return salt.toString("hex") + ":" + hash.toString("hex");
}
function verifyPassword(pw, stored) {
  if (typeof stored !== "string") return false;
  const [saltHex, hashHex] = stored.split(":");
  if (!saltHex || !hashHex) return false;
  const salt = Buffer.from(saltHex, "hex");
  const expected = Buffer.from(hashHex, "hex");
  const actual = crypto.scryptSync(pw, salt, 64);
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function findByEmail(email) {
  const db = load();
  return db.users.find(u => u.email === email) || null;
}

function createUser({ name, email, password, member = true }) {
  const db = load();
  if (db.users.some(u => u.email === email)) throw new Error("exists");
  const user = {
    email,
    name,
    hash: hashPassword(password),
    member: !!member,
    created: Date.now(),
  };
  db.users.push(user);
  save(db);
  return user;
}

function updateUser(email, patch) {
  const db = load();
  const u = db.users.find(x => x.email === email);
  if (!u) return null;
  if (typeof patch.member === "boolean") u.member = patch.member;
  if (typeof patch.name === "string") u.name = patch.name;
  save(db);
  return u;
}

function deleteUser(email) {
  const db = load();
  const before = db.users.length;
  db.users = db.users.filter(u => u.email !== email);
  save(db);
  return db.users.length !== before;
}

function listUsers() {
  return load().users.map(publicView);
}

function publicView(u) {
  return { email: u.email, name: u.name, member: !!u.member, created: u.created };
}

function sessionFor(user) {
  const payload = JSON.stringify({
    email: user.email,
    name: user.name,
    member: !!user.member,
    exp: Date.now() + 7 * 24 * 3600 * 1000,
  });
  const b64 = Buffer.from(payload).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(b64).digest("base64url");
  return b64 + "." + sig;
}

function verifySession(token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  const expect = crypto.createHmac("sha256", SESSION_SECRET).update(b64).digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let data;
  try { data = JSON.parse(Buffer.from(b64, "base64url").toString()); }
  catch { return null; }
  if (!data || typeof data.exp !== "number" || Date.now() > data.exp) return null;
  return data;
}

module.exports = {
  hashPassword, verifyPassword,
  findByEmail, createUser, updateUser, deleteUser, listUsers, publicView,
  sessionFor, verifySession,
};

import express from "express";
import session from "express-session";
import SQLiteStoreFactory from "connect-sqlite3";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "chester.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 phone TEXT DEFAULT '', password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
 status TEXT NOT NULL DEFAULT 'active', plan TEXT NOT NULL DEFAULT 'Free',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tickets (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, subject TEXT NOT NULL,
 message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Open', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, service TEXT NOT NULL,
 details TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);
const getSetting = db.prepare("SELECT value FROM settings WHERE key=?");
const setSetting = db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
if (!getSetting.get("support_phone")) setSetting.run("support_phone", process.env.SUPPORT_PHONE || "+44 7888 370178");

if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
  const email = process.env.ADMIN_EMAIL.trim().toLowerCase();
  const existing = db.prepare("SELECT id FROM users WHERE email=?").get(email);
  if (!existing) {
    const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
    db.prepare("INSERT INTO users(name,email,password_hash,role,plan) VALUES(?,?,?,?,?)")
      .run("CHESTER Administrator", email, hash, "admin", "Business");
    console.log("Initial administrator account created from environment settings.");
  }
}

const app = express();
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "30kb" }));
app.use(express.urlencoded({ extended: false }));
const SQLiteStore = SQLiteStoreFactory(session);
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir }),
  name: "chester.sid",
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret-before-deploying",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 1000*60*60*8 }
}));
app.use("/api/auth", rateLimit({ windowMs: 15*60*1000, limit: 30, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, "public")));

const safeUser = u => ({ id:u.id, name:u.name, email:u.email, phone:u.phone, role:u.role, plan:u.plan, status:u.status, createdAt:u.created_at });
const currentUser = req => req.session.userId ? db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId) : null;
function requireAuth(req,res,next) {
  const user=currentUser(req);
  if (!user || user.status !== "active") { req.session.destroy(()=>{}); return res.status(401).json({error:"Please sign in again."}); }
  req.user=user; next();
}
function requireAdmin(req,res,next) {
  if (req.user?.role !== "admin") return res.status(403).json({error:"Administrator access required."});
  next();
}
const emailOk = s => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s||""));
app.post("/api/auth/register", (req,res)=>{
  const {name,email,password,phone=""}=req.body||{};
  if (!name?.trim() || !emailOk(email) || typeof password!=="string" || password.length<10)
    return res.status(400).json({error:"Enter your name, a valid email and a password of at least 10 characters."});
  try {
    const hash=bcrypt.hashSync(password,12);
    const result=db.prepare("INSERT INTO users(name,email,phone,password_hash) VALUES(?,?,?,?)")
      .run(name.trim().slice(0,80),email.trim().toLowerCase(),String(phone).slice(0,30),hash);
    req.session.userId=Number(result.lastInsertRowid);
    res.json({user:safeUser(currentUser(req))});
  } catch(e) { res.status(409).json({error:"An account with that email may already exist."}); }
});
app.post("/api/auth/login",(req,res)=>{
  const email=String(req.body?.email||"").trim().toLowerCase(), password=String(req.body?.password||"");
  const user=db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if(!user || !bcrypt.compareSync(password,user.password_hash) || user.status!=="active")
    return res.status(401).json({error:"Email or password is incorrect, or the account is inactive."});
  req.session.userId=user.id; res.json({user:safeUser(user)});
});
app.post("/api/auth/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",requireAuth,(req,res)=>res.json({user:safeUser(req.user),supportPhone:getSetting.get("support_phone")?.value||"+44 7888 370178"}));
app.patch("/api/profile",requireAuth,(req,res)=>{
  const name=String(req.body?.name||"").trim().slice(0,80), phone=String(req.body?.phone||"").slice(0,30);
  if(!name) return res.status(400).json({error:"Name is required."});
  db.prepare("UPDATE users SET name=?,phone=? WHERE id=?").run(name,phone,req.user.id);
  res.json({user:safeUser(currentUser(req))});
});
app.post("/api/password",requireAuth,(req,res)=>{
  const {currentPassword,newPassword}=req.body||{};
  if(!bcrypt.compareSync(String(currentPassword||""),req.user.password_hash)) return res.status(400).json({error:"Current password is incorrect."});
  if(typeof newPassword!=="string" || newPassword.length<10) return res.status(400).json({error:"New password must be at least 10 characters."});
  db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(bcrypt.hashSync(newPassword,12),req.user.id);
  res.json({ok:true});
});
app.get("/api/overview",requireAuth,(req,res)=>{
  const tickets=db.prepare("SELECT * FROM tickets WHERE user_id=? ORDER BY id DESC").all(req.user.id);
  const orders=db.prepare("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC").all(req.user.id);
  res.json({tickets,orders,transactions:[],walletBalance:0});
});
app.post("/api/tickets",requireAuth,(req,res)=>{
  const subject=String(req.body?.subject||"").trim().slice(0,120), message=String(req.body?.message||"").trim().slice(0,3000);
  if(!subject||!message) return res.status(400).json({error:"Enter a subject and message."});
  db.prepare("INSERT INTO tickets(user_id,subject,message) VALUES(?,?,?)").run(req.user.id,subject,message);
  res.json({ok:true});
});
app.post("/api/orders",requireAuth,(req,res)=>{
  const service=String(req.body?.service||"").trim().slice(0,100), details=String(req.body?.details||"").trim().slice(0,1000);
  if(!service) return res.status(400).json({error:"Choose a service."});
  db.prepare("INSERT INTO orders(user_id,service,details) VALUES(?,?,?)").run(req.user.id,service,details);
  res.json({ok:true});
});
app.get("/api/admin/summary",requireAuth,requireAdmin,(req,res)=>{
  res.json({
    users:db.prepare("SELECT COUNT(*) n FROM users WHERE role='user'").get().n,
    active:db.prepare("SELECT COUNT(*) n FROM users WHERE role='user' AND status='active'").get().n,
    tickets:db.prepare("SELECT COUNT(*) n FROM tickets WHERE status='Open'").get().n,
    orders:db.prepare("SELECT COUNT(*) n FROM orders").get().n
  });
});
app.get("/api/admin/users",requireAuth,requireAdmin,(req,res)=>{
  res.json({users:db.prepare("SELECT id,name,email,phone,role,status,plan,created_at FROM users ORDER BY id DESC").all()});
});
app.patch("/api/admin/users/:id",requireAuth,requireAdmin,(req,res)=>{
  const id=Number(req.params.id), status=req.body?.status, plan=req.body?.plan;
  const target=db.prepare("SELECT * FROM users WHERE id=?").get(id);
  if(!target) return res.status(404).json({error:"User not found."});
  if(target.role==="admin") return res.status(400).json({error:"Admin accounts cannot be changed here."});
  if(status && !["active","suspended"].includes(status)) return res.status(400).json({error:"Invalid status."});
  if(plan && !["Free","Pro","Business"].includes(plan)) return res.status(400).json({error:"Invalid plan."});
  if(status) db.prepare("UPDATE users SET status=? WHERE id=?").run(status,id);
  if(plan) db.prepare("UPDATE users SET plan=? WHERE id=?").run(plan,id);
  res.json({ok:true});
});
app.get("/api/admin/tickets",requireAuth,requireAdmin,(req,res)=>{
  res.json({tickets:db.prepare("SELECT t.*,u.name,u.email FROM tickets t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC").all()});
});
app.patch("/api/admin/tickets/:id",requireAuth,requireAdmin,(req,res)=>{
  const status=req.body?.status;
  if(!["Open","In progress","Resolved"].includes(status)) return res.status(400).json({error:"Invalid ticket status."});
  db.prepare("UPDATE tickets SET status=? WHERE id=?").run(status,Number(req.params.id)); res.json({ok:true});
});
app.get("/api/admin/orders",requireAuth,requireAdmin,(req,res)=>{
  res.json({orders:db.prepare("SELECT o.*,u.name,u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC").all()});
});
app.patch("/api/admin/orders/:id",requireAuth,requireAdmin,(req,res)=>{
  const status=req.body?.status;
  if(!["Pending","Processing","Completed","Cancelled"].includes(status)) return res.status(400).json({error:"Invalid order status."});
  db.prepare("UPDATE orders SET status=? WHERE id=?").run(status,Number(req.params.id)); res.json({ok:true});
});
app.get("/api/admin/settings",requireAuth,requireAdmin,(req,res)=>res.json({supportPhone:getSetting.get("support_phone")?.value||""}));
app.patch("/api/admin/settings",requireAuth,requireAdmin,(req,res)=>{
  const phone=String(req.body?.supportPhone||"").trim().slice(0,30);
  if(!phone) return res.status(400).json({error:"Support phone is required."});
  setSetting.run("support_phone",phone); res.json({ok:true,supportPhone:phone});
});
app.get("/health",(req,res)=>res.json({ok:true,service:"CHESTER TECHNOLOGIES"}));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
const port=Number(process.env.PORT||3000);
app.listen(port,"0.0.0.0",()=>console.log(`CHESTER TECHNOLOGIES running on port ${port}`));

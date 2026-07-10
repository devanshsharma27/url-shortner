import express from "express";
import { nanoid } from "nanoid";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const PORT = 3000;
const prisma = new PrismaClient();

// Load JWT secret from .env — crash loudly at startup if missing
const JWT_SECRET: string = process.env.JWT_SECRET ?? "";
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not set in .env");
}

app.use(express.json());

// ================= AUTH MIDDLEWARE =================

// Extend Express's Request type so TypeScript allows req.userId
interface AuthRequest extends express.Request {
  userId?: number;
}

function requireAuth(
  req: AuthRequest,
  res: express.Response,
  next: express.NextFunction
) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing or malformed token" });
  }

  const token = authHeader.slice(7); // strip "Bearer "

  try {
    const payload = jwt.verify(token, JWT_SECRET) as { userId: number };
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ error: "invalid or expired token" });
  }
}

// ================= HEALTH =================

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", message: "Backend is running" });
});

// ================= AUTH ROUTES =================

app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "password must be at least 8 characters" });
  }

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return res.status(409).json({ error: "email already registered" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: { email, password: hashedPassword },
  });

  res.status(201).json({ id: user.id, email: user.email });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return res.status(401).json({ error: "invalid credentials" });
  }

  const passwordMatches = await bcrypt.compare(password, user.password);
  if (!passwordMatches) {
    return res.status(401).json({ error: "invalid credentials" });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "15m" });

  res.json({ token });
});

// ================= URL ROUTES =================

// List all URLs (we'll make this per-user later)
app.get("/api/urls", async (req, res) => {
  const urls = await prisma.url.findMany({
    orderBy: { createdAt: "desc" },
  });
  res.json(urls);
});

// Create a short URL — PROTECTED: requires a valid token
app.post("/api/urls", requireAuth, async (req: AuthRequest, res) => {
  const { longUrl } = req.body;

  if (!longUrl) {
    return res.status(400).json({ error: "longUrl is required" });
  }

  const shortCode = nanoid(6);

  const record = await prisma.url.create({
    data: { shortCode, longUrl, userId: req.userId },
  });

  res.status(201).json({
    ...record,
    shortUrl: `http://localhost:${PORT}/${shortCode}`,
  });
});

// Redirect — public, stays last (catch-all)
app.get("/:code", async (req, res) => {
  const { code } = req.params;

  const record = await prisma.url.findUnique({
    where: { shortCode: code },
  });

  if (!record) {
    return res.status(404).json({ error: "Short URL not found" });
  }

  await prisma.url.update({
    where: { shortCode: code },
    data: { clicks: { increment: 1 } },
  });

  res.redirect(302, record.longUrl);
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
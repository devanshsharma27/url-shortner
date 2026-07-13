import express from "express";
import { nanoid } from "nanoid";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Redis from "ioredis";

const app = express();
const PORT = 3000;
const prisma = new PrismaClient();

const redis = new Redis({ host: "localhost", port: 6379 });
const CACHE_TTL_SECONDS = 3600;

const JWT_SECRET: string = process.env.JWT_SECRET ?? "";
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not set in .env");
}

const REFRESH_TOKEN_DAYS = 7;

app.use(express.json());

// ================= AUTH MIDDLEWARE =================

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

  const token = authHeader.slice(7);

  try {
    const payload = jwt.verify(token, JWT_SECRET) as { userId: number };
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ error: "invalid or expired token" });
  }
}

// NEW: helper — create both tokens for a user
async function issueTokens(userId: number) {
  const accessToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: "15m" });

  const refreshToken = nanoid(64);
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000);

  await prisma.refreshToken.create({
    data: { token: refreshToken, userId, expiresAt },
  });

  return { accessToken, refreshToken };
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

  const tokens = await issueTokens(user.id);          // CHANGED

  res.json(tokens);                                    // { accessToken, refreshToken }
});

// NEW: exchange a refresh token for fresh tokens (with rotation)
app.post("/api/auth/refresh", async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: "refreshToken is required" });
  }

  const stored = await prisma.refreshToken.findUnique({
    where: { token: refreshToken },
  });

  if (!stored) {
    return res.status(401).json({ error: "invalid refresh token" });
  }

  if (stored.expiresAt < new Date()) {
    await prisma.refreshToken.delete({ where: { id: stored.id } });
    return res.status(401).json({ error: "refresh token expired" });
  }

  // ROTATION: old token dies, new pair is issued
  await prisma.refreshToken.delete({ where: { id: stored.id } });
  const tokens = await issueTokens(stored.userId);

  res.json(tokens);
});

// NEW: logout — revoke the refresh token server-side
app.post("/api/auth/logout", async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: "refreshToken is required" });
  }

  await prisma.refreshToken.deleteMany({
    where: { token: refreshToken },
  });

  res.status(204).send();
});

// ================= URL ROUTES =================

app.get("/api/urls", requireAuth, async (req: AuthRequest, res) => {
  const page = Math.max(1, parseInt(String(req.query.page ?? "1"), 10) || 1);
  const limit = Math.min(50, Math.max(1, parseInt(String(req.query.limit ?? "10"), 10) || 10));
  const search = String(req.query.search ?? "");

  const where = {
    userId: req.userId,
    ...(search && {
      longUrl: { contains: search, mode: "insensitive" as const },
    }),
  };

  const [urls, total] = await Promise.all([
    prisma.url.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.url.count({ where }),
  ]);

  res.json({
    data: urls,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  });
});

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

app.delete("/api/urls/:id", requireAuth, async (req: AuthRequest, res) => {
  const id = parseInt(String(req.params.id), 10);

  if (isNaN(id)) {
    return res.status(400).json({ error: "invalid id" });
  }

  const record = await prisma.url.findUnique({ where: { id } });

  if (!record) {
    return res.status(404).json({ error: "URL not found" });
  }

  if (record.userId !== req.userId) {
    return res.status(403).json({ error: "you do not own this URL" });
  }

  await prisma.url.delete({ where: { id } });

  await redis.del(`url:${record.shortCode}`);

  res.status(204).send();
});

app.patch("/api/urls/:id", requireAuth, async (req: AuthRequest, res) => {
  const id = parseInt(String(req.params.id), 10);
  const { longUrl } = req.body;

  if (isNaN(id)) {
    return res.status(400).json({ error: "invalid id" });
  }
  if (!longUrl) {
    return res.status(400).json({ error: "longUrl is required" });
  }

  const record = await prisma.url.findUnique({ where: { id } });

  if (!record) {
    return res.status(404).json({ error: "URL not found" });
  }

  if (record.userId !== req.userId) {
    return res.status(403).json({ error: "you do not own this URL" });
  }

  const updated = await prisma.url.update({
    where: { id },
    data: { longUrl },
  });

  await redis.del(`url:${record.shortCode}`);

  res.json(updated);
});

// Redirect — cached
app.get("/:code", async (req, res) => {
  const { code } = req.params;
  const cacheKey = `url:${code}`;

  const cached = await redis.get(cacheKey);
  if (cached) {
    prisma.url
      .update({ where: { shortCode: code }, data: { clicks: { increment: 1 } } })
      .catch(() => {});
    return res.redirect(302, cached);
  }

  const record = await prisma.url.findUnique({
    where: { shortCode: code },
  });

  if (!record) {
    return res.status(404).json({ error: "Short URL not found" });
  }

  await redis.set(cacheKey, record.longUrl, "EX", CACHE_TTL_SECONDS);

  await prisma.url.update({
    where: { shortCode: code },
    data: { clicks: { increment: 1 } },
  });

  res.redirect(302, record.longUrl);
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
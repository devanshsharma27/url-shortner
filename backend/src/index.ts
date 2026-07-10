import express from "express";
import { nanoid } from "nanoid";
import { PrismaClient } from "@prisma/client";

const app = express();
const PORT = 3000;
const prisma = new PrismaClient();

app.use(express.json());

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", message: "Backend is running" });
});

// List all URLs — now from the database
app.get("/api/urls", async (req, res) => {
  const urls = await prisma.url.findMany({
    orderBy: { createdAt: "desc" },
  });
  res.json(urls);
});

// Create a short URL — now saved permanently
app.post("/api/urls", async (req, res) => {
  const { longUrl } = req.body;

  if (!longUrl) {
    return res.status(400).json({ error: "longUrl is required" });
  }

  const shortCode = nanoid(6);

  const record = await prisma.url.create({
    data: { shortCode, longUrl },
  });

  res.status(201).json({
    ...record,
    shortUrl: `http://localhost:${PORT}/${shortCode}`,
  });
});

// Redirect — looks up the database
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
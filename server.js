import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { prisma } from "./db.js";

const app = express();
app.use(helmet());
app.use(express.json({ limit: "256kb" }));

const ALLOWED = (process.env.CORS_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED.length === 0 || ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error("Not allowed by CORS"));
  }
}));
app.use(rateLimit({ windowMs: 60_000, max: 60 }));

app.get("/healthz", (_req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

app.post("/devices/register", async (req, res) => {
  const { platform, push_token, user_id, org_id } = req.body || {};
  if (!platform || !push_token) return res.status(400).json({ error: "platform and push_token required" });
  const device = await prisma.device.create({
    data: {
      platform,
      pushToken: push_token,
      userId: user_id || null,
      orgId: org_id || null
    }
  });
  res.json({ ok: true, id: device.id });
});

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`API up on :${port}`));

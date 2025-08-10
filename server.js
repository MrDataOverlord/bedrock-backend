import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";

const app = express();
app.use(helmet());
app.use(express.json({ limit: "256kb" }));

// Allowlist via env var: CORS_ORIGINS="app://,capacitor://,ms-windows-store://"
const ALLOWED = (process.env.CORS_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED.length === 0 || ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error("Not allowed by CORS"));
  }
}));

// Basic rate limit
app.use(rateLimit({ windowMs: 60_000, max: 60 }));

app.get("/healthz", (_req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// Placeholder endpoint (no DB yet)
app.post("/devices/register", (req, res) => {
  const { platform, push_token } = req.body || {};
  if (!platform || !push_token) return res.status(400).json({ error: "platform and push_token required" });
  // Later: save to DB. For now, just echo success.
  return res.json({ ok: true });
});

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`API up on :${port}`));

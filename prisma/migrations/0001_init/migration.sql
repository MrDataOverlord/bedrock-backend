-- CreateTable: Device
CREATE TABLE IF NOT EXISTS "Device" (
  "id"        TEXT PRIMARY KEY,
  "userId"    TEXT,
  "orgId"     TEXT,
  "platform"  TEXT NOT NULL,
  "pushToken" TEXT NOT NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL
);

-- Prisma will set "id" (cuid) and manage "updatedAt" values in queries.
-- No DB-side trigger needed for updatedAt because Prisma updates it automatically.

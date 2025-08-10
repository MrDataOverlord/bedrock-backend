-- Users
CREATE TABLE IF NOT EXISTS "User" (
  "id"           TEXT PRIMARY KEY,
  "email"        TEXT UNIQUE NOT NULL,
  "passwordHash" TEXT NOT NULL,
  "totpSecret"   TEXT,
  "createdAt"    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Orgs (each owner gets one org for now)
CREATE TABLE IF NOT EXISTS "Org" (
  "id"           TEXT PRIMARY KEY,
  "ownerUserId"  TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "name"         TEXT NOT NULL DEFAULT 'My Org',
  "createdAt"    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Members (user belongs to an org with a role)
CREATE TABLE IF NOT EXISTS "Member" (
  "id"        TEXT PRIMARY KEY,
  "orgId"     TEXT NOT NULL REFERENCES "Org"("id") ON DELETE CASCADE,
  "userId"    TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "role"      TEXT NOT NULL DEFAULT 'owner',
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

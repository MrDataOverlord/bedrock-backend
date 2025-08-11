CREATE TABLE IF NOT EXISTS "Subscription" (
  "id"           TEXT PRIMARY KEY,
  "orgId"        TEXT NOT NULL REFERENCES "Org"("id") ON DELETE CASCADE,
  "provider"     TEXT NOT NULL DEFAULT 'stripe',
  "status"       TEXT NOT NULL DEFAULT 'inactive', -- inactive|active|past_due|canceled
  "currentPeriodEnd" TIMESTAMPTZ,
  "createdAt"    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt"    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "sub_org_idx" ON "Subscription"("orgId");

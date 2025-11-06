/*
  Warnings:

  - A unique constraint covering the columns `[stripeCustomerId]` on the table `Org` will be added. If there are existing duplicate values, this will fail.

*/
-- DropForeignKey
ALTER TABLE "Org" DROP CONSTRAINT "Org_ownerUserId_fkey";

-- AlterTable
ALTER TABLE "Org" ADD COLUMN     "stripeCustomerId" TEXT,
ALTER COLUMN "ownerUserId" DROP NOT NULL;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "isAdmin" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "NotificationSettings" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "soundEnabled" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NotificationSettings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NotificationRule" (
    "id" TEXT NOT NULL,
    "settingsId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" TEXT NOT NULL DEFAULT 'contains',
    "pattern" TEXT NOT NULL,
    "soundFile" TEXT NOT NULL DEFAULT 'default.wav',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NotificationRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NotificationTrigger" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "ruleName" TEXT NOT NULL,
    "triggeredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lineLength" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "NotificationTrigger_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "NotificationSettings_userId_key" ON "NotificationSettings"("userId");

-- CreateIndex
CREATE INDEX "NotificationSettings_userId_idx" ON "NotificationSettings"("userId");

-- CreateIndex
CREATE INDEX "NotificationRule_settingsId_idx" ON "NotificationRule"("settingsId");

-- CreateIndex
CREATE INDEX "NotificationTrigger_userId_idx" ON "NotificationTrigger"("userId");

-- CreateIndex
CREATE INDEX "NotificationTrigger_triggeredAt_idx" ON "NotificationTrigger"("triggeredAt");

-- CreateIndex
CREATE UNIQUE INDEX "Org_stripeCustomerId_key" ON "Org"("stripeCustomerId");

-- AddForeignKey
ALTER TABLE "Org" ADD CONSTRAINT "Org_ownerUserId_fkey" FOREIGN KEY ("ownerUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NotificationSettings" ADD CONSTRAINT "NotificationSettings_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NotificationRule" ADD CONSTRAINT "NotificationRule_settingsId_fkey" FOREIGN KEY ("settingsId") REFERENCES "NotificationSettings"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NotificationTrigger" ADD CONSTRAINT "NotificationTrigger_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

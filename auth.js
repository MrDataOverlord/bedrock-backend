import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { authenticator } from "otplib";
import { prisma } from "./db.js";

const JWT_SECRET = process.env.JWT_SECRET;

export function signJwt(payload, expiresIn = "15m") {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

export function verifyJwt(token) {
  return jwt.verify(token, JWT_SECRET);
}

export async function createUserWithOrg(email, password) {
  const passwordHash = await bcrypt.hash(password, 12);
  const user = await prisma.user.create({
    data: { email, passwordHash }
  });
  const org = await prisma.org.create({
    data: { ownerUserId: user.id, name: "My Server" }
  });
  await prisma.member.create({
    data: { orgId: org.id, userId: user.id, role: "owner" }
  });
  return { user, org };
}

export async function authenticate(email, password) {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return null;
  const ok = await bcrypt.compare(password, user.passwordHash);
  return ok ? user : null;
}

export function newTotpSecret() {
  const secret = authenticator.generateSecret();
  const otpauth = authenticator.keyuri("owner", "Bedrock Log Viewer", secret);
  return { secret, otpauth };
}

export function verifyTotp(secret, code) {
  return authenticator.check(code, secret);
}

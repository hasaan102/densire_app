import { createHash, createHmac, timingSafeEqual } from "node:crypto";

const COOKIE_NAME = "densire_admin_session";

export function getAdminAuthConfig() {
  const password = process.env.ADMIN_PASSWORD;
  const secret = process.env.ADMIN_SESSION_SECRET;

  if (!password || password.length < 12 || !secret || secret.length < 32) {
    return null;
  }

  return { password, secret };
}

export function safeEqual(left: string, right: string) {
  const leftHash = createHash("sha256").update(left).digest();
  const rightHash = createHash("sha256").update(right).digest();
  return timingSafeEqual(leftHash, rightHash);
}

export function signAdminExpiry(expiry: string, secret: string) {
  return createHmac("sha256", secret).update(expiry).digest("base64url");
}

export function hasValidAdminSession(request: Request, secret: string) {
  const cookieHeader = request.headers.get("cookie");
  if (!cookieHeader) return false;

  const prefix = `${COOKIE_NAME}=`;
  const cookie = cookieHeader.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(prefix));
  const token = cookie?.slice(prefix.length);
  if (!token) return false;

  const [expiry, signature, ...extra] = token.split(".");
  if (extra.length || !/^\d+$/.test(expiry) || Number(expiry) <= Date.now()) {
    return false;
  }

  return safeEqual(signature, signAdminExpiry(expiry, secret));
}

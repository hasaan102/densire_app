import {
  createHash,
  createHmac,
  timingSafeEqual,
} from "node:crypto";

const COOKIE_NAME = "densire_admin_session";
const SESSION_DURATION_SECONDS = 60 * 60 * 8;

function getAuthConfig() {
  const password = process.env.ADMIN_PASSWORD;
  const secret = process.env.ADMIN_SESSION_SECRET;

  if (!password || password.length < 12 || !secret || secret.length < 32) {
    return null;
  }

  return { password, secret };
}

function jsonResponse(
  body: Record<string, string | boolean>,
  status = 200,
  headers = new Headers(),
) {
  headers.set("Cache-Control", "no-store");
  return Response.json(body, { status, headers });
}

function signExpiry(expiry: string, secret: string) {
  return createHmac("sha256", secret).update(expiry).digest("base64url");
}

function safeEqual(left: string, right: string) {
  const leftHash = createHash("sha256").update(left).digest();
  const rightHash = createHash("sha256").update(right).digest();
  return timingSafeEqual(leftHash, rightHash);
}

function getCookie(request: Request, name: string) {
  const cookieHeader = request.headers.get("cookie");
  if (!cookieHeader) return null;

  const prefix = `${name}=`;
  const cookie = cookieHeader.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(prefix));
  return cookie ? cookie.slice(prefix.length) : null;
}

function hasValidSession(request: Request, secret: string) {
  const token = getCookie(request, COOKIE_NAME);
  if (!token) return false;

  const [expiry, signature, ...extra] = token.split(".");
  if (extra.length || !/^\d+$/.test(expiry) || Number(expiry) <= Date.now()) {
    return false;
  }

  return safeEqual(signature, signExpiry(expiry, secret));
}

function cookieOptions(maxAge: number) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}

export async function GET(request: Request) {
  const config = getAuthConfig();
  if (!config) {
    return jsonResponse({
      authenticated: false,
      error: "Admin sign-in is not configured. Set ADMIN_PASSWORD and ADMIN_SESSION_SECRET.",
    }, 503);
  }

  if (!hasValidSession(request, config.secret)) {
    return jsonResponse({ authenticated: false }, 401);
  }

  return jsonResponse({ authenticated: true });
}

export async function POST(request: Request) {
  const config = getAuthConfig();
  if (!config) {
    return jsonResponse({
      authenticated: false,
      error: "Admin sign-in is not configured. Set ADMIN_PASSWORD and ADMIN_SESSION_SECRET.",
    }, 503);
  }

  if (!request.headers.get("content-type")?.includes("application/json")) {
    return jsonResponse({ authenticated: false, error: "Invalid request." }, 415);
  }
  const contentLength = Number(request.headers.get("content-length"));
  if (contentLength > 4096) {
    return jsonResponse({ authenticated: false, error: "Invalid request." }, 413);
  }

  let payload: unknown;
  try {
    payload = await request.json();
  } catch {
    return jsonResponse({ authenticated: false, error: "Invalid request." }, 400);
  }

  const password =
    payload && typeof payload === "object" && "password" in payload
      ? payload.password
      : null;
  if (typeof password !== "string" || password.length > 1024) {
    return jsonResponse({ authenticated: false, error: "Enter your admin password." }, 400);
  }

  if (!safeEqual(password, config.password)) {
    return jsonResponse({ authenticated: false, error: "Incorrect admin password." }, 401);
  }

  const expiry = String(Date.now() + SESSION_DURATION_SECONDS * 1000);
  const token = `${expiry}.${signExpiry(expiry, config.secret)}`;
  const headers = new Headers();
  headers.set(
    "Set-Cookie",
    `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_DURATION_SECONDS}${process.env.NODE_ENV === "production" ? "; Secure" : ""}`,
  );
  return jsonResponse({ authenticated: true }, 200, headers);
}

export async function DELETE() {
  const headers = new Headers();
  headers.set("Set-Cookie", cookieOptions(0));
  return jsonResponse({ authenticated: false }, 200, headers);
}

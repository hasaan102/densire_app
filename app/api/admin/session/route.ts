import {
  getAdminAuthConfig,
  hasValidAdminSession,
  safeEqual,
  signAdminExpiry,
} from "@/app/lib/admin-auth";

const COOKIE_NAME = "densire_admin_session";
const SESSION_DURATION_SECONDS = 60 * 60 * 8;

function jsonResponse(
  body: Record<string, string | boolean>,
  status = 200,
  headers = new Headers(),
) {
  headers.set("Cache-Control", "no-store");
  return Response.json(body, { status, headers });
}

function cookieOptions(maxAge: number) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}

export async function GET(request: Request) {
  const config = getAdminAuthConfig();
  if (!config) {
    return jsonResponse({
      authenticated: false,
      error: "Admin sign-in is not configured. Set ADMIN_PASSWORD and ADMIN_SESSION_SECRET.",
    }, 503);
  }

  if (!hasValidAdminSession(request, config.secret)) {
    return jsonResponse({ authenticated: false }, 401);
  }

  return jsonResponse({ authenticated: true });
}

export async function POST(request: Request) {
  const config = getAdminAuthConfig();
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
  const token = `${expiry}.${signAdminExpiry(expiry, config.secret)}`;
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

import {
  getAdminAuthConfig,
  hasValidAdminSession,
} from "@/app/lib/admin-auth";

const ORDER_BODY_LIMIT = 1_000_000;
const ORDER_STATUSES = ["New", "Preparing", "Ready", "Completed", "Cancelled"];
const PAYMENT_METHODS = ["Cash", "JazzCash", "Easypaisa"];

type OrderRecord = {
  id: string;
  createdAt: string;
  status: "New";
  orderType: "delivery" | "pickup" | "dinein";
  customer: {
    name: string;
    phone: string;
    address: string;
  };
  items: Array<{
    name: string;
    qty: number;
    unitPrice: number;
    [key: string]: unknown;
  }>;
  subtotal: number;
  deliveryFee: number;
  grandTotal: number;
  paymentMethod: "Cash" | "JazzCash" | "Easypaisa";
  paymentScreenshot: string;
  notes: string;
  [key: string]: unknown;
};

function jsonResponse(body: unknown, status = 200) {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function isOrderRecord(value: unknown): value is OrderRecord {
  if (!isRecord(value) || !isRecord(value.customer) || !Array.isArray(value.items)) {
    return false;
  }

  const { customer, items } = value;
  return typeof value.id === "string"
    && value.id.length > 0
    && value.id.length <= 80
    && typeof value.createdAt === "string"
    && Number.isFinite(Date.parse(value.createdAt))
    && value.status === "New"
    && ["delivery", "pickup", "dinein"].includes(String(value.orderType))
    && typeof customer.name === "string"
    && customer.name.length <= 120
    && typeof customer.phone === "string"
    && customer.phone.length <= 40
    && typeof customer.address === "string"
    && customer.address.length <= 500
    && items.length > 0
    && items.length <= 50
    && items.every((item) => isRecord(item)
      && typeof item.name === "string"
      && item.name.length <= 160
      && typeof item.qty === "number"
      && Number.isFinite(item.qty)
      && item.qty > 0
      && item.qty <= 100
      && typeof item.unitPrice === "number"
      && Number.isFinite(item.unitPrice)
      && item.unitPrice >= 0)
    && ["subtotal", "deliveryFee", "grandTotal"].every((key) =>
      typeof value[key] === "number"
      && Number.isFinite(value[key])
      && (value[key] as number) >= 0)
    && PAYMENT_METHODS.includes(String(value.paymentMethod))
    && typeof value.paymentScreenshot === "string"
    && value.paymentScreenshot.length <= 500_000
    && typeof value.notes === "string"
    && value.notes.length <= 2_000;
}

async function readJson(request: Request, limit: number) {
  if (!request.headers.get("content-type")?.includes("application/json")) {
    return { error: "Send a JSON request.", status: 415 };
  }

  const contentLength = Number(request.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > limit) {
    return { error: "Request is too large.", status: 413 };
  }

  const body = await request.text();
  if (new TextEncoder().encode(body).byteLength > limit) {
    return { error: "Request is too large.", status: 413 };
  }

  try {
    return { payload: JSON.parse(body) as unknown };
  } catch {
    return { error: "Invalid JSON request.", status: 400 };
  }
}

function getSupabaseConfig() {
  const projectUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!projectUrl || !serviceKey) return null;

  try {
    const url = new URL(projectUrl);
    if (url.protocol !== "https:" && url.hostname !== "localhost") return null;
    return {
      ordersUrl: `${url.origin}/rest/v1/orders`,
      serviceKey,
    };
  } catch {
    return null;
  }
}

function supabaseHeaders(serviceKey: string, extra: HeadersInit = {}) {
  return {
    apikey: serviceKey,
    Authorization: `Bearer ${serviceKey}`,
    "Content-Type": "application/json",
    ...extra,
  };
}

function adminError(request: Request) {
  const config = getAdminAuthConfig();
  if (!config) {
    return jsonResponse({
      error: "Admin sign-in is not configured. Set ADMIN_PASSWORD and ADMIN_SESSION_SECRET.",
    }, 503);
  }
  if (!hasValidAdminSession(request, config.secret)) {
    return jsonResponse({ error: "Admin sign-in required." }, 401);
  }
  return null;
}

export async function GET(request: Request) {
  const authError = adminError(request);
  if (authError) return authError;

  const config = getSupabaseConfig();
  if (!config) {
    return jsonResponse({
      error: "Order storage is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.",
    }, 503);
  }

  try {
    const response = await fetch(
      `${config.ordersUrl}?select=id,created_at,status,order_data&order=created_at.desc&limit=100`,
      {
        headers: supabaseHeaders(config.serviceKey),
        cache: "no-store",
      },
    );
    if (!response.ok) {
      console.error("Supabase order listing failed with status", response.status);
      return jsonResponse({ error: "Orders could not be loaded from storage." }, 502);
    }

    const rows: unknown = await response.json();
    if (!Array.isArray(rows)) {
      console.error("Supabase returned an invalid order list.");
      return jsonResponse({ error: "Order storage returned an invalid response." }, 502);
    }

    const orders = rows.flatMap((row) => {
      if (!isRecord(row) || !isRecord(row.order_data) || typeof row.status !== "string") {
        return [];
      }
      return [{ ...row.order_data, status: row.status }];
    });
    return jsonResponse({ orders });
  } catch (error) {
    console.error("Supabase order listing request failed:", error);
    return jsonResponse({ error: "Order storage could not be reached." }, 502);
  }
}

export async function POST(request: Request) {
  const parsed = await readJson(request, ORDER_BODY_LIMIT);
  if ("error" in parsed) return jsonResponse({ error: parsed.error }, parsed.status);
  const order = isRecord(parsed.payload) ? parsed.payload.order : null;
  if (!isOrderRecord(order)) {
    return jsonResponse({ error: "The order details are invalid. Please check them and try again." }, 400);
  }

  const config = getSupabaseConfig();
  if (!config) {
    return jsonResponse({
      error: "Order submission is temporarily unavailable. Please contact the restaurant.",
    }, 503);
  }

  try {
    const response = await fetch(config.ordersUrl, {
      method: "POST",
      headers: supabaseHeaders(config.serviceKey, { Prefer: "return=minimal" }),
      body: JSON.stringify({
        id: order.id,
        created_at: order.createdAt,
        status: order.status,
        order_data: order,
      }),
    });
    if (!response.ok) {
      console.error("Supabase order creation failed with status", response.status);
      return jsonResponse({
        error: "We could not submit your order. Please try again or contact the restaurant.",
      }, 502);
    }

    return jsonResponse({ accepted: true }, 201);
  } catch (error) {
    console.error("Supabase order submission request failed:", error);
    return jsonResponse({
      error: "We could not reach order storage. Please try again or contact the restaurant.",
    }, 502);
  }
}

export async function PATCH(request: Request) {
  const authError = adminError(request);
  if (authError) return authError;

  const parsed = await readJson(request, 4096);
  if ("error" in parsed) return jsonResponse({ error: parsed.error }, parsed.status);
  if (!isRecord(parsed.payload)
    || typeof parsed.payload.id !== "string"
    || !parsed.payload.id
    || parsed.payload.id.length > 80
    || typeof parsed.payload.status !== "string"
    || !ORDER_STATUSES.includes(parsed.payload.status)) {
    return jsonResponse({ error: "The order status update is invalid." }, 400);
  }

  const config = getSupabaseConfig();
  if (!config) {
    return jsonResponse({
      error: "Order storage is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.",
    }, 503);
  }

  try {
    const url = new URL(config.ordersUrl);
    url.searchParams.set("id", `eq.${parsed.payload.id}`);
    const response = await fetch(url, {
      method: "PATCH",
      headers: supabaseHeaders(config.serviceKey, { Prefer: "return=representation" }),
      body: JSON.stringify({ status: parsed.payload.status }),
    });
    if (!response.ok) {
      console.error("Supabase order status update failed with status", response.status);
      return jsonResponse({ error: "The order status could not be updated." }, 502);
    }

    const rows: unknown = await response.json();
    if (!Array.isArray(rows) || rows.length === 0) {
      return jsonResponse({ error: "Order not found." }, 404);
    }

    return jsonResponse({ updated: true });
  } catch (error) {
    console.error("Supabase order status request failed:", error);
    return jsonResponse({ error: "Order storage could not be reached." }, 502);
  }
}

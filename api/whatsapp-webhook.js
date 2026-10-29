const crypto = require("crypto");

const PIXEL_ID = "1734115240991081";
const META_API_VERSION = "v25.0";

async function readRawBody(req) {
  const chunks = [];

  for await (const chunk of req) {
    chunks.push(
      Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    );
  }

  return Buffer.concat(chunks);
}

function verifySignature(rawBody, signature, secret) {
  if (!signature || !secret) return false;

  const expected = Buffer.from(
    "sha256=" +
      crypto
        .createHmac("sha256", secret)
        .update(rawBody)
        .digest("hex")
  );

  const received = Buffer.from(signature);

  return (
    received.length === expected.length &&
    crypto.timingSafeEqual(received, expected)
  );
}

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex");
}

async function sendContactToMeta(payload, deliveryId) {
  const token = process.env.META_CAPI_TOKEN;

  if (!token) {
    throw new Error("Missing META_CAPI_TOKEN");
  }

  const data = payload.data || {};
  const phone = String(data.from || "").replace(/\D/g, "");
  const userId = String(data.user_id || "").trim().toLowerCase();
  const messageId = String(data.message_id || "").trim();

  if (!phone && !userId) {
    throw new Error("No matching user identifier");
  }

  const userData = {};

  if (phone) {
    userData.ph = [sha256(phone)];
  }

  if (userId) {
    userData.external_id = [sha256(userId)];
  }

  const timestamp = Number(data.timestamp);

  const eventTime =
    Number.isFinite(timestamp) && timestamp > 0
      ? Math.floor(timestamp)
      : Math.floor(Date.now() / 1000);

  const event = {
    event_name: "Contact",
    event_time: eventTime,
    action_source: "chat",
    messaging_channel: "whatsapp",
    user_data: userData
  };

  // Reutilizar el mismo ID en reintentos ayuda a identificar
  // el mismo mensaje. No reemplaza una deduplicación persistente.
  if (messageId || deliveryId) {
    event.event_id = messageId || deliveryId;
  }

  const url =
    `https://graph.facebook.com/${META_API_VERSION}/${PIXEL_ID}/events` +
    `?access_token=${encodeURIComponent(token)}`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      data: [event]
    })
  });

  const result = await response.json();

  if (!response.ok || result.error) {
    const metaError = result.error || {};

    console.error("Meta CAPI rejected Contact", {
      status: response.status,
      code: metaError.code || null,
      subcode: metaError.error_subcode || null,
      type: metaError.type || null,
      message: metaError.message || null,
      details: metaError.error_data?.details || null,
      trace: metaError.fbtrace_id || null
    });

    throw new Error("Meta CAPI request failed");
  }

  console.log("Meta Contact accepted", {
    eventsReceived: result.events_received,
    eventId: event.event_id || null
  });

  return result;
}

async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");

    return res.status(405).json({
      ok: false,
      error: "Method not allowed"
    });
  }

  const secret = process.env.ZAPCLAW_WEBHOOK_SECRET;

  if (!secret) {
    console.error("Missing webhook secret");

    return res.status(500).json({
      ok: false,
      error: "Webhook secret not configured"
    });
  }

  try {
    const rawBody = await readRawBody(req);
    const signature = req.headers["x-zapclaw-signature"];

    if (!verifySignature(rawBody, signature, secret)) {
      console.error("Invalid ZapClaw webhook signature");

      return res.status(401).json({
        ok: false,
        error: "Invalid webhook signature"
      });
    }

    const payload = JSON.parse(rawBody.toString("utf8"));

    const eventType =
      req.headers["x-zapclaw-event"] || payload.event;

    if (eventType !== "message.received") {
      return res.status(200).json({
        ok: true,
        ignored: true,
        event: eventType || "unknown"
      });
    }

    const deliveryId =
      req.headers["x-zapclaw-delivery"] || null;

    await sendContactToMeta(payload, deliveryId);

    return res.status(200).json({
      ok: true,
      event: "Contact",
      received: true,
      sentToMeta: true
    });
  } catch (error) {
    console.error("Webhook processing failed", {
      message: error.message
    });

    return res.status(502).json({
      ok: false,
      error: "Message processing failed"
    });
  }
}

module.exports = handler;

module.exports.config = {
  api: {
    bodyParser: false
  }
};

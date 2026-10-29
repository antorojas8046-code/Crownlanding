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

async function sendContactToMeta(payload) {
  const token = process.env.META_CAPI_TOKEN;

  if (!token) {
    throw new Error("Missing META_CAPI_TOKEN");
  }

  const data = payload.data || {};
  const textBody = String(data.text?.body || "");

  // Solo contabilizar el mensaje inicial que lleva la referencia
  // generada por la landing.
  const match = textBody.match(/\bRef:\s*([A-Z0-9]{8,32})\b/i);

  if (!match) {
    return {
      sent: false,
      reason: "No landing reference"
    };
  }

  const reference = match[1].toUpperCase();
  const messageId = String(data.message_id || "").trim();

  // Sin un ID de mensaje no enviamos el evento, para evitar
  // conversiones que no podamos identificar correctamente.
  if (!messageId) {
    throw new Error("Missing WhatsApp message_id");
  }

  const phone = String(data.from || "").replace(/\D/g, "");
  const userId = String(data.user_id || "").trim().toLowerCase();

  const userData = {};

  if (phone) {
    userData.ph = [sha256(phone)];
  }

  if (userId) {
    userData.external_id = [sha256(userId)];
  }

  if (!phone && !userId) {
    throw new Error("Missing user identifier");
  }

  const timestamp = Number(data.timestamp);

  const eventTime =
    Number.isFinite(timestamp) && timestamp > 0
      ? Math.floor(timestamp)
      : Math.floor(Date.now() / 1000);

  const event = {
    event_name: "Contact",
    event_time: eventTime,
    event_id: messageId,
    action_source: "chat",
    user_data: userData,
    custom_data: {
      landing_reference: reference
    }
  };

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
    eventId: messageId,
    reference: reference
  });

  return {
    sent: true,
    eventsReceived: result.events_received
  };
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
        reason: "Not an incoming message"
      });
    }

    const result = await sendContactToMeta(payload);

    return res.status(200).json({
      ok: true,
      event: result.sent ? "Contact" : null,
      received: true,
      sentToMeta: result.sent,
      reason: result.reason || null
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

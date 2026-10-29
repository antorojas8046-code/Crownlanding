const crypto = require("crypto");

module.exports.config = {
  api: {
    bodyParser: false
  }
};

async function readRawBody(req) {
  const chunks = [];

  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  return Buffer.concat(chunks);
}

function verifySignature(rawBody, signature, secret) {
  if (!signature || !secret) return false;

  const expected = Buffer.from(
    "sha256=" +
    crypto.createHmac("sha256", secret)
      .update(rawBody)
      .digest("hex")
  );

  const received = Buffer.from(signature);

  return received.length === expected.length &&
    crypto.timingSafeEqual(received, expected);
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({
      ok: false,
      error: "Method not allowed"
    });
  }

  const secret = process.env.ZAPCLAW_WEBHOOK_SECRET;

  if (!secret) {
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
    const eventType = req.headers["x-zapclaw-event"] || payload.event;

    if (eventType === "message.received") {
      // Mensaje entrante verificado.
      // No guardamos el texto ni el teléfono del cliente.
      console.log("WhatsAppMessageReceived", {
        event: eventType,
        deliveryId: req.headers["x-zapclaw-delivery"] || null,
        timestamp: payload.timestamp || null,
        received: true
      });

      return res.status(200).json({
        ok: true,
        event: "WhatsAppMessageReceived",
        received: true
      });
    }

    // Otros eventos de ZapClaw: reconocidos, pero no contados
    // como mensajes entrantes.
    return res.status(200).json({
      ok: true,
      ignored: true,
      event: eventType || "unknown"
    });

  } catch (error) {
    console.error("Webhook processing error");

    return res.status(400).json({
      ok: false,
      error: "Invalid webhook request"
    });
  }
};

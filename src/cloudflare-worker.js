// src/cloudflare-worker.js

export default {
  async fetch(request, env, ctx) {
    // 1. Only accept POST requests
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // 2. Read the raw request body (signature verification must use the raw bytes)
    const rawBody = await request.text();
    const signatureHeader = request.headers.get("webhook-signature");

    // 3. Verify the OpenAI webhook signature
    if (env.OPENAI_WEBHOOK_SECRET && signatureHeader) {
      const isValid = await verifySignature(
        env.OPENAI_WEBHOOK_SECRET,
        signatureHeader,
        rawBody
      );
      if (!isValid) {
        console.error("Invalid webhook signature");
        return new Response("Unauthorized", { status: 401 });
      }
    } else if (env.OPENAI_WEBHOOK_SECRET && !signatureHeader) {
      // Secret is configured but the request has no signature header — reject
      return new Response("Missing signature", { status: 401 });
    } else {
      // No secret configured — skip verification (only recommended for testing)
      console.warn("Webhook signature verification skipped: no secret configured");
    }

    // 4. Parse the JSON payload
    let event;
    try {
      event = JSON.parse(rawBody);
    } catch (err) {
      return new Response("Invalid JSON", { status: 400 });
    }

    // 5. Return 200 immediately so OpenAI knows we received it.
    //    The notification is sent in the background (does not block the response).
    ctx.waitUntil(handleEvent(event, env));

    return new Response(JSON.stringify({ received: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  },
};


// ========== Signature Verification ==========

async function verifySignature(secret, signatureHeader, rawBody) {
  try {
    // OpenAI's signature is usually "sha256=<hex>" or a bare hex string
    const providedSignature = signatureHeader.startsWith("sha256=")
      ? signatureHeader.slice(7)
      : signatureHeader;

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    // Decode the hex signature into a byte array
    const signatureBytes = hexToBytes(providedSignature);
    if (!signatureBytes) return false;

    // crypto.subtle.verify uses constant-time comparison internally,
    // which protects against timing attacks
    return await crypto.subtle.verify(
      "HMAC",
      key,
      signatureBytes,
      encoder.encode(rawBody)
    );
  } catch (err) {
    console.error("Signature verification error:", err);
    return false;
  }
}

function hexToBytes(hex) {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}


// ========== Event Handling and Notification ==========

async function handleEvent(event, env) {
  const eventType = event.type ?? "unknown";
  const batchData = event.data ?? {};
  const status = eventType.replace("batch.", ""); // completed / failed / canceled / expired

  // Skip statuses we don't care about
  const validStatuses = new Set(["completed", "failed", "canceled", "expired"]);
  if (!validStatuses.has(status)) return;

  const notification = buildNotification(status, batchData);

  // Send to ntfy (via the JSON publish protocol, all fields in the body)
  if (env.NTFY_TOPIC) {
    try {
      await fetch("https://ntfy.sh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          topic: env.NTFY_TOPIC,
          title: notification.title,
          message: notification.message,
          priority: notification.priority,
          tags: notification.tags,
          click: notification.clickUrl || undefined,
        }),
      });
    } catch (err) {
      console.error("Failed to send ntfy notification:", err);
      // Notification failure should not affect the response already sent to OpenAI
    }
  } else {
    console.warn("NTFY_TOPIC not configured; notification skipped");
  }
}


function buildNotification(status, data) {
  const statusEmoji = {
    completed: "✅",
    failed: "❌",
    canceled: "🚫",
    expired: "⏳",
  }[status] || "ℹ️";

  const priority = status === "failed" ? "high" : "default";

  // Extract metadata
  const batchId = data.id ?? "Unknown ID";
  const counts = data.request_counts ?? {};
  const total = counts.total ?? 0;
  const completed = counts.completed ?? 0;
  const failed = counts.failed ?? 0;
  const errorCount = data.errors?.data?.length ?? 0;
  const metadata = data.metadata ?? {};
  const outputFileId = data.output_file_id ?? null;
  const errorFileId = data.error_file_id ?? null;
  const createdAt = formatTs(data.created_at);
  const finishedAt = formatTs(
    data.completed_at || data.failed_at || data.expired_at || null
  );

  // Build the message body
  const lines = [
    `${statusEmoji} OpenAI Batch ${status.toUpperCase()}`,
    `ID: ${batchId}`,
    `Requests: ${completed}/${total} completed, ${failed} failed`,
    `Created: ${createdAt}`,
  ];

  if (finishedAt !== "N/A") lines.push(`Finished: ${finishedAt}`);
  if (errorCount > 0) lines.push(`Errors: ${errorCount}`);
  if (Object.keys(metadata).length > 0) {
    lines.push(`Metadata: ${JSON.stringify(metadata)}`);
  }
  if (outputFileId) lines.push(`Output File: ${outputFileId}`);
  if (errorFileId) lines.push(`Error File: ${errorFileId}`);

  // Click action: if an output file exists, tapping the notification jumps to the download URL
  const clickUrl = outputFileId
    ? `https://api.openai.com/v1/files/${outputFileId}/content`
    : null;

  // ntfy tags (used for icons/categorization)
  const tags = ["openai", "robot_face"];
  if (status === "completed") tags.push("white_check_mark");
  if (status === "failed") tags.push("x");
  if (status === "canceled") tags.push("no_entry_sign");
  if (status === "expired") tags.push("hourglass");

  return {
    title: `OpenAI Batch ${status.toUpperCase()}`,
    message: lines.join("\n"),
    priority,
    tags,
    clickUrl,
  };
}

function formatTs(unixSeconds) {
  if (!unixSeconds) return "N/A";
  return new Date(unixSeconds * 1000).toISOString();
}

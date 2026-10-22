// src/cloudflare-worker.js

export default {
  async fetch(request, env, ctx) {
    // 1. Only accept POST requests
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // 2. Read the raw request body (signature verification must use the raw bytes)
    const rawBody = await request.text();

    // 3. Verify the OpenAI webhook signature (Svix scheme: id.timestamp.body)
    if (env.OPENAI_WEBHOOK_SECRET) {
      const isValid = await verifySignature(
        env.OPENAI_WEBHOOK_SECRET,
        request.headers,
        rawBody
      );
      if (!isValid) {
        console.error("Invalid webhook signature");
        return new Response("Unauthorized", { status: 401 });
      }
    } else {
      console.warn("Webhook signature verification skipped: no secret configured");
    }

    // 4. Parse the JSON payload
    let event;
    try {
      event = JSON.parse(rawBody);
    } catch (err) {
      return new Response("Invalid JSON", { status: 400 });
    }

    // 5. Return 200 immediately; send the notification in the background
    ctx.waitUntil(handleEvent(event, env));

    return new Response(JSON.stringify({ received: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  },
};

// ========== Signature Verification ==========

async function verifySignature(secret, headers, rawBody) {
  const id = headers.get("webhook-id") || headers.get("svix-id");
  const timestamp = headers.get("webhook-timestamp") || headers.get("svix-timestamp");
  const signatureHeader = headers.get("webhook-signature") || headers.get("svix-signature");

  if (!id || !timestamp || !signatureHeader) return false;

  // Reject stale timestamps (> 5 minutes) to limit replay
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(timestamp, 10)) > 300) return false;

  // Strip the whsec_ prefix and base64-decode the remainder
  const secretKey = secret.startsWith("whsec_") ? secret.slice(6) : secret;
  const keyBytes = base64ToBytes(secretKey);
  if (!keyBytes) return false;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signedContent = encoder.encode(`${id}.${timestamp}.${rawBody}`);

  // Header may contain multiple space-separated "v1,<base64>" signatures
  for (const candidate of signatureHeader.trim().split(/\s+/)) {
    const parts = candidate.split(",");
    const version = parts.length === 2 ? parts[0] : "v1";
    const signature = parts.length === 2 ? parts[1] : parts[0];
    if (version !== "v1") continue;

    const sigBytes = base64ToBytes(signature);
    if (!sigBytes) continue;

    const valid = await crypto.subtle.verify("HMAC", key, sigBytes, signedContent);
    if (valid) return true;
  }

  return false;
}

function base64ToBytes(b64) {
  try {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

// ========== Event Handling and Notification ==========

async function handleEvent(event, env) {
  const eventType = event.type ?? "unknown";
  const batchData = event.data ?? {};
  const status = eventType.replace("batch.", "");

  const validStatuses = new Set(["completed", "failed", "canceled", "expired"]);
  if (!validStatuses.has(status)) return;

  const notification = buildNotification(status, batchData);

  if (!env.NTFY_TOPIC) {
    console.warn("NTFY_TOPIC not configured; notification skipped");
    return;
  }

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

  const clickUrl = outputFileId
    ? `https://api.openai.com/v1/files/${outputFileId}/content`
    : null;

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

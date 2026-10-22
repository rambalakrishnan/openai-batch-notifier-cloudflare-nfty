// oai-batch-proxy.cjs — run with:
//   OPENAI_API_KEY=sk-... [PROXY_TOKEN=...] node oai-batch-proxy.cjs
const http = require("http");
const https = require("https");
const { Transform } = require("stream");

const PORT                = process.env.PORT || 3000;
const OPENAI_API_KEY      = process.env.OPENAI_API_KEY;
const PROXY_TOKEN         = process.env.PROXY_TOKEN || "";
const MAX_BODY_BYTES      = parseInt(process.env.MAX_BODY_BYTES || String(250 * 1024 * 1024), 10);
const UPSTREAM_TIMEOUT_MS = parseInt(process.env.UPSTREAM_TIMEOUT_MS || "600000", 10);
const REQUEST_TIMEOUT_MS  = parseInt(process.env.REQUEST_TIMEOUT_MS || "900000", 10);

const ALLOWED_METHODS = new Set(["GET", "POST", "DELETE", "HEAD", "OPTIONS"]);
const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection", "expect",
]);

if (!OPENAI_API_KEY) {
  console.error("Set OPENAI_API_KEY.");
  process.exit(1);
}

const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64 });

function sendJson(res, status, obj) {
  if (res.headersSent) return res.destroy();
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

function sanitizeRequestHeaders(req) {
  const out = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP.has(key)) continue;
    if (key === "host" || key === "origin" || key === "referer") continue;
    if (key === "x-proxy-token") continue;
    if (key === "authorization") continue; // never forward the client's
    out[key] = v;
  }
  out["authorization"] = `Bearer ${OPENAI_API_KEY}`;
  return out;
}

function sanitizeResponseHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (HOP_BY_HOP.has(k.toLowerCase())) continue;
    out[k] = v;
  }
  return out;
}

class BodyLimit extends Transform {
  constructor(limit, onLimit) {
    super();
    this.bytes = 0;
    this.limit = limit;
    this.onLimit = onLimit;
  }
  _transform(chunk, enc, cb) {
    this.bytes += chunk.length;
    if (this.bytes > this.limit) {
      this.onLimit();
      cb(new Error("Request body exceeds limit"));
      return;
    }
    cb(null, chunk);
  }
}

const server = http.createServer((req, res) => {
  const start = Date.now();

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, HEAD, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Proxy-Token");
  res.setHeader("Access-Control-Expose-Headers", "x-request-id");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // Health probe — no upstream request, no token required.
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (PROXY_TOKEN && req.headers["x-proxy-token"] !== PROXY_TOKEN) {
    return sendJson(res, 401, { error: { message: "Proxy token required or invalid." } });
  }

  if (!ALLOWED_METHODS.has(req.method)) {
    return sendJson(res, 405, { error: { message: `Method ${req.method} not allowed.` } });
  }

  let target;
  try {
    target = new URL(req.url, "http://localhost");
  } catch {
    return sendJson(res, 400, { error: { message: "Invalid request URL." } });
  }
  const pathname = target.pathname;
  if (!pathname.startsWith("/v1/") || pathname.includes("..") || pathname.includes("//")) {
    return sendJson(res, 404, { error: { message: "Only /v1/* paths are proxied." } });
  }

  const declaredLength = parseInt(req.headers["content-length"], 10);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
    return sendJson(res, 413, { error: { message: "Request body exceeds limit." } });
  }

  const proxyReq = https.request({
    hostname: "api.openai.com",
    port: 443,
    path: pathname + target.search,
    method: req.method,
    headers: sanitizeRequestHeaders(req),
    agent: httpsAgent,
  }, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, sanitizeResponseHeaders(proxyRes.headers));

    proxyRes.on("error", (err) => {
      console.error("Upstream response error:", err.message);
      if (!res.headersSent) sendJson(res, 502, { error: { message: "Upstream response error." } });
      else res.destroy();
    });

    proxyRes.pipe(res);

    const requestId = proxyRes.headers["x-request-id"] || null;
    res.on("finish", () => {
      console.log(JSON.stringify({
        ts: new Date().toISOString(),
        method: req.method,
        path: pathname,
        status: proxyRes.statusCode,
        ms: Date.now() - start,
        requestId,
      }));
    });
  });

  proxyReq.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
    proxyReq.destroy(new Error("Upstream timeout"));
  });

  proxyReq.on("error", (err) => {
    const isTimeout = err.message === "Upstream timeout";
    console.error("Proxy error:", err.message);
    if (!res.headersSent) {
      sendJson(res, isTimeout ? 504 : 502, {
        error: { message: isTimeout ? "Upstream timeout." : "Upstream error: " + err.message },
      });
    } else {
      res.destroy();
    }
  });

  // Client disconnect → tear down the upstream request.
  res.on("close", () => {
    if (!res.writableFinished) proxyReq.destroy();
  });
  req.on("error", (err) => proxyReq.destroy(err));

  if (req.method === "GET" || req.method === "HEAD") {
    proxyReq.end();
  } else {
    const limiter = new BodyLimit(MAX_BODY_BYTES, () => {
      if (!res.headersSent) {
        sendJson(res, 413, { error: { message: "Request body exceeds limit." } });
      }
      proxyReq.destroy();
    });
    limiter.on("error", (err) => proxyReq.destroy(err));
    req.pipe(limiter).pipe(proxyReq);
  }
});

server.requestTimeout  = REQUEST_TIMEOUT_MS;
server.headersTimeout   = 66_000;
server.keepAliveTimeout = 65_000;

server.on("clientError", (err, socket) => {
  if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
});

server.listen(PORT, () => {
  console.log(`Proxy listening on :${PORT}${PROXY_TOKEN ? " (token required)" : ""}`);
});

function shutdown(signal) {
  console.log(`Received ${signal}, shutting down...`);
  server.close(() => process.exit(0));
  setTimeout(() => {
    if (server.closeAllConnections) server.closeAllConnections();
    process.exit(1);
  }, 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));
process.on("unhandledRejection", (err) => {
  console.error("Unhandled rejection:", err);
  shutdown("unhandledRejection");
});
process.on("uncaughtException", (err) => {
  console.error("Uncaught exception:", err);
  shutdown("uncaughtException");
});

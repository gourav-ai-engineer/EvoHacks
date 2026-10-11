#!/usr/bin/env node
/*
 * Zero-dependency local server: serves the static app and routes /api/plan to
 * the same handler Vercel runs. Lets anyone test AI mode locally:
 *
 *   GEMINI_API_KEY=your-key node server.js
 *   PORT=3000 node server.js
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const handler = require("./api/plan.js");

const ROOT = __dirname;
const PORT = Number(process.env.PORT) || 3000;
const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".md": "text/markdown; charset=utf-8"
};
// Only the files the web app needs are served.
const PUBLIC = new Set(["/index.html", "/app.js", "/styles.css", "/lib/core.js", "/favicon.svg"]);

function adapt(res) {
  res.status = (code) => {
    res.statusCode = code;
    return res;
  };
  res.json = (data) => {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify(data));
    return res;
  };
  return res;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/api/plan") {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 100000) req.destroy();
    });
    req.on("end", () => {
      try {
        req.body = raw ? JSON.parse(raw) : {};
      } catch (error) {
        req.body = {};
      }
      Promise.resolve(handler(req, adapt(res))).catch(() => {
        if (!res.headersSent) adapt(res).status(500).json({ error: "Internal error." });
      });
    });
    return;
  }

  const pathname = url.pathname === "/" ? "/index.html" : url.pathname;
  if (!PUBLIC.has(pathname)) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not found");
    return;
  }
  fs.readFile(path.join(ROOT, pathname), (error, data) => {
    if (error) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not found");
      return;
    }
    res.writeHead(200, { "Content-Type": TYPES[path.extname(pathname)] || "application/octet-stream", "Cache-Control": "no-cache" });
    res.end(data);
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    const ai = process.env.GEMINI_API_KEY ? "Gemini AI planning enabled" : "local rules engine (set GEMINI_API_KEY for AI mode)";
    console.log("RelayProof running at http://localhost:" + PORT + " — " + ai);
  });
}

module.exports = server;

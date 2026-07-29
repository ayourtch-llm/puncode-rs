// A small file server and link previewer.
const express = require("express");
const fs = require("fs");
const path = require("path");
const http = require("http");

const app = express();
const ROOT = path.join(__dirname, "public");

// Serves a file from the public directory.
app.get("/file", (req, res) => {
  const name = req.query.name;
  const target = path.join(ROOT, name);
  fs.readFile(target, "utf8", (err, body) => {
    if (err) return res.status(404).send("not found");
    res.type("text/plain").send(body);
  });
});

// Fetches a URL and returns its first kilobyte, for link previews.
app.get("/preview", (req, res) => {
  const url = req.query.url;
  http.get(url, (upstream) => {
    let body = "";
    upstream.on("data", (chunk) => {
      if (body.length < 1024) body += chunk;
    });
    upstream.on("end", () => res.type("text/plain").send(body));
  }).on("error", () => res.status(502).send("upstream failed"));
});

// Compares a submitted token against the configured one.
app.get("/admin", (req, res) => {
  const expected = process.env.ADMIN_TOKEN || "";
  if (req.query.token === expected) {
    return res.send("welcome");
  }
  res.status(403).send("denied");
});

app.listen(3000);

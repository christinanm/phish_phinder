// Minimal dev server for Outlook add-in files (OWA/CSP safe)
// Usage:
// 1) Install trusted Office dev certs (recommended): npx office-addin-dev-certs install
//    The generated files are discovered automatically from %USERPROFILE%/.office-addin-dev-certs.
//    Alternatively, place key.pem and cert.pem in the project root.
// 2) Run: node server.js (HTTPS on port 3000 if certs are found, otherwise HTTP).
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const express = require('express');
const rateLimit = require('express-rate-limit');

const app = express();
const port = Number(process.env.PORT || 3000);

app.disable('x-powered-by');

// Basic limiter to keep stray requests from hammering the dev server
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Strong, Outlook-friendly CSP (no inline/eval; allow Outlook to frame us)
const csp = [
  "default-src 'self'",
  // allow Office + ASP.NET CDN and eval (needed by MicrosoftAjax)
  "script-src 'self' https://appsforoffice.microsoft.com https://ajax.aspnetcdn.com 'unsafe-eval'",
  "script-src-elem 'self' https://appsforoffice.microsoft.com https://ajax.aspnetcdn.com 'unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",          
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self' https://telemetryservice.firstpartyapps.oaspapps.com",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'self' https://outlook.office.com https://*.office.com https://*.office365.com https://outlook.live.com",
  "frame-src 'self' https://outlook.office.com https://*.office.com https://*.office365.com https://outlook.live.com https://telemetryservice.firstpartyapps.oaspapps.com"
].join('; ');

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', csp);
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    // Tell clients to stick with HTTPS once they see it
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN'); // frame-ancestors is authoritative; this is additive
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

// Serve static files from project root
app.use(express.static(path.join(__dirname), {
  etag: true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.json')) res.setHeader('Content-Type', 'application/json; charset=utf-8');
  }
}));

// Simple index route -> taskpane.html
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'taskpane.html'));
});

// --- HTTPS with Office dev certs -------------------------------------------
// Install once:   npx office-addin-dev-certs install
// Files live at:  %USERPROFILE%\.office-addin-dev-certs  (Windows)
//                 ~/.office-addin-dev-certs               (macOS)
function getOfficeDevCert() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const certDir = path.join(home, '.office-addin-dev-certs');
  const keyPath = path.join(certDir, 'localhost.key');
  const crtPath = path.join(certDir, 'localhost.crt');
  if (fs.existsSync(keyPath) && fs.existsSync(crtPath)) {
    return {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(crtPath),
      // allow HTTP/2 ALPN if desired; not required
    };
  }
  return null;
}

// Fallback: project-local key/cert if provided (key.pem/cert.pem)
function getLocalCert() {
  const keyPath = path.join(__dirname, 'key.pem');
  const crtPath = path.join(__dirname, 'cert.pem');
  if (fs.existsSync(keyPath) && fs.existsSync(crtPath)) {
    return {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(crtPath)
    };
  }
  return null;
}

const officeCert = getOfficeDevCert();
const localCert = getLocalCert();

if (officeCert || localCert) {
  const options = officeCert || localCert;
  https.createServer(options, app).listen(port, () => {
    console.log(`HTTPS server running at https://localhost:${port}`);
    if (!officeCert) {
      console.warn('Using local certs (key.pem/cert.pem). For zero-setup trust, run: npx office-addin-dev-certs install');
    }
    console.log(`CSP: ${csp}`);
  });
} else {
  http.createServer(app).listen(port, () => {
    console.log(`HTTP server running at http://localhost:${port}`);
    console.warn('No HTTPS certs found. For Outlook add-ins, install trusted dev certs:\n  npx office-addin-dev-certs install');
    console.log(`CSP: ${csp}`);
  });
}

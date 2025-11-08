// Minimal dev server for serving the add-in files
// Usage:
// 1) Generate certs (if using HTTPS) and place key.pem and cert.pem in the project root.
//    See README for OpenSSL commands.
// 2) Run: node server.js
//    By default this starts HTTPS on port 3000 if certs are present, otherwise HTTP on port 3000.

const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const express = require('express');

const app = express();
const port = process.env.PORT || 3000;

// Serve static files from project root
app.use(express.static(path.join(__dirname)));

// Simple index route (optional)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'taskpane.html'));
});

const keyPath = path.join(__dirname, 'key.pem');
const certPath = path.join(__dirname, 'cert.pem');

if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
  const options = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath)
  };

  https.createServer(options, app).listen(port, () => {
    console.log(`HTTPS server running at https://localhost:${port}`);
  });
} else {
  http.createServer(app).listen(port, () => {
    console.log(`HTTP server running at http://localhost:${port}`);
    console.log('To enable HTTPS, create key.pem and cert.pem in the project root and restart the server.');
  });
}

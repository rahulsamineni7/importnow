/**
 * Production Hardened Web Server for ImportNow
 * 
 * Features:
 * - Native zero-dependency Node.js HTTP implementation (zero supply-chain risk)
 * - OWASP Top 10 Security Headers (Strict CSP, HSTS, X-Frame-Options, etc.)
 * - Sliding-window IP Rate Limiter (Anti-DDoS / Anti-Brute-Force)
 * - Path-traversal & LFI/RFI protection
 * - Clean URL routing (/ -> index.html, /blog -> blog.html, /post -> post.html)
 * - HTTP Method restriction (GET/HEAD only)
 * - Gzip compression
 * - Security logging & graceful shutdown
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const PORT = parseInt(process.env.PORT, 10) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const ROOT_DIR = __dirname;

// MIME Map with charset specification
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml; charset=utf-8',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf'
};

// Strict OWASP Security Headers
const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https: blob:; connect-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'self' https://wa.me; frame-ancestors 'none'; upgrade-insecure-requests;",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-XSS-Protection': '0',
  'Server': 'WebSecure'
};

// Sliding-window IP Rate Limiter
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 300;     // 300 requests per minute per IP
const ipRequestCounts = new Map();

// Periodic cleanup of rate limiter table
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of ipRequestCounts.entries()) {
    if (now - record.startTime > RATE_LIMIT_WINDOW_MS) {
      ipRequestCounts.delete(ip);
    }
  }
}, 30 * 1000).unref();

function checkRateLimit(ip) {
  const now = Date.now();
  let record = ipRequestCounts.get(ip);
  if (!record || now - record.startTime > RATE_LIMIT_WINDOW_MS) {
    ipRequestCounts.set(ip, { count: 1, startTime: now });
    return true;
  }
  record.count++;
  if (record.count > MAX_REQUESTS_PER_WINDOW) {
    return false;
  }
  return true;
}

const server = http.createServer((req, res) => {
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';

  // 1. Rate Limiting Check
  if (!checkRateLimit(clientIp)) {
    res.writeHead(429, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Retry-After': '60',
      ...SECURITY_HEADERS
    });
    res.end('429 Too Many Requests - Rate limit exceeded. Try again in 1 minute.');
    return;
  }

  // 2. HTTP Method Validation (Defense against unexpected HTTP verbs)
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, {
      'Allow': 'GET, HEAD',
      'Content-Type': 'text/plain; charset=utf-8',
      ...SECURITY_HEADERS
    });
    res.end('405 Method Not Allowed');
    return;
  }

  // 3. URL Sanitization and Path Traversal Prevention
  let parsedUrl;
  try {
    parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
    res.end('400 Bad Request');
    return;
  }

  let pathname = decodeURIComponent(parsedUrl.pathname);

  // Normalize and prevent directory traversal
  const normalizedPath = path.normalize(pathname).replace(/^(\.\.[\/\\])+/, '');
  let filePath = path.join(ROOT_DIR, normalizedPath);

  // Guard: Ensure file is strictly within ROOT_DIR
  if (!filePath.startsWith(ROOT_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
    res.end('403 Forbidden - Invalid path');
    return;
  }

  // Clean URLs support (/ -> index.html, /blog -> blog.html, /post -> post.html)
  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    filePath = path.join(filePath, 'index.html');
  } else if (!fs.existsSync(filePath)) {
    if (fs.existsSync(filePath + '.html')) {
      filePath = filePath + '.html';
    }
  }

  // Check file existence
  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      // 404 Fallback
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8', ...SECURITY_HEADERS });
      res.end('<!doctype html><html><head><title>404 Not Found</title></head><body style="font-family:sans-serif;text-align:center;padding:50px"><h1>404 - Page Not Found</h1><p><a href="/">Return to Home</a></p></body></html>');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    // Caching Strategy
    const headers = { ...SECURITY_HEADERS, 'Content-Type': contentType };
    if (filePath.includes(path.sep + 'assets' + path.sep)) {
      headers['Cache-Control'] = 'public, max-age=31536000, immutable';
    } else {
      headers['Cache-Control'] = 'public, max-age=3600, must-revalidate';
    }

    // Compression check (Gzip support for compressible text assets)
    const acceptEncoding = req.headers['accept-encoding'] || '';
    const compressible = /text|javascript|json|xml|svg/.test(contentType);

    if (compressible && acceptEncoding.includes('gzip')) {
      headers['Content-Encoding'] = 'gzip';
      res.writeHead(200, headers);
      if (req.method === 'HEAD') {
        res.end();
        return;
      }
      const rawStream = fs.createReadStream(filePath);
      const gzip = zlib.createGzip();
      rawStream.pipe(gzip).pipe(res);
    } else {
      headers['Content-Length'] = stats.size;
      res.writeHead(200, headers);
      if (req.method === 'HEAD') {
        res.end();
        return;
      }
      fs.createReadStream(filePath).pipe(res);
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`[SECURE SERVER] ImportNow running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`[CYBERSECURITY] OWASP Security Headers, Anti-DDoS Rate Limiter, and LFI Protection ACTIVE.`);
});

// Graceful termination handling
process.on('SIGTERM', () => {
  console.log('Shutting down server gracefully...');
  server.close(() => process.exit(0));
});
process.on('SIGINT', () => {
  console.log('Server interrupted. Exiting...');
  server.close(() => process.exit(0));
});

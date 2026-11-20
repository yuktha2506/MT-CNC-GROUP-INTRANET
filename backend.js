/**
 * MT CNC-Group Node.js backend.
 * In production, IIS serves frontend.html and proxies /api and /socket.io here.
 * The backend binds to loopback only so port 3000 is not exposed to the network.
 */
const fs = require('fs');
const path = require('path');
const envFile = path.join(__dirname, '.env');
if (typeof process.loadEnvFile === 'function' && fs.existsSync(envFile)) {
  // Node 22 built-in .env loader; no dotenv runtime dependency is needed.
  process.loadEnvFile(envFile);
}

const express = require('express');
const http = require('http');
const cors = require('cors');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const createApiRouter = require('./api');

const required = ['JWT_SECRET'];
const missing = required.filter((key) => !process.env[key]);
if (missing.length) throw new Error('Missing required environment settings: ' + missing.join(', '));
if (process.env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters.');

const production = process.env.NODE_ENV === 'production';
if (process.env.COOKIE_SECURE && !['true', 'false'].includes(process.env.COOKIE_SECURE)) {
  throw new Error('COOKIE_SECURE must be true or false.');
}
if (production && process.env.COOKIE_SECURE !== 'true' && process.env.COOKIE_SECURE !== 'false') {
  throw new Error('Set COOKIE_SECURE explicitly to true for HTTPS or false for the configured HTTP binding.');
}

const app = express();
app.disable('x-powered-by');
// IIS ARR connects to Node from this machine. Trust forwarded protocol/IP only
// from loopback; do not trust arbitrary client-supplied X-Forwarded-* headers.
app.set('trust proxy', 'loopback');
const server = http.createServer(app);
const frontendOrigin = process.env.FRONTEND_ORIGIN;
if (frontendOrigin) app.use(cors({ origin: frontendOrigin, credentials: true }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self' ws: wss:");
  // HSTS is intentionally omitted: the specified public IIS binding is HTTP.
  // Enable it at IIS only after HTTPS is configured.
  next();
});
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});
app.use(express.json({ limit: '1mb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

const io = new Server(server, {
  // Same-origin IIS proxying requires no permissive cross-origin allowance.
  ...(frontendOrigin ? { cors: { origin: frontendOrigin, credentials: true } } : {})
});
app.set('io', io);

io.use(async (socket, next) => {
  try {
    const cookieHeader = socket.handshake.headers.cookie || '';
    const cookie = cookieHeader.split(';').map((part) => part.trim()).find((part) => part.startsWith('mt_session='));
    const cookieToken = cookie ? cookie.slice('mt_session='.length) : '';
    const decoded = jwt.verify(cookieToken, process.env.JWT_SECRET);
    const role = decoded.id === 'static-admin' ? 'admin' : decoded.id === 'static-employee' ? 'employee' : null;
    if (decoded.auth_source !== 'static' || !role || decoded.role !== role) return next(new Error('Authentication required'));
    socket.data.user = { id: decoded.id, role };
    next();
  } catch (_) {
    next(new Error('Authentication required'));
  }
});
io.on('connection', (socket) => {
  socket.join(`user:${socket.data.user.id}`);
  if (socket.data.user.role === 'admin') socket.join('admins');
});

app.use('/api', createApiRouter({ jwtSecret: process.env.JWT_SECRET }));
app.get('/api/health', (req, res) => res.json({
  status: 'online',
  app: 'MT CNC-Group - Microtech CNC Pvt. Ltd.',
  storage: 'in-memory',
  loginIdPolicy: 'configured-account-match'
}));

// These two bundled files are required by the SOP PDF canvas viewer. IIS serves
// them as static files in production; these exact routes support local preview
// without letting the frontend fallback return HTML for a JavaScript module.
for (const assetName of ['pdf.min.js', 'pdf.worker.min.js']) {
  app.get('/' + assetName, (req, res, next) => {
    res.type('application/javascript');
    res.setHeader('Cache-Control', 'no-store');
    res.sendFile(path.join(__dirname, assetName), (err) => { if (err) next(err); });
  });
}

// IIS owns static file delivery in production. This optional local preview is
// retained for development only and is never used on the production server.
const serveFrontend = (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(__dirname, 'frontend.html'), (err) => err && next(err));
};
if (!production && process.env.SERVE_FRONTEND !== 'false') {
  app.get(['/','/frontend.html'], serveFrontend);
  app.use((req, res, next) => {
    if (req.path.startsWith('/api/') || req.path.startsWith('/socket.io/')) {
      return res.status(404).json({ success: false, message: 'Endpoint not found.' });
    }
    return serveFrontend(req, res, next);
  });
} else {
  app.use((req, res) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({ success: false, message: 'API endpoint not found.' });
    return res.status(404).type('text').send('Not found. Frontend files are served by IIS.');
  });
}

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err && err.type === 'entity.too.large') return res.status(413).json({ success: false, message: 'Request is too large.' });
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) return res.status(400).json({ success: false, message: 'Invalid JSON request body.' });
  console.error('Unhandled request error.');
  return res.status(500).json({ success: false, message: 'Internal server error.' });
});

// Production always binds exactly to 127.0.0.1:3000 behind IIS ARR.
const host = production ? '127.0.0.1' : (process.env.HOST || '127.0.0.1');
const port = production ? 3000 : Number(process.env.PORT || 3000);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be a valid TCP port.');

function start() {
  return new Promise((resolve, reject) => {
    const onError = (err) => reject(err);
    server.once('error', onError);
    server.listen(port, host, () => {
      server.removeListener('error', onError);
      console.log(`MT CNC-Group backend listening on ${host}:${port}.`);
      resolve();
    });
  });
}
start().catch((err) => {
  if (err.code === 'EADDRINUSE') console.error(`Backend port ${port} is already in use; stop the other process or configure the deployment.`);
  else console.error('Unable to start MT CNC-Group backend. Check required environment settings and dependencies.');
  process.exitCode = 1;
});

process.on('SIGTERM', () => server.close());
process.on('SIGINT', () => server.close());

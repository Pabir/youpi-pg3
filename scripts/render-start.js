import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runMigrations, getDatabase, ensureDatabaseInitialized } from '@youpi/db';
import { startServer as startPaymentApi } from '../apps/payment-api/src/index.js';
import { startCheckoutServer } from '../apps/checkout-portal/src/index.js';
import { startAdminServer } from '../apps/merchant-admin/src/index.js';
import { startCoinWalletStore } from '../apps/coin-wallet-store/src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

// Ensure production/cloud environment defaults
process.env.NODE_ENV = process.env.NODE_ENV || 'production';
process.env.YOUPI_BIND_HOST = '127.0.0.1'; // Internal services bind to local loopback

// Forwarding helper that proxies HTTP requests to internal ports
function proxyRequest(req, res, targetPort) {
  const options = {
    hostname: '127.0.0.1',
    port: targetPort,
    path: req.url,
    method: req.method,
    headers: {
      ...req.headers,
      host: `localhost:${targetPort}`,
      'x-forwarded-host': req.headers.host || '',
      'x-forwarded-proto': req.headers['x-forwarded-proto'] || 'https'
    }
  };

  const proxy = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxy.on('error', (err) => {
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Service Unavailable', details: err.message }));
    }
  });

  req.pipe(proxy);
}

async function main() {
  console.log('====================================================');
  console.log('🚀 Starting YOUPI PG — Render Cloud Gateway');
  console.log('====================================================');

  // 1. Initialize Database
  console.log('[1/4] Running database migrations & seeds...');
  const db = getDatabase();
  ensureDatabaseInitialized(db);
  const migrationResult = runMigrations(db);
  console.log(`[✓] Database ready. Merchant: ${migrationResult?.defaultMerchant?.businessName || 'Default'}`);

  // 2. Ports for internal background microservices
  const API_PORT = 6100;
  const CHECKOUT_PORT = 7000;
  const ADMIN_PORT = 6001;
  const STORE_PORT = 5000;
  const PUBLIC_PORT = Number(process.env.PORT || 10000);

  // 3. Start internal services
  console.log('[2/4] Starting internal gateway services on 127.0.0.1...');
  await startPaymentApi(API_PORT);
  await startCheckoutServer(CHECKOUT_PORT);
  await startAdminServer(ADMIN_PORT);
  try {
    await startCoinWalletStore(STORE_PORT);
  } catch (err) {
    console.warn('[!] Demo store skipped:', err.message);
  }

  // 4. Create unified front router for Render (binds to 0.0.0.0:PORT)
  console.log(`[3/4] Launching unified reverse-proxy on port ${PUBLIC_PORT}...`);
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    // Liveness / Health check (Render monitors this)
    if (pathname === '/health' || pathname === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'UP',
        service: 'youpi-render-gateway',
        timestamp: new Date().toISOString()
      }));
      return;
    }

    // Checkout portal routes: /checkout/:id, /youpi.js, /sdk/*, /icons/*
    if (
      pathname === '/youpi.js' ||
      pathname.startsWith('/sdk/') ||
      pathname.startsWith('/checkout') ||
      pathname.startsWith('/icons/')
    ) {
      return proxyRequest(req, res, CHECKOUT_PORT);
    }

    // Payment Core REST API: /api/*
    if (pathname.startsWith('/api/')) {
      return proxyRequest(req, res, API_PORT);
    }

    // APK download for Android banking observer
    if (pathname === '/youpi-sms-gateway.apk' || pathname === '/download/apk') {
      return proxyRequest(req, res, ADMIN_PORT);
    }

    // Demo store: /store or /store/*
    if (pathname === '/store' || pathname.startsWith('/store/')) {
      return proxyRequest(req, res, STORE_PORT);
    }

    // Merchant Admin panel: /admin, /admin/* or root /
    if (pathname === '/' || pathname === '/admin' || pathname.startsWith('/admin/')) {
      return proxyRequest(req, res, ADMIN_PORT);
    }

    // Default 404
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });

  server.listen(PUBLIC_PORT, '0.0.0.0', () => {
    console.log('====================================================');
    console.log(`🟢 YOUPI PG GATEWAY ONLINE ON RENDER (PORT ${PUBLIC_PORT})`);
    console.log('====================================================');
    console.log(`• Merchant Admin Hub:   http://0.0.0.0:${PUBLIC_PORT}/admin`);
    console.log(`• Checkout Portal:      http://0.0.0.0:${PUBLIC_PORT}/checkout/:id`);
    console.log(`• JS SDK Script:        http://0.0.0.0:${PUBLIC_PORT}/youpi.js`);
    console.log(`• Payment Core API:     http://0.0.0.0:${PUBLIC_PORT}/api/v1/payments`);
    console.log(`• Demo Store:           http://0.0.0.0:${PUBLIC_PORT}/store`);
    console.log(`• Health Check:         http://0.0.0.0:${PUBLIC_PORT}/health`);
    console.log('====================================================');
  });
}

main().catch((err) => {
  console.error('Fatal startup error on Render:', err);
  process.exit(1);
});

/**
 * EFSF + Express Integration Example
 *
 * Demonstrates how to integrate EFSF with an Express web application
 * for ephemeral session management with compliance-ready destruction
 * certificates.
 *
 * Run with: npx ts-node examples/express-example.ts
 * Then test with:
 *   curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"username":"admin","password":"secret"}'
 *   curl -X GET http://localhost:3000/me -H "Authorization: Bearer <session_id>"
 *   curl -X POST http://localhost:3000/logout -H "Authorization: Bearer <session_id>"
 */

// Note: This example requires express to be installed:
// npm install express @types/express

import express, { Request, Response, NextFunction } from 'express';
import {
  EphemeralStore,
  DataClassification,
  sealed,
  RecordNotFoundError,
  RecordExpiredError,
} from '../src/index.js';

// ============================================================
// Configuration
// ============================================================

const SESSION_TTL = '30m';
const PORT = process.env.PORT || 3000;

// Use memory backend for demo; use redis:// in production
const STORE_BACKEND = process.env.REDIS_URL || 'memory://';

// ============================================================
// Initialize Store
// ============================================================

const store = new EphemeralStore({
  backend: STORE_BACKEND,
  defaultTTL: SESSION_TTL,
  attestation: true,
});

// ============================================================
// Express App
// ============================================================

const app = express();
app.use(express.json());

// ============================================================
// Session Interface
// ============================================================

interface Session {
  session_id: string;
  user_id: string;
  username: string;
  roles: string[];
  created_at: string;
}

// ============================================================
// Authentication Middleware
// ============================================================

async function authenticate(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No session token provided' });
  }

  const sessionId = authHeader.replace('Bearer ', '');

  try {
    const sessionData = await store.get(sessionId);
    (req as any).session = { session_id: sessionId, ...sessionData } as Session;
    next();
  } catch (error) {
    if (error instanceof RecordNotFoundError || error instanceof RecordExpiredError) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }
    return res.status(500).json({ error: 'Internal server error' });
  }
}

// ============================================================
// Routes
// ============================================================

/**
 * POST /login
 * Create a new ephemeral session
 */
app.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body;

  // Simplified authentication (use proper auth in production!)
  if (username !== 'admin' || password !== 'secret') {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Create ephemeral session
  const sessionData = {
    user_id: 'user_001',
    username,
    created_at: new Date().toISOString(),
    roles: ['user', 'admin'],
  };

  const record = await store.put(sessionData, {
    ttl: SESSION_TTL,
    classification: DataClassification.TRANSIENT,
    metadata: {
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
    },
  });

  res.json({
    session_id: record.id,
    expires_at: record.expiresAt.toISOString(),
    ttl_seconds: record.ttl / 1000,
    message: `Welcome, ${username}!`,
  });
});

/**
 * GET /me
 * Get current user info (requires authentication)
 */
app.get('/me', authenticate, (req: Request, res: Response) => {
  const session = (req as any).session as Session;

  res.json({
    user_id: session.user_id,
    username: session.username,
    roles: session.roles,
    session_created_at: session.created_at,
  });
});

/**
 * GET /session/ttl
 * Check remaining session time
 */
app.get('/session/ttl', authenticate, async (req: Request, res: Response) => {
  const session = (req as any).session as Session;
  const ttl = await store.ttl(session.session_id);

  res.json({
    session_id: session.session_id,
    remaining_seconds: ttl ? Math.floor(ttl / 1000) : 0,
    remaining_minutes: ttl ? Math.floor(ttl / 60000) : 0,
  });
});

/**
 * POST /logout
 * Destroy session with destruction certificate
 */
app.post('/logout', authenticate, async (req: Request, res: Response) => {
  const session = (req as any).session as Session;

  const certificate = await store.destroy(session.session_id);

  res.json({
    message: 'Session destroyed',
    destruction_certificate: {
      certificate_id: certificate?.certificateId,
      method: certificate?.destructionMethod,
      timestamp: certificate?.destructionTimestamp.toISOString(),
      verified_by: certificate?.verifiedBy,
    },
  });
});

/**
 * POST /sensitive-operation
 * Example of sealed execution for sensitive operations
 */
app.post('/sensitive-operation', authenticate, async (req: Request, res: Response) => {
  const { credit_card, amount } = req.body;

  // Process in sealed context - data destroyed after processing
  const processCreditCard = sealed({ attestation: true })(
    async (cardNumber: string, chargeAmount: number) => {
      // All local state destroyed on return
      const masked = `****-****-****-${cardNumber.slice(-4)}`;
      return {
        success: true,
        masked_card: masked,
        amount: chargeAmount,
        transaction_id: `txn_${Date.now()}`,
      };
    }
  );

  const result = await processCreditCard(credit_card || '4111111111111111', amount || 100);

  res.json(result);
});

/**
 * GET /admin/stats
 * Admin endpoint for compliance reporting
 */
app.get('/admin/stats', authenticate, async (req: Request, res: Response) => {
  const session = (req as any).session as Session;

  if (!session.roles.includes('admin')) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const stats = store.stats();
  const recentCerts = store.listCertificates().slice(0, 10);

  res.json({
    store_stats: stats,
    recent_destructions: recentCerts.map((cert) => ({
      certificate_id: cert.certificateId,
      resource_id: cert.resource.resourceId,
      resource_type: cert.resource.resourceType,
      method: cert.destructionMethod,
      timestamp: cert.destructionTimestamp.toISOString(),
    })),
  });
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    store: store.stats(),
  });
});

// ============================================================
// Start Server
// ============================================================

app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('EFSF + Express Example Server');
  console.log('='.repeat(60));
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Backend: ${STORE_BACKEND}`);
  console.log(`Session TTL: ${SESSION_TTL}`);
  console.log('');
  console.log('Try these commands:');
  console.log('');
  console.log('  # Login');
  console.log(`  curl -X POST http://localhost:${PORT}/login \\`);
  console.log('    -H "Content-Type: application/json" \\');
  console.log('    -d \'{"username":"admin","password":"secret"}\'');
  console.log('');
  console.log('  # Get user info (replace <session_id>)');
  console.log(`  curl http://localhost:${PORT}/me \\`);
  console.log('    -H "Authorization: Bearer <session_id>"');
  console.log('');
  console.log('  # Check session TTL');
  console.log(`  curl http://localhost:${PORT}/session/ttl \\`);
  console.log('    -H "Authorization: Bearer <session_id>"');
  console.log('');
  console.log('  # Logout (with destruction certificate)');
  console.log(`  curl -X POST http://localhost:${PORT}/logout \\`);
  console.log('    -H "Authorization: Bearer <session_id>"');
  console.log('');
  console.log('  # Admin stats');
  console.log(`  curl http://localhost:${PORT}/admin/stats \\`);
  console.log('    -H "Authorization: Bearer <session_id>"');
  console.log('='.repeat(60));
});

// Cleanup on shutdown
process.on('SIGINT', async () => {
  console.log('\nShutting down...');
  await store.close();
  process.exit(0);
});

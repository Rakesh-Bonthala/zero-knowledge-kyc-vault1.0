import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import path from 'path';
import { fileURLToPath } from 'url';
import { config } from './config/config.js';
import vaultRoutes from './routes/vault.routes.js';
import { errorMiddleware } from './middleware/error.middleware.js';
import { StorageFactory } from './services/storage/storage.factory.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendPath = path.resolve(__dirname, '../frontend');

const app = express();

// Security Headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "blob:"],
        connectSrc: ["'self'", "https://api.pwnedpasswords.com"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: []
      }
    },
    crossOriginResourcePolicy: { policy: 'cross-origin' }
  })
);

// CORS configuration
app.use(
  cors({
    origin: config.corsOrigin === '*' ? true : config.corsOrigin,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Id'],
    exposedHeaders: [
      'X-Doc-Id',
      'X-Original-Filename',
      'X-Mime-Type',
      'X-File-Size',
      'X-Salt',
      'X-IV',
      'X-Iterations',
      'X-AAD',
      'X-Encryption-Algorithm',
      'X-KDF-Algorithm'
    ]
  })
);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve frontend static assets
app.use(express.static(frontendPath));

// API Routes
app.use('/api/vault', vaultRoutes);

// Single-page fallback for frontend
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return next();
  }
  res.sendFile(path.join(frontendPath, 'index.html'));
});

// Error handling
app.use(errorMiddleware);

// Check if this module is being run directly
const isDirectRun = Boolean(
  process.argv[1] &&
  (path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url)) ||
    process.argv[1].endsWith('server.js'))
);

if (isDirectRun && process.env.NODE_ENV !== 'test') {
  const PORT = config.port;
  app.listen(PORT, async () => {
    console.log(`=======================================================`);
    console.log(` 🛡️  ZERO-KNOWLEDGE KYC VAULT SERVER RUNNING`);
    console.log(` 🌐  URL: http://localhost:${PORT}`);
    console.log(` 📦  Configured Storage Provider: ${config.storageProvider}`);
    console.log(` 🔒  Zero-Knowledge Guarantee: Server receives ciphertext only.`);
    console.log(`=======================================================`);

    try {
      await StorageFactory.getAdapter();
      const status = StorageFactory.getStatus();
      console.log(` [Storage Ready] Adapter: ${status.name} (isMock: ${status.isMock})`);
      if (status.fallbackOccurred) {
        console.log(` [Storage Fallback Notice] ${status.fallbackReason}`);
      }
    } catch (e) {
      console.error(` [Storage Init Warning] ${e.message}`);
    }
  });
}

export default app;

import express from 'express';
import multer from 'multer';
import { VaultController } from '../controllers/vault.controller.js';
import { authMiddleware } from '../middleware/auth.middleware.js';
import { config } from '../config/config.js';

const router = express.Router();

// Memory storage for multer: processes encrypted blob directly in memory
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: config.maxFileSizeMB * 1024 * 1024 // e.g. 50 MB
  }
});

// Vault Routes with authentication & ownership isolation
router.get('/status', VaultController.status);
router.post('/upload', authMiddleware, upload.single('encryptedFile'), VaultController.upload);
router.get('/documents', authMiddleware, VaultController.list);
router.get('/download/:id', authMiddleware, VaultController.download);
router.delete('/documents/:id', authMiddleware, VaultController.delete);

export default router;


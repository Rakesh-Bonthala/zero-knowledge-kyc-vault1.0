import { cryptoRandomUUID } from './crypto-uuid.js';
import { StorageFactory } from '../services/storage/storage.factory.js';
import { DocumentRepository } from '../models/document.model.js';

export class VaultController {
  /**
   * Upload an encrypted document and its non-secret metadata.
   * Backend handles exclusively ciphertext and metadata.
   */
  static async upload(req, res, next) {
    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: 'No encrypted file payload provided.'
        });
      }

      // Parse metadata from request body
      let meta = {};
      if (req.body.metadata) {
        try {
          meta = typeof req.body.metadata === 'string' ? JSON.parse(req.body.metadata) : req.body.metadata;
        } catch (e) {
          return res.status(400).json({ success: false, error: 'Malformed metadata JSON.' });
        }
      } else {
        meta = req.body;
      }

      // Validate mandatory cryptographic fields
      const { salt, iv, pbkdf2Iterations, originalFilename, mimeType, fileSize, aad } = meta;
      if (!salt || !iv) {
        return res.status(400).json({
          success: false,
          error: 'Missing required cryptographic parameters (salt, iv).'
        });
      }

      const docId = cryptoRandomUUID();
      const ownerId = req.user.id;
      const ciphertextSizeBytes = req.file.buffer.length;

      // Get storage adapter
      const storageAdapter = await StorageFactory.getAdapter();
      const storageResult = await storageAdapter.store(docId, req.file.buffer, {
        encryptionVersion: meta.encryptionVersion || 'v1.0'
      });

      // Save metadata record
      const docRecord = await DocumentRepository.create({
        docId,
        ownerId,
        originalFilename: originalFilename || 'untitled.bin',
        mimeType: mimeType || 'application/octet-stream',
        fileSize: parseInt(fileSize, 10) || ciphertextSizeBytes,
        ciphertextSizeBytes,
        encryptionAlgorithm: meta.encryptionAlgorithm || 'AES-256-GCM',
        kdfAlgorithm: meta.kdfAlgorithm || 'PBKDF2',
        pbkdf2Iterations: parseInt(pbkdf2Iterations, 10) || 600000,
        salt,
        iv,
        aad: aad || '',
        encryptionVersion: meta.encryptionVersion || 'v1.0',
        storageBackend: storageAdapter.name,
        storageRef: storageResult.storageRef || ''
      });

      res.status(201).json({
        success: true,
        message: 'Encrypted document securely stored.',
        document: {
          docId: docRecord.docId,
          originalFilename: docRecord.originalFilename,
          mimeType: docRecord.mimeType,
          fileSize: docRecord.fileSize,
          ciphertextSizeBytes: docRecord.ciphertextSizeBytes,
          storageBackend: docRecord.storageBackend,
          createdAt: docRecord.createdAt
        }
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * List all documents owned by the authenticated user.
   */
  static async list(req, res, next) {
    try {
      const ownerId = req.user.id;
      const documents = await DocumentRepository.findByOwner(ownerId);

      res.json({
        success: true,
        count: documents.length,
        documents: documents.map(doc => ({
          docId: doc.docId,
          originalFilename: doc.originalFilename,
          mimeType: doc.mimeType,
          fileSize: doc.fileSize,
          ciphertextSizeBytes: doc.ciphertextSizeBytes,
          encryptionAlgorithm: doc.encryptionAlgorithm,
          kdfAlgorithm: doc.kdfAlgorithm,
          pbkdf2Iterations: doc.pbkdf2Iterations,
          storageBackend: doc.storageBackend,
          createdAt: doc.createdAt
        }))
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * Download the encrypted ciphertext and return its decryption metadata.
   */
  static async download(req, res, next) {
    try {
      const { id } = req.params;
      const doc = await DocumentRepository.findById(id);

      if (!doc) {
        return res.status(404).json({
          success: false,
          error: `Document with ID "${id}" was not found.`
        });
      }

      // Enforce ownership
      if (doc.ownerId !== req.user.id) {
        return res.status(403).json({
          success: false,
          error: 'Access denied: You do not own this document.'
        });
      }

      const storageAdapter = await StorageFactory.getAdapter();
      const ciphertextBuffer = await storageAdapter.retrieve(doc.docId);

      // Return metadata in custom headers for client decryption
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${doc.docId}.enc"`);
      res.setHeader('X-Doc-Id', doc.docId);
      res.setHeader('X-Original-Filename', encodeURIComponent(doc.originalFilename));
      res.setHeader('X-Mime-Type', doc.mimeType);
      res.setHeader('X-File-Size', String(doc.fileSize));
      res.setHeader('X-Salt', doc.salt);
      res.setHeader('X-IV', doc.iv);
      res.setHeader('X-Iterations', String(doc.pbkdf2Iterations));
      res.setHeader('X-Encryption-Algorithm', doc.encryptionAlgorithm);
      res.setHeader('X-KDF-Algorithm', doc.kdfAlgorithm);
      if (doc.aad) {
        res.setHeader('X-AAD', encodeURIComponent(doc.aad));
      }
      res.setHeader('Access-Control-Expose-Headers', 'X-Doc-Id, X-Original-Filename, X-Mime-Type, X-File-Size, X-Salt, X-IV, X-Iterations, X-AAD, X-Encryption-Algorithm, X-KDF-Algorithm');

      res.send(ciphertextBuffer);
    } catch (err) {
      next(err);
    }
  }

  /**
   * Delete an encrypted document and its associated metadata.
   */
  static async delete(req, res, next) {
    try {
      const { id } = req.params;
      const doc = await DocumentRepository.findById(id);

      if (!doc) {
        return res.status(404).json({
          success: false,
          error: `Document with ID "${id}" was not found.`
        });
      }

      if (doc.ownerId !== req.user.id) {
        return res.status(403).json({
          success: false,
          error: 'Access denied: You do not own this document.'
        });
      }

      // Delete from storage adapter
      const storageAdapter = await StorageFactory.getAdapter();
      await storageAdapter.delete(doc.docId);

      // Delete from metadata repository
      await DocumentRepository.delete(doc.docId);

      res.json({
        success: true,
        message: `Encrypted document ${id} permanently removed.`
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * Retrieve storage and security status.
   */
  static async status(req, res, next) {
    try {
      // Ensure adapter is probed
      await StorageFactory.getAdapter();
      const status = StorageFactory.getStatus();
      res.json({
        success: true,
        storage: status,
        security: {
          zeroKnowledgeMode: true,
          serverDecryptionEnabled: false,
          maxAllowedUploadMB: 50
        }
      });
    } catch (err) {
      next(err);
    }
  }
}


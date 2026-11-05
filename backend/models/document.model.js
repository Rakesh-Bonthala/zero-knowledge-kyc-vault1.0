import mongoose from 'mongoose';
import fs from 'fs/promises';
import path from 'path';

// Mongoose Schema for MongoDB storage
const documentSchema = new mongoose.Schema(
  {
    docId: { type: String, required: true, unique: true, index: true },
    ownerId: { type: String, required: true, index: true },
    originalFilename: { type: String, required: true },
    mimeType: { type: String, required: true },
    fileSize: { type: Number, required: true },
    ciphertextSizeBytes: { type: Number, required: true },
    encryptionAlgorithm: { type: String, default: 'AES-256-GCM' },
    kdfAlgorithm: { type: String, default: 'PBKDF2' },
    pbkdf2Iterations: { type: Number, default: 600000 },
    salt: { type: String, required: true }, // Base64
    iv: { type: String, required: true },   // Base64
    aad: { type: String, default: '' },     // Base64 or JSON string of AAD
    encryptionVersion: { type: String, default: 'v1.0' },
    storageBackend: { type: String, required: true },
    storageRef: { type: String, default: '' }
  },
  { timestamps: true }
);

let MongoDocumentModel = null;
try {
  MongoDocumentModel = mongoose.model('DocumentMeta', documentSchema);
} catch (e) {
  MongoDocumentModel = mongoose.models.DocumentMeta;
}

/**
 * Unified Document Repository supporting both MongoDB and local mock store.
 */
export class DocumentRepository {
  static localStoreFile = path.resolve(process.cwd(), '.mock_storage', 'metadata.json');
  static localMemoryStore = new Map();

  static isMongoAvailable() {
    return mongoose.connection && mongoose.connection.readyState === 1;
  }

  static async _ensureLocalStore() {
    try {
      await fs.mkdir(path.dirname(this.localStoreFile), { recursive: true });
      try {
        const data = await fs.readFile(this.localStoreFile, 'utf8');
        const parsed = JSON.parse(data);
        this.localMemoryStore = new Map(Object.entries(parsed));
      } catch (err) {
        if (err.code === 'ENOENT') {
          this.localMemoryStore = new Map();
          await this._persistLocalStore();
        }
      }
    } catch (e) {
      // Memory store fallback
    }
  }

  static async _persistLocalStore() {
    try {
      const obj = Object.fromEntries(this.localMemoryStore);
      await fs.writeFile(this.localStoreFile, JSON.stringify(obj, null, 2), 'utf8');
    } catch (e) {
      // Ignore write errors in restricted envs
    }
  }

  static async create(docData) {
    if (this.isMongoAvailable()) {
      const doc = new MongoDocumentModel(docData);
      return await doc.save();
    } else {
      await this._ensureLocalStore();
      const record = {
        ...docData,
        createdAt: new Date(),
        updatedAt: new Date()
      };
      this.localMemoryStore.set(docData.docId, record);
      await this._persistLocalStore();
      return record;
    }
  }

  static async findById(docId) {
    if (this.isMongoAvailable()) {
      return await MongoDocumentModel.findOne({ docId }).lean();
    } else {
      await this._ensureLocalStore();
      return this.localMemoryStore.get(docId) || null;
    }
  }

  static async findByOwner(ownerId) {
    if (this.isMongoAvailable()) {
      return await MongoDocumentModel.find({ ownerId }).sort({ createdAt: -1 }).lean();
    } else {
      await this._ensureLocalStore();
      const docs = Array.from(this.localMemoryStore.values()).filter(d => d.ownerId === ownerId);
      docs.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      return docs;
    }
  }

  static async delete(docId) {
    if (this.isMongoAvailable()) {
      const res = await MongoDocumentModel.deleteOne({ docId });
      return res.deletedCount > 0;
    } else {
      await this._ensureLocalStore();
      const existed = this.localMemoryStore.has(docId);
      this.localMemoryStore.delete(docId);
      await this._persistLocalStore();
      return existed;
    }
  }
}


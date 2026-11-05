import mongoose from 'mongoose';
import { GridFSBucket } from 'mongodb';
import { Readable } from 'stream';
import { StorageAdapter } from './storage.interface.js';

export class GridFSStorageAdapter extends StorageAdapter {
  constructor(mongoUri, bucketName = 'encrypted_documents', options = {}) {
    super('MongoDB GridFS');
    this.mongoUri = mongoUri;
    this.bucketName = bucketName;
    this.options = options;
    this.bucket = null;
    this.ready = false;
  }

  async init() {
    try {
      if (mongoose.connection.readyState !== 1) {
        await mongoose.connect(this.mongoUri, {
          ...this.options
        });
      }
      const db = mongoose.connection.db;
      this.bucket = new GridFSBucket(db, { bucketName: this.bucketName });
      this.ready = true;
      return true;
    } catch (err) {
      this.ready = false;
      throw new Error(`MongoDB GridFS connection failed: ${err.message}`);
    }
  }

  async store(docId, buffer, metadata = {}) {
    if (!this.ready || !this.bucket) {
      await this.init();
    }

    return new Promise((resolve, reject) => {
      const uploadStream = this.bucket.openUploadStream(docId, {
        metadata: {
          docId,
          encryptionFormat: metadata.encryptionVersion || 'v1.0',
          uploadedAt: new Date()
        }
      });

      const readableStream = new Readable();
      readableStream.push(buffer);
      readableStream.push(null);

      readableStream
        .pipe(uploadStream)
        .on('error', (err) => reject(new Error(`GridFS upload failed: ${err.message}`)))
        .on('finish', () => {
          resolve({
            storageRef: uploadStream.id.toString(),
            storedAt: new Date()
          });
        });
    });
  }

  async retrieve(docId) {
    if (!this.ready || !this.bucket) {
      await this.init();
    }

    // Find file metadata first
    const files = await this.bucket.find({ filename: docId }).toArray();
    if (!files || files.length === 0) {
      const notFound = new Error(`Encrypted file for document ${docId} not found in GridFS.`);
      notFound.statusCode = 404;
      throw notFound;
    }

    return new Promise((resolve, reject) => {
      const downloadStream = this.bucket.openDownloadStreamByName(docId);
      const chunks = [];

      downloadStream.on('data', (chunk) => chunks.push(chunk));
      downloadStream.on('error', (err) => reject(new Error(`GridFS download failed: ${err.message}`)));
      downloadStream.on('end', () => resolve(Buffer.concat(chunks)));
    });
  }

  async delete(docId) {
    if (!this.ready || !this.bucket) {
      await this.init();
    }

    const files = await this.bucket.find({ filename: docId }).toArray();
    if (!files || files.length === 0) {
      return false;
    }

    for (const file of files) {
      await this.bucket.delete(file._id);
    }
    return true;
  }

  getStatus() {
    const isConnected = mongoose.connection.readyState === 1 && this.ready;
    return {
      name: 'MongoDB GridFS',
      isMock: false,
      ready: isConnected,
      details: isConnected
        ? `Connected to MongoDB database "${mongoose.connection.name}" bucket "${this.bucketName}"`
        : 'Disconnected or connecting'
    };
  }
}


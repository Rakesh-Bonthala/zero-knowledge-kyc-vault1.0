import fs from 'fs/promises';
import path from 'path';
import { StorageAdapter } from './storage.interface.js';

export class MockStorageAdapter extends StorageAdapter {
  constructor(storageDir = './.mock_storage') {
    super('Local Mock Storage');
    this.storageDir = path.resolve(process.cwd(), storageDir);
    this.ready = false;
  }

  async init() {
    try {
      await fs.mkdir(this.storageDir, { recursive: true });
      this.ready = true;
      return true;
    } catch (err) {
      this.ready = false;
      throw new Error(`Failed to initialize mock storage directory: ${err.message}`);
    }
  }

  _getFilePath(docId) {
    // Sanitize docId to prevent directory traversal
    const safeDocId = docId.replace(/[^a-zA-Z0-9_-]/g, '');
    return path.join(this.storageDir, `${safeDocId}.enc`);
  }

  async store(docId, buffer, metadata = {}) {
    if (!this.ready) await this.init();
    const filePath = this._getFilePath(docId);
    await fs.writeFile(filePath, buffer);
    return {
      storageRef: filePath,
      storedAt: new Date()
    };
  }

  async retrieve(docId) {
    if (!this.ready) await this.init();
    const filePath = this._getFilePath(docId);
    try {
      const buffer = await fs.readFile(filePath);
      return buffer;
    } catch (err) {
      if (err.code === 'ENOENT') {
        const notFound = new Error(`Encrypted file for document ${docId} not found in mock storage.`);
        notFound.statusCode = 404;
        throw notFound;
      }
      throw err;
    }
  }

  async delete(docId) {
    if (!this.ready) await this.init();
    const filePath = this._getFilePath(docId);
    try {
      await fs.unlink(filePath);
      return true;
    } catch (err) {
      if (err.code === 'ENOENT') {
        return false;
      }
      throw err;
    }
  }

  getStatus() {
    return {
      name: 'Local Mock Storage',
      isMock: true,
      ready: this.ready,
      details: 'Operating in zero-credential mock mode. Ciphertext is isolated in local directory.'
    };
  }
}


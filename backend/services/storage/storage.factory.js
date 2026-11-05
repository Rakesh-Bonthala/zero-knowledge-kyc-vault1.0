import { config } from '../../config/config.js';
import { MockStorageAdapter } from './mock.adapter.js';
import { GridFSStorageAdapter } from './gridfs.adapter.js';
import { S3StorageAdapter } from './s3.adapter.js';
import { FirebaseStorageAdapter } from './firebase.adapter.js';

export class StorageFactory {
  static activeAdapter = null;
  static fallbackOccurred = false;
  static fallbackReason = null;
  static initPromise = null;

  static async getAdapter() {
    if (this.activeAdapter && this.activeAdapter.ready) {
      return this.activeAdapter;
    }

    if (this.initPromise) {
      return await this.initPromise;
    }

    this.initPromise = (async () => {
      const provider = config.storageProvider;
      console.log(`[StorageFactory] Initializing storage provider: "${provider}"...`);

      let primaryAdapter = null;

      switch (provider) {
        case 'gridfs':
          primaryAdapter = new GridFSStorageAdapter(
            config.mongodb.uri,
            config.mongodb.bucketName,
            config.mongodb.options
          );
          break;

        case 's3':
          primaryAdapter = new S3StorageAdapter(config.aws);
          break;

        case 'firebase':
          primaryAdapter = new FirebaseStorageAdapter(config.firebase);
          break;

        case 'mock':
        default:
          primaryAdapter = new MockStorageAdapter();
          break;
      }

      try {
        await primaryAdapter.init();
        this.activeAdapter = primaryAdapter;
        console.log(`[StorageFactory] Successfully connected to ${primaryAdapter.name}`);
        return this.activeAdapter;
      } catch (err) {
        console.warn(`[StorageFactory] Warning: Failed to initialize primary provider "${provider}": ${err.message}`);

        if (config.allowMockFallback && provider !== 'mock') {
          console.warn('[StorageFactory] Falling back to Local Mock Storage adapter for offline/local development.');
          const mockAdapter = new MockStorageAdapter();
          await mockAdapter.init();
          this.activeAdapter = mockAdapter;
          this.fallbackOccurred = true;
          this.fallbackReason = err.message;
          return this.activeAdapter;
        }

        throw err;
      } finally {
        this.initPromise = null;
      }
    })();

    return await this.initPromise;
  }

  static getStatus() {
    if (!this.activeAdapter) {
      return {
        name: config.storageProvider,
        isMock: config.storageProvider === 'mock',
        ready: false,
        details: 'Not initialized yet',
        fallbackOccurred: this.fallbackOccurred,
        fallbackReason: this.fallbackReason
      };
    }

    const baseStatus = this.activeAdapter.getStatus();
    return {
      ...baseStatus,
      fallbackOccurred: this.fallbackOccurred,
      fallbackReason: this.fallbackReason,
      configuredProvider: config.storageProvider
    };
  }
}

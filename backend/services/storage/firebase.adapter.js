import { StorageAdapter } from './storage.interface.js';

export class FirebaseStorageAdapter extends StorageAdapter {
  constructor(firebaseConfig = {}) {
    super('Firebase Storage');
    this.projectId = firebaseConfig.projectId;
    this.clientEmail = firebaseConfig.clientEmail;
    this.privateKey = firebaseConfig.privateKey ? firebaseConfig.privateKey.replace(/\\n/g, '\n') : '';
    this.bucketName = firebaseConfig.bucket;
    this.bucket = null;
    this.ready = false;
  }

  async init() {
    if (!this.projectId || !this.clientEmail || !this.privateKey || !this.bucketName) {
      this.ready = false;
      throw new Error('Firebase credentials (projectId, clientEmail, privateKey, bucket) are missing in configuration.');
    }

    try {
      const admin = await import('firebase-admin');
      const { cert, getApps, initializeApp } = admin.default || admin;

      if (!getApps().length) {
        initializeApp({
          credential: cert({
            projectId: this.projectId,
            clientEmail: this.clientEmail,
            privateKey: this.privateKey
          }),
          storageBucket: this.bucketName
        });
      }

      const { getStorage } = await import('firebase-admin/storage');
      this.bucket = getStorage().bucket();
      this.ready = true;
      return true;
    } catch (err) {
      this.ready = false;
      throw new Error(`Failed to initialize Firebase Storage: ${err.message}. Ensure firebase-admin is installed.`);
    }
  }

  async store(docId, buffer, metadata = {}) {
    if (!this.ready || !this.bucket) await this.init();
    const file = this.bucket.file(`vault/${docId}.enc`);

    await file.save(buffer, {
      contentType: 'application/octet-stream',
      metadata: {
        metadata: {
          docId,
          encryptionVersion: metadata.encryptionVersion || 'v1.0'
        }
      }
    });

    return {
      storageRef: `gs://${this.bucketName}/vault/${docId}.enc`,
      storedAt: new Date()
    };
  }

  async retrieve(docId) {
    if (!this.ready || !this.bucket) await this.init();
    const file = this.bucket.file(`vault/${docId}.enc`);

    const [exists] = await file.exists();
    if (!exists) {
      const notFound = new Error(`Encrypted file for document ${docId} not found in Firebase Storage.`);
      notFound.statusCode = 404;
      throw notFound;
    }

    const [contents] = await file.download();
    return contents;
  }

  async delete(docId) {
    if (!this.ready || !this.bucket) await this.init();
    const file = this.bucket.file(`vault/${docId}.enc`);
    const [exists] = await file.exists();
    if (!exists) return false;
    await file.delete();
    return true;
  }

  getStatus() {
    return {
      name: 'Firebase Storage',
      isMock: false,
      ready: this.ready,
      details: this.ready
        ? `Configured for Firebase bucket "${this.bucketName}"`
        : 'Firebase service account or storage bucket not configured'
    };
  }
}


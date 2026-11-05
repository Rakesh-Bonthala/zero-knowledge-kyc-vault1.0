import { StorageAdapter } from './storage.interface.js';

export class S3StorageAdapter extends StorageAdapter {
  constructor(awsConfig = {}) {
    super('AWS S3');
    this.region = awsConfig.region || 'us-east-1';
    this.accessKeyId = awsConfig.accessKeyId;
    this.secretAccessKey = awsConfig.secretAccessKey;
    this.bucket = awsConfig.bucket;
    this.client = null;
    this.ready = false;
  }

  async init() {
    if (!this.accessKeyId || !this.secretAccessKey || !this.bucket) {
      this.ready = false;
      throw new Error('AWS S3 credentials or bucket name are missing in configuration.');
    }

    try {
      // Dynamic import to allow running even if optional AWS SDK is not in dependencies
      const { S3Client } = await import('@aws-sdk/client-s3');
      this.client = new S3Client({
        region: this.region,
        credentials: {
          accessKeyId: this.accessKeyId,
          secretAccessKey: this.secretAccessKey
        }
      });
      this.ready = true;
      return true;
    } catch (err) {
      this.ready = false;
      throw new Error(`Failed to initialize AWS S3 client: ${err.message}. Ensure @aws-sdk/client-s3 is installed.`);
    }
  }

  async store(docId, buffer, metadata = {}) {
    if (!this.ready || !this.client) await this.init();
    const { PutObjectCommand } = await import('@aws-sdk/client-s3');

    const key = `vault/${docId}.enc`;
    const command = new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      Body: buffer,
      ContentType: 'application/octet-stream',
      Metadata: {
        docId: docId,
        encryptionVersion: metadata.encryptionVersion || 'v1.0'
      }
    });

    await this.client.send(command);
    return {
      storageRef: `s3://${this.bucket}/${key}`,
      storedAt: new Date()
    };
  }

  async retrieve(docId) {
    if (!this.ready || !this.client) await this.init();
    const { GetObjectCommand } = await import('@aws-sdk/client-s3');

    const key = `vault/${docId}.enc`;
    try {
      const command = new GetObjectCommand({
        Bucket: this.bucket,
        Key: key
      });
      const response = await this.client.send(command);
      const byteArray = await response.Body.transformToByteArray();
      return Buffer.from(byteArray);
    } catch (err) {
      if (err.name === 'NoSuchKey') {
        const notFound = new Error(`Encrypted file for document ${docId} not found in S3.`);
        notFound.statusCode = 404;
        throw notFound;
      }
      throw err;
    }
  }

  async delete(docId) {
    if (!this.ready || !this.client) await this.init();
    const { DeleteObjectCommand } = await import('@aws-sdk/client-s3');

    const key = `vault/${docId}.enc`;
    const command = new DeleteObjectCommand({
      Bucket: this.bucket,
      Key: key
    });
    await this.client.send(command);
    return true;
  }

  getStatus() {
    return {
      name: 'AWS S3',
      isMock: false,
      ready: this.ready,
      details: this.ready
        ? `Configured for S3 bucket "${this.bucket}" in region "${this.region}"`
        : 'AWS credentials or bucket not fully configured'
    };
  }
}


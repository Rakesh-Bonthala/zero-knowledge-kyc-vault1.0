import dotenv from 'dotenv';
dotenv.config();

export const config = {
  port: parseInt(process.env.PORT, 10) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  storageProvider: (process.env.STORAGE_PROVIDER || 'gridfs').toLowerCase(),
  allowMockFallback: process.env.STORAGE_ALLOW_MOCK_FALLBACK !== 'false',
  maxFileSizeMB: parseInt(process.env.MAX_FILE_SIZE_MB, 10) || 50,
  corsOrigin: process.env.CORS_ORIGIN || '*',

  // MongoDB GridFS
  mongodb: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/zk_kyc_vault',
    bucketName: 'encrypted_documents',
    options: {
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
    }
  },

  // AWS S3
  aws: {
    region: process.env.AWS_REGION || 'us-east-1',
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || '',
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || '',
    bucket: process.env.AWS_S3_BUCKET || 'zk-kyc-vault-bucket'
  },

  // Firebase
  firebase: {
    projectId: process.env.FIREBASE_PROJECT_ID || '',
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
    privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
    bucket: process.env.FIREBASE_STORAGE_BUCKET || ''
  }
};


/**
 * Client-Side Cryptographic Engine for Zero-Knowledge KYC Vault
 *
 * Implements standard W3C Web Crypto API specifications:
 * - Cipher: AES-256-GCM (96-bit IV, 128-bit Authentication Tag)
 * - Key Derivation: PBKDF2 with HMAC-SHA-256 (600,000 iterations default)
 * - Salt: Cryptographically secure random 128-bit (16-byte)
 * - Additional Authenticated Data (AAD): Cryptographic binding of file metadata
 *
 * No external cryptography libraries. Zero key escrow. Zero server-side plaintext.
 */

const cryptoSubtle = globalThis.crypto?.subtle || globalThis.crypto?.webcrypto?.subtle;
const cryptoObj = globalThis.crypto;

export class DecryptionError extends Error {
  constructor(message, originalError = null) {
    super(message);
    this.name = 'DecryptionError';
    this.originalError = originalError;
  }
}

/**
 * Converts an ArrayBuffer or Uint8Array to a standard Base64 string.
 */
export function arrayBufferToBase64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Converts a Base64 string to a Uint8Array.
 */
export function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generates a cryptographically secure random salt.
 * Minimum 16 bytes (128 bits).
 */
export function generateSalt(length = 16) {
  if (length < 16) throw new Error('Salt must be at least 16 bytes for cryptographic security.');
  const salt = new Uint8Array(length);
  cryptoObj.getRandomValues(salt);
  return salt;
}

/**
 * Generates a fresh cryptographically secure random 12-byte (96-bit) IV for AES-GCM.
 * Critical: Never reuse an IV with the same encryption key.
 */
export function generateIV(length = 12) {
  const iv = new Uint8Array(length);
  cryptoObj.getRandomValues(iv);
  return iv;
}

/**
 * Derives a 256-bit AES-GCM key from a user passphrase and a fresh salt using PBKDF2.
 * Uses HMAC-SHA-256 and configurable iteration count (default 600,000).
 */
export async function deriveKey(passphrase, saltBytes, iterations = 600000) {
  if (!passphrase || typeof passphrase !== 'string') {
    throw new Error('Passphrase must be a non-empty string.');
  }
  if (!saltBytes || saltBytes.byteLength < 16) {
    throw new Error('Salt must be at least 16 bytes.');
  }

  const enc = new TextEncoder();
  const passphraseBytes = enc.encode(passphrase);

  // Import passphrase as PBKDF2 base key (not extractable)
  const baseKey = await cryptoSubtle.importKey(
    'raw',
    passphraseBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // Derive AES-GCM 256-bit encryption key
  const aesKey = await cryptoSubtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: iterations,
      hash: 'SHA-256'
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    false, // Key is non-extractable from browser memory
    ['encrypt', 'decrypt']
  );

  return aesKey;
}

/**
 * Canonical serialization for Additional Authenticated Data (AAD).
 * Binds document metadata to ciphertext to prevent metadata tampering/substitution.
 */
export function createAAD(metadata = {}) {
  const canonical = JSON.stringify({
    filename: metadata.filename || '',
    mimeType: metadata.mimeType || 'application/octet-stream',
    size: metadata.size || 0,
    version: metadata.version || 'v1.0'
  });
  return new TextEncoder().encode(canonical);
}

/**
 * Encrypts a document buffer using AES-256-GCM with fresh Salt and fresh IV.
 *
 * @param {ArrayBuffer} plaintextBuffer - Raw document bytes.
 * @param {string} passphrase - User's secret passphrase.
 * @param {Object} docInfo - Document metadata (filename, mimeType, size).
 * @param {Object} options - Cryptographic settings (iterations).
 * @returns {Promise<{ ciphertext: ArrayBuffer, metadata: Object }>}
 */
export async function encryptDocument(plaintextBuffer, passphrase, docInfo = {}, options = {}) {
  const iterations = options.iterations || 600000;
  const saltBytes = generateSalt(16);
  const ivBytes = generateIV(12);

  // Derive 256-bit key
  const key = await deriveKey(passphrase, saltBytes, iterations);

  // Generate Additional Authenticated Data (AAD)
  const aadBytes = createAAD({
    filename: docInfo.filename,
    mimeType: docInfo.mimeType,
    size: plaintextBuffer.byteLength,
    version: 'v1.0'
  });

  // AES-256-GCM Authenticated Encryption
  // Web Crypto automatically computes and appends the 128-bit authentication tag
  const ciphertextBuffer = await cryptoSubtle.encrypt(
    {
      name: 'AES-GCM',
      iv: ivBytes,
      additionalData: aadBytes,
      tagLength: 128
    },
    key,
    plaintextBuffer
  );

  const metadata = {
    originalFilename: docInfo.filename || 'kyc-document',
    mimeType: docInfo.mimeType || 'application/octet-stream',
    fileSize: plaintextBuffer.byteLength,
    ciphertextSizeBytes: ciphertextBuffer.byteLength,
    salt: arrayBufferToBase64(saltBytes),
    iv: arrayBufferToBase64(ivBytes),
    aad: arrayBufferToBase64(aadBytes),
    pbkdf2Iterations: iterations,
    encryptionAlgorithm: 'AES-256-GCM',
    kdfAlgorithm: 'PBKDF2',
    encryptionVersion: 'v1.0'
  };

  return {
    ciphertextBuffer,
    metadata
  };
}

/**
 * Decrypts an encrypted document buffer using AES-256-GCM.
 * Reconstructs original file if authentication tag verification succeeds.
 *
 * @param {ArrayBuffer} ciphertextBuffer - Ciphertext + 16-byte authentication tag.
 * @param {string} passphrase - User's secret passphrase.
 * @param {Object} metadata - Cryptographic metadata (salt, iv, aad, iterations).
 * @returns {Promise<{ decryptedBuffer: ArrayBuffer, blob: Blob, filename: string, mimeType: string }>}
 */
export async function decryptDocument(ciphertextBuffer, passphrase, metadata = {}) {
  if (!passphrase) {
    throw new DecryptionError('Passphrase is required for decryption.');
  }
  if (!metadata.salt || !metadata.iv) {
    throw new DecryptionError('Missing required cryptographic parameters (salt or IV).');
  }

  const saltBytes = base64ToUint8Array(metadata.salt);
  const ivBytes = base64ToUint8Array(metadata.iv);
  const iterations = parseInt(metadata.pbkdf2Iterations, 10) || 600000;

  // Re-derive 256-bit AES key locally
  const key = await deriveKey(passphrase, saltBytes, iterations);

  // Parse or reconstruct AAD
  let aadBytes;
  if (metadata.aad) {
    aadBytes = base64ToUint8Array(metadata.aad);
  } else {
    aadBytes = createAAD({
      filename: metadata.originalFilename,
      mimeType: metadata.mimeType,
      size: metadata.fileSize,
      version: metadata.encryptionVersion || 'v1.0'
    });
  }

  try {
    const decryptedBuffer = await cryptoSubtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBytes,
        additionalData: aadBytes,
        tagLength: 128
      },
      key,
      ciphertextBuffer
    );

    const mimeType = metadata.mimeType || 'application/octet-stream';
    const blob = new Blob([decryptedBuffer], { type: mimeType });

    return {
      decryptedBuffer,
      blob,
      filename: metadata.originalFilename || 'decrypted-kyc-document',
      mimeType
    };
  } catch (err) {
    // In AES-GCM, any corruption of ciphertext, incorrect key, or altered AAD triggers an authentication failure
    throw new DecryptionError(
      'Decryption and authentication failed. Either the passphrase is incorrect, or the ciphertext / metadata has been altered.',
      err
    );
  }
}


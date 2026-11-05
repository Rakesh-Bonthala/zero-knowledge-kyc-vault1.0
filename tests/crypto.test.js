import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  generateSalt,
  generateIV,
  deriveKey,
  encryptDocument,
  decryptDocument,
  DecryptionError,
  arrayBufferToBase64,
  base64ToUint8Array
} from '../frontend/js/crypto.js';

describe('Zero-Knowledge Cryptographic Engine (Web Crypto API)', () => {
  const samplePassphrase = 'CorrectHorseBatteryStaple!2026';
  const wrongPassphrase = 'IncorrectPassword999';
  const samplePlaintext = 'CONFIDENTIAL KYC DOCUMENT: Passport #P987654321, DOB: 1990-01-01, Holder: Alice Smith';
  const sampleBuffer = new TextEncoder().encode(samplePlaintext).buffer;

  it('generates unique salts of at least 16 bytes', () => {
    const salt1 = generateSalt(16);
    const salt2 = generateSalt(16);

    assert.strictEqual(salt1.byteLength, 16);
    assert.strictEqual(salt2.byteLength, 16);
    assert.notDeepStrictEqual(salt1, salt2, 'Salts must be randomly generated and unique');
  });

  it('generates fresh 12-byte IVs for every operation (NIST SP 800-38D standard)', () => {
    const iv1 = generateIV(12);
    const iv2 = generateIV(12);

    assert.strictEqual(iv1.byteLength, 12);
    assert.strictEqual(iv2.byteLength, 12);
    assert.notDeepStrictEqual(iv1, iv2, 'IVs must never be reused');
  });

  it('derives 256-bit AES-GCM CryptoKey using PBKDF2-HMAC-SHA256', async () => {
    const salt = generateSalt(16);
    const key = await deriveKey(samplePassphrase, salt, 10000); // 10k for fast unit test

    assert.ok(key);
    assert.strictEqual(key.algorithm.name, 'AES-GCM');
    assert.strictEqual(key.algorithm.length, 256);
    assert.strictEqual(key.extractable, false, 'Derived key must not be extractable from memory');
  });

  it('successfully encrypts and decrypts document preserving exact plaintext bytes', async () => {
    const docInfo = {
      filename: 'passport_scan.pdf',
      mimeType: 'application/pdf'
    };

    // Encrypt
    const { ciphertextBuffer, metadata } = await encryptDocument(
      sampleBuffer,
      samplePassphrase,
      docInfo,
      { iterations: 10000 }
    );

    assert.ok(ciphertextBuffer.byteLength > sampleBuffer.byteLength, 'Ciphertext must include 16-byte GCM authentication tag');
    assert.ok(metadata.salt);
    assert.ok(metadata.iv);
    assert.ok(metadata.aad);
    assert.strictEqual(metadata.encryptionAlgorithm, 'AES-256-GCM');

    // Decrypt
    const result = await decryptDocument(ciphertextBuffer, samplePassphrase, metadata);
    const decryptedText = new TextDecoder().decode(result.decryptedBuffer);

    assert.strictEqual(decryptedText, samplePlaintext, 'Decrypted text must match original plaintext exactly');
    assert.strictEqual(result.filename, docInfo.filename);
    assert.strictEqual(result.mimeType, docInfo.mimeType);
  });

  it('ciphertext is unreadable and does not leak plaintext fragments', async () => {
    const { ciphertextBuffer } = await encryptDocument(
      sampleBuffer,
      samplePassphrase,
      { filename: 'doc.txt', mimeType: 'text/plain' },
      { iterations: 10000 }
    );

    const ciphertextView = new Uint8Array(ciphertextBuffer);
    const plaintextView = new Uint8Array(sampleBuffer);

    // Verify raw bytes are not equal
    assert.notDeepStrictEqual(ciphertextView.slice(0, plaintextView.length), plaintextView);

    // Ensure raw string search fails
    const rawString = String.fromCharCode(...ciphertextView);
    assert.ok(!rawString.includes('Passport'), 'Ciphertext must not contain plaintext substrings');
    assert.ok(!rawString.includes('Alice Smith'), 'Ciphertext must not leak KYC identity info');
  });

  it('fails decryption and throws DecryptionError when wrong passphrase is provided', async () => {
    const { ciphertextBuffer, metadata } = await encryptDocument(
      sampleBuffer,
      samplePassphrase,
      { filename: 'doc.txt', mimeType: 'text/plain' },
      { iterations: 10000 }
    );

    await assert.rejects(
      async () => {
        await decryptDocument(ciphertextBuffer, wrongPassphrase, metadata);
      },
      (err) => {
        assert.ok(err instanceof DecryptionError);
        assert.ok(err.message.includes('authentication failed'));
        return true;
      },
      'Wrong passphrase must fail AES-GCM tag verification without returning corrupted plaintext'
    );
  });

  it('fails decryption when ciphertext is tampered with (GCM integrity check)', async () => {
    const { ciphertextBuffer, metadata } = await encryptDocument(
      sampleBuffer,
      samplePassphrase,
      { filename: 'doc.txt', mimeType: 'text/plain' },
      { iterations: 10000 }
    );

    // Tamper with one single byte in the ciphertext
    const tampered = new Uint8Array(ciphertextBuffer.slice(0));
    tampered[10] ^= 0xff; // Invert bits of 10th byte

    await assert.rejects(
      async () => {
        await decryptDocument(tampered.buffer, samplePassphrase, metadata);
      },
      (err) => {
        assert.ok(err instanceof DecryptionError);
        return true;
      },
      'Tampered ciphertext must be detected by AES-GCM authentication tag'
    );
  });

  it('fails decryption when Additional Authenticated Data (AAD) is modified', async () => {
    const { ciphertextBuffer, metadata } = await encryptDocument(
      sampleBuffer,
      samplePassphrase,
      { filename: 'doc.txt', mimeType: 'text/plain' },
      { iterations: 10000 }
    );

    // Tamper with AAD metadata (e.g., attacker replaces bound metadata)
    const tamperedMetadata = {
      ...metadata,
      aad: arrayBufferToBase64(new TextEncoder().encode(JSON.stringify({
        filename: 'fraudulent_passport.pdf',
        mimeType: 'application/pdf',
        size: 9999,
        version: 'v1.0'
      })))
    };

    await assert.rejects(
      async () => {
        await decryptDocument(ciphertextBuffer, samplePassphrase, tamperedMetadata);
      },
      (err) => {
        assert.ok(err instanceof DecryptionError);
        return true;
      },
      'Altering bound AAD metadata must fail cryptographic verification'
    );
  });
});


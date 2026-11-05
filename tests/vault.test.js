process.env.NODE_ENV = 'test';
process.env.STORAGE_PROVIDER = 'mock';

import { describe, it, before } from 'node:test';
import assert from 'node:assert';
import request from 'supertest';
import app from '../backend/server.js';
import { encryptDocument, decryptDocument } from '../frontend/js/crypto.js';

describe('Zero-Knowledge KYC Vault API & Storage Test Suite', () => {
  const testUserId = 'test_fintech_user_42';
  const otherUserId = 'unauthorized_attacker_99';
  const passphrase = 'SuperSecretVaultPassphrase!2026';
  const kycDocumentText = 'GOVERNMENT ISSUED IDENTITY CARD - CITIZEN #789012345 - EXP: 2030';
  const plaintextBuffer = new TextEncoder().encode(kycDocumentText).buffer;

  let uploadedDocId = null;
  let clientEncryptedResult = null;

  before(async () => {
    // Encrypt document client-side before any network request
    clientEncryptedResult = await encryptDocument(
      plaintextBuffer,
      passphrase,
      {
        filename: 'national_id.pdf',
        mimeType: 'application/pdf'
      },
      { iterations: 10000 }
    );
  });

  it('GET /api/vault/status returns storage backend status and zero-knowledge posture', async () => {
    const res = await request(app).get('/api/vault/status');

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(res.body.storage);
    assert.ok(res.body.storage.name);
    assert.strictEqual(res.body.security.zeroKnowledgeMode, true);
    assert.strictEqual(res.body.security.serverDecryptionEnabled, false);
  });

  it('POST /api/vault/upload accepts ciphertext blob and non-secret metadata (zero plaintext received)', async () => {
    const ciphertextBytes = Buffer.from(clientEncryptedResult.ciphertextBuffer);

    const res = await request(app)
      .post('/api/vault/upload')
      .set('X-User-Id', testUserId)
      .attach('encryptedFile', ciphertextBytes, 'encrypted.bin')
      .field('metadata', JSON.stringify(clientEncryptedResult.metadata));

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.success, true);
    assert.ok(res.body.document.docId);
    assert.strictEqual(res.body.document.originalFilename, 'national_id.pdf');
    assert.strictEqual(res.body.document.ciphertextSizeBytes, ciphertextBytes.length);

    uploadedDocId = res.body.document.docId;
  });

  it('GET /api/vault/documents lists documents for authorized owner without leaking ciphertexts or keys', async () => {
    const res = await request(app)
      .get('/api/vault/documents')
      .set('X-User-Id', testUserId);

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(Array.isArray(res.body.documents));
    assert.ok(res.body.documents.length >= 1);

    const found = res.body.documents.find(d => d.docId === uploadedDocId);
    assert.ok(found);
    assert.strictEqual(found.originalFilename, 'national_id.pdf');
    assert.strictEqual(found.encryptionAlgorithm, 'AES-256-GCM');
    // Ensure no secrets exist in response
    assert.strictEqual(found.passphrase, undefined);
    assert.strictEqual(found.key, undefined);
    assert.strictEqual(found.plaintext, undefined);
  });

  it('GET /api/vault/download/:id returns raw ciphertext and cryptographic headers', async () => {
    const res = await request(app)
      .get(`/api/vault/download/${uploadedDocId}`)
      .set('X-User-Id', testUserId)
      .buffer(true)
      .parse((res, callback) => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => callback(null, Buffer.concat(chunks)));
      });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers['content-type'], 'application/octet-stream');
    assert.strictEqual(res.headers['x-doc-id'], uploadedDocId);
    assert.ok(res.headers['x-salt']);
    assert.ok(res.headers['x-iv']);
    assert.ok(res.headers['x-iterations']);

    // Verify downloaded bytes are raw ciphertext matching what was uploaded
    const downloadedBuffer = res.body;
    assert.strictEqual(downloadedBuffer.length, clientEncryptedResult.ciphertextBuffer.byteLength);

    // Extract exact ArrayBuffer slice for Web Crypto API
    const arrayBuffer = downloadedBuffer.buffer.slice(
      downloadedBuffer.byteOffset,
      downloadedBuffer.byteOffset + downloadedBuffer.byteLength
    );

    // Decrypt locally using Web Crypto API and verify match with original document
    const metadataFromHeaders = {
      originalFilename: decodeURIComponent(res.headers['x-original-filename']),
      mimeType: res.headers['x-mime-type'],
      fileSize: parseInt(res.headers['x-file-size'], 10),
      salt: res.headers['x-salt'],
      iv: res.headers['x-iv'],
      pbkdf2Iterations: parseInt(res.headers['x-iterations'], 10),
      aad: res.headers['x-aad'] ? decodeURIComponent(res.headers['x-aad']) : null
    };

    const decrypted = await decryptDocument(arrayBuffer, passphrase, metadataFromHeaders);
    const decryptedText = new TextDecoder().decode(decrypted.decryptedBuffer);

    assert.strictEqual(decryptedText, kycDocumentText, 'End-to-end decrypted content must match original KYC document');
  });

  it('GET /api/vault/download/:id denies access to unauthorized users (Ownership Isolation)', async () => {
    const res = await request(app)
      .get(`/api/vault/download/${uploadedDocId}`)
      .set('X-User-Id', otherUserId); // Different user

    assert.strictEqual(res.status, 403);
    assert.strictEqual(res.body.success, false);
    assert.ok(res.body.error.includes('Access denied'));
  });

  it('DELETE /api/vault/documents/:id deletes document and prevents subsequent downloads', async () => {
    // Delete document
    const delRes = await request(app)
      .delete(`/api/vault/documents/${uploadedDocId}`)
      .set('X-User-Id', testUserId);

    assert.strictEqual(delRes.status, 200);
    assert.strictEqual(delRes.body.success, true);

    // Verify subsequent download returns 404
    const getRes = await request(app)
      .get(`/api/vault/download/${uploadedDocId}`)
      .set('X-User-Id', testUserId);

    assert.strictEqual(getRes.status, 404);
  });
});

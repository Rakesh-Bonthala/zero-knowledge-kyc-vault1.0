/**
 * REST API Client for Zero-Knowledge KYC Vault
 * Transmits exclusively ciphertext and non-secret cryptographic metadata.
 */

const API_BASE = '/api/vault';

export class VaultAPI {
  static getHeaders(userId = 'demo_fintech_user_01') {
    return {
      'X-User-Id': userId
    };
  }

  /**
   * Fetches backend and storage provider status.
   */
  static async getStatus() {
    const res = await fetch(`${API_BASE}/status`);
    if (!res.ok) throw new Error(`Status check failed: HTTP ${res.status}`);
    return await res.json();
  }

  /**
   * Fetches document metadata list for authenticated user.
   */
  static async listDocuments(userId) {
    const res = await fetch(`${API_BASE}/documents`, {
      headers: this.getHeaders(userId)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Failed to fetch documents: HTTP ${res.status}`);
    }
    return await res.json();
  }

  /**
   * Uploads encrypted file blob and cryptographic metadata.
   */
  static async uploadEncrypted(ciphertextBuffer, metadata, userId, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${API_BASE}/upload`, true);
      xhr.setRequestHeader('X-User-Id', userId || 'demo_fintech_user_01');

      if (xhr.upload && onProgress) {
        xhr.upload.onprogress = (event) => {
          if (event.lengthComputable) {
            const percent = Math.round((event.loaded / event.total) * 100);
            onProgress(percent);
          }
        };
      }

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            const data = JSON.parse(xhr.responseText);
            resolve(data);
          } catch (e) {
            reject(new Error('Invalid JSON response from server.'));
          }
        } else {
          try {
            const data = JSON.parse(xhr.responseText);
            reject(new Error(data.error || `Upload failed with HTTP ${xhr.status}`));
          } catch (e) {
            reject(new Error(`Upload failed with HTTP ${xhr.status}`));
          }
        }
      };

      xhr.onerror = () => reject(new Error('Network error during document upload.'));

      const formData = new FormData();
      const encryptedBlob = new Blob([ciphertextBuffer], { type: 'application/octet-stream' });
      formData.append('encryptedFile', encryptedBlob, 'encrypted.bin');
      formData.append('metadata', JSON.stringify(metadata));

      xhr.send(formData);
    });
  }

  /**
   * Downloads raw ciphertext and extracts cryptographic metadata from response headers.
   */
  static async downloadEncrypted(docId, userId) {
    const res = await fetch(`${API_BASE}/download/${docId}`, {
      headers: this.getHeaders(userId)
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Failed to download document: HTTP ${res.status}`);
    }

    const ciphertextBuffer = await res.arrayBuffer();

    // Extract decryption metadata from headers
    const metadata = {
      docId: res.headers.get('X-Doc-Id'),
      originalFilename: decodeURIComponent(res.headers.get('X-Original-Filename') || 'kyc_document'),
      mimeType: res.headers.get('X-Mime-Type') || 'application/octet-stream',
      fileSize: parseInt(res.headers.get('X-File-Size'), 10) || ciphertextBuffer.byteLength,
      salt: res.headers.get('X-Salt'),
      iv: res.headers.get('X-IV'),
      pbkdf2Iterations: parseInt(res.headers.get('X-Iterations'), 10) || 600000,
      aad: res.headers.get('X-AAD') ? decodeURIComponent(res.headers.get('X-AAD')) : null,
      encryptionAlgorithm: res.headers.get('X-Encryption-Algorithm') || 'AES-256-GCM',
      kdfAlgorithm: res.headers.get('X-KDF-Algorithm') || 'PBKDF2'
    };

    return {
      ciphertextBuffer,
      metadata
    };
  }

  /**
   * Deletes document and metadata permanently from backend.
   */
  static async deleteDocument(docId, userId) {
    const res = await fetch(`${API_BASE}/documents/${docId}`, {
      method: 'DELETE',
      headers: this.getHeaders(userId)
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Failed to delete document: HTTP ${res.status}`);
    }

    return await res.json();
  }
}


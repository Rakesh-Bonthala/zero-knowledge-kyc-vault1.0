/**
 * StorageAdapter interface definition.
 * Every storage provider must implement these methods.
 */
export class StorageAdapter {
  constructor(name) {
    this.name = name;
  }

  /**
   * Initializes connections, buckets, or directories.
   */
  async init() {
    throw new Error('init() not implemented');
  }

  /**
   * Stores ciphertext in storage.
   * @param {string} docId - Unique document UUID.
   * @param {Buffer} buffer - Raw encrypted ciphertext buffer.
   * @param {Object} metadata - Non-secret encryption and document metadata.
   * @returns {Promise<{ storageRef: string, storedAt: Date }>}
   */
  async store(docId, buffer, metadata) {
    throw new Error('store() not implemented');
  }

  /**
   * Retrieves encrypted ciphertext from storage.
   * @param {string} docId
   * @returns {Promise<Buffer>}
   */
  async retrieve(docId) {
    throw new Error('retrieve() not implemented');
  }

  /**
   * Deletes ciphertext from storage.
   * @param {string} docId
   * @returns {Promise<boolean>}
   */
  async delete(docId) {
    throw new Error('delete() not implemented');
  }

  /**
   * Returns current health and identification status of the storage backend.
   * @returns {{ name: string, isMock: boolean, ready: boolean, details: string }}
   */
  getStatus() {
    return {
      name: this.name,
      isMock: false,
      ready: false,
      details: 'Uninitialized'
    };
  }
}


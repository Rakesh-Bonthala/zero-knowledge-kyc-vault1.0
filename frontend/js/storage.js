/**
 * Client-Side Session & State Management
 *
 * CRITICAL ZERO-KNOWLEDGE COMPLIANCE:
 * - NO passphrase persistence (forbidden in localStorage/sessionStorage/cookies/IndexedDB).
 * - NO derived encryption key persistence.
 * - Only user preferences (UI theme, iterations config, breach check toggle) are stored.
 */

const PREF_PREFIX = 'zk_vault_pref_';

export class ClientSessionState {
  static defaultIterations = 600000;

  static getIterations() {
    try {
      const saved = localStorage.getItem(`${PREF_PREFIX}iterations`);
      const val = parseInt(saved, 10);
      return val && val >= 10000 ? val : this.defaultIterations;
    } catch (e) {
      return this.defaultIterations;
    }
  }

  static setIterations(count) {
    try {
      localStorage.setItem(`${PREF_PREFIX}iterations`, String(count));
    } catch (e) {}
  }

  static isBreachCheckEnabled() {
    try {
      const saved = localStorage.getItem(`${PREF_PREFIX}breach_check`);
      return saved !== 'false'; // Enabled by default
    } catch (e) {
      return true;
    }
  }

  static setBreachCheckEnabled(enabled) {
    try {
      localStorage.setItem(`${PREF_PREFIX}breach_check`, String(enabled));
    } catch (e) {}
  }

  static getUserId() {
    try {
      return localStorage.getItem(`${PREF_PREFIX}user_id`) || 'demo_fintech_user_01';
    } catch (e) {
      return 'demo_fintech_user_01';
    }
  }

  static setUserId(userId) {
    try {
      localStorage.setItem(`${PREF_PREFIX}user_id`, userId);
    } catch (e) {}
  }

  /**
   * Securely zeroes out a typed array buffer to prevent sensitive residuals.
   */
  static wipeBuffer(buffer) {
    if (buffer instanceof Uint8Array || buffer instanceof ArrayBuffer) {
      const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
      for (let i = 0; i < view.length; i++) {
        view[i] = 0;
      }
    }
  }
}


/**
 * k-Anonymity Passphrase Breach Check via Have I Been Pwned (HIBP) Range API
 *
 * Security Guarantees:
 * 1. Passphrase NEVER leaves the browser.
 * 2. Only the first 5 hexadecimal characters of the SHA-1 hash are queried.
 * 3. The remaining 35 characters are compared strictly client-side against the returned suffix list.
 * 4. SHA-1 is used solely as a public lookup hash for HIBP, never for document encryption.
 */

const cryptoSubtle = globalThis.crypto?.subtle || globalThis.crypto?.webcrypto?.subtle;

/**
 * Computes uppercase hex SHA-1 of string using Web Crypto API.
 */
async function computeSha1Hex(text) {
  const enc = new TextEncoder();
  const data = enc.encode(text);
  const hashBuffer = await cryptoSubtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/**
 * Checks if the passphrase appears in known breach databases using k-Anonymity.
 *
 * @param {string} passphrase
 * @param {number} timeoutMs
 * @returns {Promise<{ checked: boolean, breached: boolean, count: number, warning?: string, error?: string }>}
 */
export async function checkPassphraseBreach(passphrase, timeoutMs = 5000) {
  if (!passphrase || passphrase.length === 0) {
    return { checked: false, breached: false, count: 0 };
  }

  try {
    const fullHash = await computeSha1Hex(passphrase);
    const prefix = fullHash.substring(0, 5);
    const suffix = fullHash.substring(5);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      method: 'GET',
      headers: {
        'Add-Padding': 'true' // HIBP privacy padding against response-length side channels
      },
      signal: controller.signal
    });

    clearTimeout(timer);

    if (!response.ok) {
      throw new Error(`HIBP API responded with HTTP status ${response.status}`);
    }

    const text = await response.text();
    const lines = text.split('\r\n');

    for (const line of lines) {
      const [hashSuffix, countStr] = line.trim().split(':');
      if (hashSuffix && hashSuffix.toUpperCase() === suffix) {
        const count = parseInt(countStr, 10);
        return {
          checked: true,
          breached: true,
          count: isNaN(count) ? 1 : count,
          warning: `Security Alert: This passphrase has appeared in ${count.toLocaleString()} known data breaches! We strongly advise choosing a unique, high-entropy passphrase.`
        };
      }
    }

    return {
      checked: true,
      breached: false,
      count: 0,
      note: 'Passphrase not found in known breach datasets. Note: An unlisted passphrase is not guaranteed to be safe against targeted guessing.'
    };
  } catch (err) {
    console.warn('[BreachCheck] Service unreachable or aborted:', err.message);
    return {
      checked: false,
      breached: false,
      count: 0,
      error: err.message,
      warning: 'Breach verification service could not be reached. You may proceed, but ensure your passphrase is strong.'
    };
  }
}


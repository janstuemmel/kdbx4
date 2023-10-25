
/**
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
export const bufferToHex = buffer =>
  Array.from(new Uint8Array(buffer))
    .map(s => s.toString(16).padStart(2, '0')).join('');

/**
 * @param {string} hex
 * @returns {ArrayBuffer}
 */
export const hexToBuffer = hex =>
  new Uint8Array(hex.match(/../g)?.map(h => Number.parseInt(h, 16)) || []).buffer;

/**
 * @param {string} s
 * @returns {ArrayBuffer}
 */
export const base64ToBuffer = s =>
  Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer;

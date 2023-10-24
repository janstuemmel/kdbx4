
/**
 * @param {ArrayBuffer} buffer 
 * @returns {string}
 */
export const bufferToHex = (buffer) => 
  Array.from(new Uint8Array(buffer))
    .map((s) => s.toString(16).padStart(2, '0')).join('');

/**
 * @param {string} hex 
 * @returns {ArrayBuffer}
 */
export const hexToBuffer = (hex) => 
  new Uint8Array(hex.match(/../g)?.map((h) => parseInt(h, 16)) || []).buffer;

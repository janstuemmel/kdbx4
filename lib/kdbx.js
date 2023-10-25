import {computeKeys} from './crypto.js';
import {getHeader} from './header.js';
import {base64ToBuffer} from './util.js';

export class Kdbx4 {
  /**
   * @param {ArrayBuffer} file
   */
  constructor(file) {
    /**
     * @type {import('./header.js').Kdbx4Header}
     */
    this.header = getHeader(file);
  }

  /**
   * @param {ArrayBuffer} file
   * @returns {Kdbx4}
   */
  static fromFile(file) {
    return new Kdbx4(file);
  }

  /**
   * @param {string} base64
   * @returns {Kdbx4}
   */
  static fromBase64(base64) {
    return new Kdbx4(base64ToBuffer(base64));
  }

  /**
   * @param {ArrayBuffer} password
   */
  async unlock(password) {
    await computeKeys(password, this.header);
    return this;
  }
}

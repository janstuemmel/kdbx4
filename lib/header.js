import { bufferToHex } from './util.js';

/**
 * KDF Params in Header for AES_KDF
 * @typedef {Object} KdfParamsAesKdf
 * @property {'AES-KDF'} type
 * @property {number} R Number of rounds the KDF is applied.
 * @property {ArrayBuffer} S KDF Seed
 */

/**
 * KDF Params in Header for Argon
 * @typedef {Object} KdfParamsArgon
 * @property {'Argon2d' | 'Argon2id'} type
 * @property {number} P Parallism
 * @property {ArrayBuffer} S KDF Salt
 * @property {number} M Memory usage
 * @property {number} I Iterations
 * @property {number} V Argon2 version
 * @property {ArrayBuffer | undefined} K Key
 * @property {ArrayBuffer | undefined} A Associated data
 */

/**
 * KDF Params, either Argon or AES-KDF
 * @typedef {KdfParamsAesKdf | KdfParamsArgon} KdfParams
 */

/**
 * Content compression type 
 * @typedef {'none' | 'gzip'} Compression
 */

/**
 * Cipher type
 * @typedef {'AES256-CBC' | 'CHACHA20'} CipherId
 */

/**
 * The header of the kdbx4 fileformat 
 * @typedef {Object} Kdbx4Header
 * @property {number} size
 * @property {number} signature1
 * @property {number} signature2
 * @property {number} versionMinor
 * @property {number} versionMajor
 * @property {CipherId} cipherId
 * @property {Compression} compressionFlag
 * @property {ArrayBuffer} masterSeed
 * @property {ArrayBuffer} encryptionIv
 * @property {KdfParams} kdfParams
 * @property {ArrayBuffer=} publicCustomData
 */

const UUID_AES_KDF = 'c9d9f39a628a4460bf740d08c18a4fea';
const UUID_ARGON2D = 'ef636ddf8c29444b91f7a9a403e30a0c';
const UUID_ARGON2ID = '9e298b1956db4773b23dfc3ec6f0a1e6';

const CID_AES256_CBC = '31c1f2e6bf714350be5805216afc5aff';
const CID_CHACHA20 = 'd6038a2b8b6f4cb5a524339a31dbb59a';

/**
 * @type {Record<number, string>}
 */
const KDBX4_FIELDS = {
  0: 'endOfHeader',
  1: 'comment',
  2: 'cipherId',
  3: 'compressionFlag',
  4: 'masterSeed',
  7: 'encryptionIv',
  11: 'kdfParams',
  12: 'publicCustomData',
};

/**
 * @param {ArrayBuffer} buffer
 * @returns {Record<string, ArrayBuffer>}
 */
export const readKdfParams = (buffer) => {
  const view = new DataView(buffer)

  /** @type {Record<string, ArrayBuffer>} */
  const data = {};
  
  for (let i = 2;;) {
    const type = view.getUint8(i)
    if (type === 0) {
      break;
    }
    const keySize = view.getUint32(i+1, true)
    const key = view.buffer.slice(i+1+4, i+1+4+keySize)
    const valueSize = view.getUint32(i+1+4+keySize, true)
    const value = view.buffer.slice(i+1+4+keySize+4, i+1+4+keySize+4+valueSize)

    data[new TextDecoder().decode(key)] = value
    i += 1+4+keySize+4+valueSize
  }

  return data
}

/**
 * @param {ArrayBuffer} buffer 
 * @returns {[number, Record<string, ArrayBuffer>]}
 */
export const readOuterHeaderFields = (buffer) => {
  const view = new DataView(buffer)

  /** @type {Record<string, ArrayBuffer>} */
  const data = {};
  let i = 12

  while (true) {
    const id = view.getUint8(i);
    if (id === 0) {
      break;
    }
    const size = view.getUint32(i+1, true);
    const value = view.buffer.slice(i+1+4, i+1+4+size);
    if (KDBX4_FIELDS[id]) {
      data[KDBX4_FIELDS[id]] = value
    }
    i += 5+size;
  }

  return [i, data]
}

/**
 * @param {ArrayBuffer} buffer 
 * @returns {Record<string, number>}
 */
export const readOuterHeaderStart = (buffer) => {
  const view = new DataView(buffer)
  return {
    signature1: view.getUint32(0, true),
    signature2: view.getUint32(4, true),
    versionMinor: view.getUint16(8, true),
    versionMajor: view.getUint16(10, true),
  }
}

/**
 * @param {Record<string, ArrayBuffer>} records 
 * @returns {KdfParams}
 */
export const mapKdfParams = (records) => {
  if (!records['$UUID']) {
    throw new Error('no uuid')
  }

  const uuid = bufferToHex(records['$UUID'])  

  switch (uuid) {
    case UUID_AES_KDF:
      if (!records['R'] || !records['S']) {
        throw new Error('wrong params for AES-KDF')
      }

      return {
        type: 'AES-KDF',
        R: Number(new DataView(records['R']).getBigUint64(0, true)),
        S: records['S']
      }
    case UUID_ARGON2D:
    case UUID_ARGON2ID:
      if (!Object.keys(records).every(r => ['S', 'P', 'M', 'I', 'V'].includes(r))) {
        throw new Error('wrong params for argon2')
      }

      return {
        type: uuid === UUID_ARGON2D ? 'Argon2d' : 'Argon2id',
        S: records['S'],
        P: new DataView(records['R']).getUint32(0, true),
        M: Number(new DataView(records['M']).getBigUint64(0, true)),
        I: Number(new DataView(records['I']).getBigUint64(0, true)),
        V: new DataView(records['V']).getUint32(0, true),
        K: records['K'],
        A: records['A'],
      }
    default:
      throw new Error('kdf uuid not supported')
  }
}

/**
 * @param {ArrayBuffer | undefined} cid
 * @returns {CipherId}
 */
const mapCipherId = (cid = new ArrayBuffer(0)) => {
  switch (bufferToHex(cid)) {
    case CID_AES256_CBC:
      return 'AES256-CBC'
    case CID_CHACHA20:
      return 'CHACHA20'
    default:
      throw new Error('unsupported cipher uuid')
  }
}

/**
 * @param {ArrayBuffer | undefined} compressionFlag
 * @returns {Compression}
 */
const mapCompressionFlag = (compressionFlag = new ArrayBuffer(0)) => {
  const flag = new DataView(compressionFlag).getUint16(0, true)
  switch (flag) {
    case 1:
      return 'gzip'
    case 0:
      return 'none'
    default:
      throw new Error(`unsupported compression flag ${flag}`)
  }
}

/**
 * @param {number} size
 * @param {Record<string, number>} headerStart
 * @param {Record<string, ArrayBuffer>} headerFields
 * @returns {Kdbx4Header}
 */
export const mapHeader = (size, headerStart, headerFields) => {
  const kdfParams = readKdfParams(headerFields.kdfParams)

  if (headerStart.signature1 !== 0x9AA2D903) {
    throw new Error('wrong signature filemagic')
  }

  if (headerStart.signature2 !== 0xB54BFB67) {
    throw new Error('wrong signature kdbx')
  }

  if (headerStart.versionMajor !== 4 || headerStart.versionMinor === undefined) {
    throw new Error(`wrong version: ${headerStart.versionMajor}.${headerStart.versionMinor}`)
  }

  if (!headerFields.encryptionIv) {
    throw new Error('no iv')
  }

  if (!headerFields.masterSeed) {
    throw new Error('no master seed')
  }

  return {
    size,
    signature1: headerStart.signature1,
    signature2: headerStart.signature2,
    versionMajor: headerStart.versionMajor,
    versionMinor: headerStart.versionMinor,
    cipherId: mapCipherId(headerFields.cipherId),
    compressionFlag: mapCompressionFlag(headerFields.compressionFlag),
    kdfParams: mapKdfParams(kdfParams),
    masterSeed: headerFields.masterSeed,
    encryptionIv: headerFields.encryptionIv,
  }
}

/**
 * @param {ArrayBuffer} buffer 
 */
export const getHeader = (buffer) => {
  const headerStart = readOuterHeaderStart(buffer);
  const [size, headerFields] = readOuterHeaderFields(buffer);
  return mapHeader(size, headerStart, headerFields);
}

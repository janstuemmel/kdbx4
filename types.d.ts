type KdfParamsAesKdf = {
  type: 'AES-KDF'
  R: number // Rounds
  S: ArrayBuffer // Seed
}

type KdfParamsArgon = {
  type: 'Argon2d' | 'Argon2id'
  S: ArrayBuffer // Salt
  P: number // Parallism
  M: number // Memory usage
  I: number // Iterations
  V: number // Argon2 version
  K?: ArrayBuffer // Key
  A?: ArrayBuffer // Associated data
}

type KdfParams = KdfParamsAesKdf | KdfParamsArgon

type Cipher = 'AES256-CBC' | 'CHACHA20'

type Compression = 'none' | 'gzip'

type Kdbx4Header = {
  size: number
  signature1: number
  signature2: number
  versionMinor: number
  versionMajor: number

  cipherId: string
  compressionFlag: Compression
  masterSeed: ArrayBuffer
  encryptionIv: ArrayBuffer

  kdfParams: KdfParams
  publicCustomData?: ArrayBuffer
}

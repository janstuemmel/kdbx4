# kdbx4

A browser-only kdbx4-only keepass fileformat parser/decryptor without dependecies written in pure ESM.

> Work in progress!

## Usage

```js
const file = /* ArrayBuffer */;
const pw = new TextEncoder().encode('your-secret')

const header = getHeader(file)
const keys = await computeKeys(compositeKey, header)
```

## Reference

* [Kdbx4 walkthrough](https://palant.info/2023/03/29/documenting-keepass-kdbx4-file-format)
* [Simulate ECB iteration for AES-KDF key stretching](https://crypto.stackexchange.com/questions/21048/can-i-simulate-iterated-aes-ecb-with-other-block-cipher-modes)

## License

MIT

export const base64ToBuffer = (s: string) =>
  Uint8Array.from(atob(s), c => c.codePointAt(0) ?? '').buffer;

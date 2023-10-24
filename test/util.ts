export const base64ToBuffer = (s: string) =>
  Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer;

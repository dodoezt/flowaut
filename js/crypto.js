export const encoder = new TextEncoder();
export const decoder = new TextDecoder();
const ITERATIONS = 310_000;

export function toBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function fromBase64Url(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export async function deriveKey(password, saltBase64) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: Uint8Array.from(atob(saltBase64), (c) => c.charCodeAt(0)), iterations: ITERATIONS, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
}

export async function encryptText(text, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(text));
  return { ciphertext: toBase64Url(new Uint8Array(data)), iv: toBase64Url(iv) };
}

export async function decryptText(record, key) {
  const data = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64Url(record.iv) }, key, fromBase64Url(record.ciphertext));
  return decoder.decode(data);
}

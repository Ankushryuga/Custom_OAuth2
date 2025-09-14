export function randomString(length=64) {
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return btoa(String.fromCharCode(...array)).replace(/[^a-zA-Z0-9]/g,'').slice(0, length)
}
export async function sha256(bytes) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bytes))
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')
}

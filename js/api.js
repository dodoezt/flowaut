let csrfToken = '';
export function setCsrfToken(token) { csrfToken = token; }

export async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && !(options.body instanceof ArrayBuffer)) headers.set('Content-Type', 'application/json');
  if (options.method && !['GET', 'HEAD'].includes(options.method)) headers.set('X-CSRF-Token', csrfToken);
  const response = await fetch(url, { ...options, headers, credentials: 'same-origin' });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || `Request failed (${response.status})`);
  return result;
}

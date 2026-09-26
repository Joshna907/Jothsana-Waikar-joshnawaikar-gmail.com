let accessToken = null;

export function setToken(token) {
  accessToken = token;
}

export function clearToken() {
  accessToken = null;
}

export async function api(path, { method = 'GET', body, auth = true } = {}) {
  const headers = body ? { 'content-type': 'application/json' } : {};
  if (auth && accessToken) headers.authorization = `Bearer ${accessToken}`;
  const response = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload?.error?.message || 'Request failed');
    error.code = payload?.error?.code;
    error.reason = payload?.error?.reason;
    throw error;
  }
  return payload;
}

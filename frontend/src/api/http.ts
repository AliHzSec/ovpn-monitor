// api/http.ts — fetch wrapper for the ovpn-monitor backend, modeled on
// 3x-ui's http-init.ts but trimmed: no base path (the panel is fixed at
// /panel, the portal at /) and no CSRF-token endpoint — the Go server injects
// the token into <meta name="csrf-token"> at runtime.

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);
const LOGIN_PATH = '/panel/login';

export class HttpError extends Error {
  status: number;
  response: { status: number; statusText: string; data: unknown };

  constructor(status: number, statusText: string, data: unknown) {
    super(`Request failed with status ${status}`);
    this.name = 'HttpError';
    this.status = status;
    this.response = { status, statusText, data };
  }
}

export interface HttpRequestOptions {
  headers?: Record<string, string> | Headers;
  params?: Record<string, unknown>;
  signal?: AbortSignal;
}

export function readCsrfToken(): string | null {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || null;
}

function encodeForm(data: unknown): string {
  if (data == null || typeof data !== 'object') return '';
  const parts: string[] = [];
  Object.entries(data as Record<string, unknown>).forEach(([key, value]) => {
    if (value === undefined) return;
    if (value === null) {
      parts.push(`${encodeURIComponent(key)}=`);
      return;
    }
    parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
  });
  return parts.join('&');
}

function appendQuery(url: string, params?: Record<string, unknown>): string {
  if (!params) return url;
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    query.set(key, String(value));
  });
  const qs = query.toString();
  return qs ? `${url}?${qs}` : url;
}

async function parseBody(res: Response): Promise<unknown> {
  if (res.status === 204 || res.status === 205) return '';
  const text = await res.text();
  if (text === '') return '';
  const contentType = (res.headers.get('content-type') || '').toLowerCase();
  if (contentType.includes('application/json') || text[0] === '{' || text[0] === '[') {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
  return text;
}

export async function httpRequest<T = unknown>(
  method: string,
  url: string,
  data?: unknown,
  options: HttpRequestOptions = {},
): Promise<T> {
  const upper = method.toUpperCase();
  const headers = new Headers(options.headers);
  headers.set('X-Requested-With', 'XMLHttpRequest');

  let body: BodyInit | undefined;
  if (!SAFE_METHODS.has(upper) && data !== undefined) {
    const declaredType = (headers.get('Content-Type') || '').toLowerCase();
    if (declaredType.startsWith('application/x-www-form-urlencoded')) {
      body = encodeForm(data);
    } else {
      headers.set('Content-Type', 'application/json');
      body = JSON.stringify(data);
    }
    const token = readCsrfToken();
    if (token) headers.set('X-CSRF-Token', token);
  }

  const res = await fetch(appendQuery(url, options.params), {
    method: upper,
    headers,
    body,
    credentials: 'same-origin',
    signal: options.signal,
  });

  // A 401 from the login POST itself means "bad credentials", not "session
  // expired" — let it reach the caller as an HttpError instead of redirecting
  // (we are already on the login page).
  if (res.status === 401 && url !== LOGIN_PATH) {
    window.location.href = LOGIN_PATH;
    return new Promise<T>(() => {});
  }

  const parsed = await parseBody(res);
  if (!res.ok) throw new HttpError(res.status, res.statusText, parsed);
  return parsed as T;
}

export function get<T = unknown>(url: string, options?: HttpRequestOptions): Promise<T> {
  return httpRequest<T>('GET', url, undefined, options);
}

export function post<T = unknown>(
  url: string,
  data?: unknown,
  options?: HttpRequestOptions,
): Promise<T> {
  return httpRequest<T>('POST', url, data, options);
}

export function postForm<T = unknown>(
  url: string,
  data?: unknown,
  options: HttpRequestOptions = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
  return httpRequest<T>('POST', url, data, { ...options, headers });
}

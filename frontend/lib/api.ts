/**
 * Fetch client for the backend.
 *
 * The access token lives only in memory, never in localStorage. The refresh
 * token is an HttpOnly cookie the browser manages; this module never reads
 * it, it only calls `/auth/refresh` with `credentials: "include"`.
 *
 * On a 401 from any call other than login or refresh, `apiFetch` refreshes
 * once and retries once.
 */

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

let accessToken: string | null = null;

export function getAccessToken(): string | null {
  return accessToken;
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

async function parseError(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body?.detail === "string") return body.detail;
  } catch {
    // body wasn't JSON - fall through to a generic message
  }
  return "Something went wrong. Please try again.";
}

interface RequestOptions extends RequestInit {
  /** Skip the automatic refresh-and-retry (used by /auth/refresh itself). */
  skipAuthRetry?: boolean;
}

async function rawFetch(path: string, options: RequestOptions = {}): Promise<Response> {
  const headers = new Headers(options.headers);
  headers.set("Content-Type", "application/json");
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);

  return fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: "include",
  });
}

let refreshPromise: Promise<boolean> | null = null;

/**
 * Attempt one silent refresh. Returns true if a new access token was obtained.
 * Never throws - a network error or non-2xx response resolves to false, same
 * as an outright refresh failure.
 *
 * Concurrent callers share a single in-flight refresh: the refresh cookie is
 * single-use and rotates on every call, so two independent refresh requests
 * racing on the same cookie would make the second one look like token reuse
 * and revoke the whole session.
 */
function tryRefresh(): Promise<boolean> {
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => {
    try {
      const res = await rawFetch("/api/auth/refresh", { method: "POST", skipAuthRetry: true });
      if (!res.ok) {
        setAccessToken(null);
        return false;
      }
      const body = await res.json();
      setAccessToken(body.access_token);
      return true;
    } catch {
      setAccessToken(null);
      return false;
    } finally {
      refreshPromise = null;
    }
  })();
  return refreshPromise;
}

/**
 * JSON request against the backend. Throws `ApiError` on any non-2xx
 * response (after the one allowed refresh-and-retry).
 */
export async function apiFetch<T>(path: string, options: RequestOptions = {}): Promise<T> {
  let res = await rawFetch(path, options);

  if (res.status === 401 && !options.skipAuthRetry) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      res = await rawFetch(path, options);
    }
  }

  if (!res.ok) {
    throw new ApiError(res.status, await parseError(res));
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// --- Auth endpoints ---

export interface User {
  id: string;
  email: string;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export function register(email: string, password: string): Promise<User> {
  return apiFetch<User>("/api/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password }),
    skipAuthRetry: true,
  });
}

export async function login(email: string, password: string): Promise<User> {
  const tokens = await apiFetch<TokenResponse>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
    skipAuthRetry: true,
  });
  setAccessToken(tokens.access_token);
  return apiFetch<User>("/api/auth/me");
}

/** Silent session restore on page load, via the HttpOnly refresh cookie. */
export async function restoreSession(): Promise<User | null> {
  const ok = await tryRefresh();
  if (!ok) return null;
  try {
    return await apiFetch<User>("/api/auth/me");
  } catch {
    return null;
  }
}

export async function logout(): Promise<void> {
  try {
    await apiFetch<void>("/api/auth/logout", { method: "POST" });
  } finally {
    setAccessToken(null);
  }
}

// --- Captures ---

export interface Capture {
  name: string;
  host: string;
  scenario: string | null;
  synthetic: boolean;
  event_count: number;
}

export function listCaptures(): Promise<Capture[]> {
  return apiFetch<Capture[]>("/api/captures");
}

// --- Incidents ---

export type Severity = "low" | "medium" | "high" | "critical";
export type Verdict = "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "INSUFFICIENT_EVIDENCE";

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: string;
  capture_id: string;
  anchor_process_guid: string | null;
  verdict: Verdict | null;
  confidence: number | null;
  created_at: string;
}

export interface IncidentCreatePayload {
  title: string;
  description?: string;
  severity: Severity;
  capture_name: string;
  anchor_process_guid?: string | null;
}

export function listIncidents(): Promise<Incident[]> {
  return apiFetch<Incident[]>("/api/incidents");
}

export function createIncident(payload: IncidentCreatePayload): Promise<Incident> {
  return apiFetch<Incident>("/api/incidents", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getIncident(incidentId: string): Promise<Incident> {
  return apiFetch<Incident>(`/api/incidents/${incidentId}`);
}

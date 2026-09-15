/**
 * A "probably logged in" flag that `proxy.ts` can read.
 *
 * The real refresh token is an HttpOnly cookie set by the backend for its own
 * origin, so the Next.js server never sees it. This cookie holds no secret,
 * only its presence matters, and it is set and cleared alongside the
 * in-memory access token. It lets `proxy.ts` redirect a visitor who is plainly
 * logged out without a network round trip. It is not proof of anything: every
 * protected page still calls the backend, which does the real check.
 */

const HINT_COOKIE = "warrant_session_hint";

export function setSessionHint(): void {
  if (typeof document === "undefined") return;
  document.cookie = `${HINT_COOKIE}=1; path=/; samesite=lax; max-age=${60 * 60 * 24 * 14}`;
}

export function clearSessionHint(): void {
  if (typeof document === "undefined") return;
  document.cookie = `${HINT_COOKIE}=; path=/; samesite=lax; max-age=0`;
}

export const SESSION_HINT_COOKIE = HINT_COOKIE;

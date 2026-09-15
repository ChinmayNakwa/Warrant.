import { NextRequest, NextResponse } from "next/server";

import { SESSION_HINT_COOKIE } from "./lib/session-hint";

const PROTECTED_PREFIXES = ["/incidents"];
const AUTH_PAGES = ["/login", "/signup"];

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const hasSessionHint = request.cookies.has(SESSION_HINT_COOKIE);

  const isProtected = PROTECTED_PREFIXES.some(
    (p) => pathname === p || pathname.startsWith(`${p}/`),
  );
  if (isProtected && !hasSessionHint) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    url.searchParams.set("from", pathname);
    return NextResponse.redirect(url);
  }

  const isAuthPage = AUTH_PAGES.some((p) => pathname === p);
  if (isAuthPage && hasSessionHint) {
    const url = request.nextUrl.clone();
    url.pathname = "/incidents";
    url.search = "";
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/incidents/:path*",
    "/login",
    "/signup",
  ],
};

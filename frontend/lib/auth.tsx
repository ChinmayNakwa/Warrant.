"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { ApiError, login as apiLogin, logout as apiLogout, register as apiRegister, restoreSession, type User } from "./api";
import { clearSessionHint, setSessionHint } from "./session-hint";

type Status = "loading" | "authenticated" | "unauthenticated";

interface AuthContextValue {
  user: User | null;
  status: Status;
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [status, setStatus] = useState<Status>("loading");

  useEffect(() => {
    let cancelled = false;
    restoreSession()
      .then((restored) => {
        if (cancelled) return;
        if (restored) {
          setUser(restored);
          setSessionHint();
          setStatus("authenticated");
        } else {
          clearSessionHint();
          setStatus("unauthenticated");
        }
      })
      .catch(() => {
        // restoreSession does not throw, but if it ever did, staying on
        // "loading" would leave every protected page on a spinner.
        if (cancelled) return;
        clearSessionHint();
        setStatus("unauthenticated");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const loggedIn = await apiLogin(email, password);
    setUser(loggedIn);
    setSessionHint();
    setStatus("authenticated");
  }, []);

  const signup = useCallback(async (email: string, password: string) => {
    await apiRegister(email, password);
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    setUser(null);
    clearSessionHint();
    setStatus("unauthenticated");
  }, []);

  const value = useMemo(
    () => ({ user, status, login, signup, logout }),
    [user, status, login, signup, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}

export { ApiError };

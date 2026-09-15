"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState, type FormEvent } from "react";

import { ApiError, useAuth } from "@/lib/auth";

function LoginForm() {
  const { login } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email, password);
      router.push(searchParams.get("from") || "/");
    } catch (err) {
      // The backend's message is generic on purpose: it never says which field was wrong.
      setError(err instanceof ApiError ? err.detail : "Something went wrong. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex flex-1 items-center justify-center px-6">
      <div className="w-full max-w-sm">
        <h1 className="mb-6 text-2xl font-semibold text-ink">Log in</h1>
        {searchParams.get("registered") === "1" && (
          <p className="mb-4 rounded-md bg-green-50 px-3 py-2 text-sm text-green-800 dark:bg-green-950 dark:text-green-300">
            Account created. Log in to continue.
          </p>
        )}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <label className="flex flex-col gap-1 text-sm text-ink-secondary">
            Email
            <input
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="rounded-md border border-line-strong bg-surface px-3 py-2 text-ink outline-none focus:border-accent"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm text-ink-secondary">
            Password
            <input
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="rounded-md border border-line-strong bg-surface px-3 py-2 text-ink outline-none focus:border-accent"
            />
          </label>
          {error && (
            <p data-testid="form-error" role="alert" className="text-sm text-red-600 dark:text-red-400">
              {error}
            </p>
          )}
          <button
            type="submit"
            disabled={submitting}
            className="mt-2 h-11 rounded-md bg-accent font-medium text-on-accent transition-opacity hover:opacity-90 disabled:opacity-60"
          >
            {submitting ? "Logging in…" : "Log in"}
          </button>
        </form>
        <p className="mt-6 text-sm text-ink-muted">
          Don&apos;t have an account?{" "}
          <Link href="/signup" className="font-medium text-accent underline">
            Sign up
          </Link>
        </p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}

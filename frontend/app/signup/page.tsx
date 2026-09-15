"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

import { ApiError, useAuth } from "@/lib/auth";

export default function SignupPage() {
  const { signup } = useAuth();
  const router = useRouter();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await signup(email, password);
      router.push("/login?registered=1");
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Something went wrong. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex flex-1 items-center justify-center px-6">
      <div className="w-full max-w-sm">
        <h1 className="mb-6 text-2xl font-semibold text-ink">Sign up</h1>
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
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="rounded-md border border-line-strong bg-surface px-3 py-2 text-ink outline-none focus:border-accent"
            />
            <span className="text-xs text-ink-muted">
              At least 10 characters, with a letter and a digit.
            </span>
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
            {submitting ? "Creating account…" : "Sign up"}
          </button>
        </form>
        <p className="mt-6 text-sm text-ink-muted">
          Already have an account?{" "}
          <Link href="/login" className="font-medium text-accent underline">
            Log in
          </Link>
        </p>
      </div>
    </div>
  );
}

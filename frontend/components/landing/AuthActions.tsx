"use client";

import { ArrowRight } from "lucide-react";
import Link from "next/link";

import { useAuth } from "@/lib/auth";

const SIZES = {
  sm: "h-9 px-4 text-sm",
  lg: "h-12 px-6 text-base",
};

const BUTTON =
  "inline-flex items-center justify-center gap-2 rounded-md font-medium transition active:scale-[0.98]";
const PRIMARY = `${BUTTON} bg-accent text-on-accent hover:opacity-90`;
const SECONDARY = `${BUTTON} border border-line-strong text-ink hover:bg-sunken`;

/**
 * Sign up and log in for a visitor, one link to the dashboard for someone
 * already signed in. Hidden but still taking up its space while the session is
 * being restored, so the page does not jump when the answer arrives.
 */
export function AuthActions({ size = "lg", className = "" }: { size?: keyof typeof SIZES; className?: string }) {
  const { status } = useAuth();

  return (
    <div
      className={`flex items-center gap-3 transition-opacity duration-300 ${
        status === "loading" ? "opacity-0" : "opacity-100"
      } ${className}`}
    >
      {status === "authenticated" ? (
        <Link href="/dashboard" className={`${PRIMARY} ${SIZES[size]} group`}>
          Go to dashboard
          <ArrowRight aria-hidden="true" className="size-4 transition-transform group-hover:translate-x-0.5" />
        </Link>
      ) : (
        <>
          <Link href="/login" className={`${SECONDARY} ${SIZES[size]}`}>
            Log in
          </Link>
          <Link href="/signup" className={`${PRIMARY} ${SIZES[size]} group`}>
            Sign up
            <ArrowRight aria-hidden="true" className="size-4 transition-transform group-hover:translate-x-0.5" />
          </Link>
        </>
      )}
    </div>
  );
}

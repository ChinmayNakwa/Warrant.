"use client";

import { Eye, EyeOff, LoaderCircle } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useId, useState, type ReactNode } from "react";

export const FIELD =
  "rounded-md border border-line-strong bg-surface px-3 py-2 text-ink outline-none transition-shadow focus:border-accent focus:ring-2 focus:ring-accent-soft";

/** A form's error line. It opens and closes instead of jumping in. */
export function FormError({ message }: { message: string | null }) {
  return (
    <AnimatePresence>
      {message && (
        <motion.p
          data-testid="form-error"
          role="alert"
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          exit={{ opacity: 0, height: 0 }}
          className="overflow-hidden text-sm text-red-600 dark:text-red-400"
        >
          {message}
        </motion.p>
      )}
    </AnimatePresence>
  );
}

/** The form's submit button, with a spinner and its own label while the request is out. */
export function SubmitButton({
  busy,
  busyLabel,
  disabled = false,
  children,
}: {
  busy: boolean;
  busyLabel: string;
  disabled?: boolean;
  children: ReactNode;
}) {
  return (
    <button
      type="submit"
      disabled={busy || disabled}
      className="mt-2 inline-flex h-11 items-center justify-center gap-2 rounded-md bg-accent font-medium text-on-accent transition hover:opacity-90 active:scale-[0.98] disabled:opacity-60"
    >
      {busy && <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />}
      {busy ? busyLabel : children}
    </button>
  );
}

/** A password box with a button to show what was typed. */
export function PasswordField({
  value,
  onChange,
  autoComplete,
  hint,
}: {
  value: string;
  onChange: (value: string) => void;
  autoComplete: "current-password" | "new-password";
  hint?: string;
}) {
  const id = useId();
  const [shown, setShown] = useState(false);
  const Icon = shown ? EyeOff : Eye;

  return (
    <div className="flex flex-col gap-1 text-sm text-ink-secondary">
      <label htmlFor={id}>Password</label>
      <div className="relative flex">
        <input
          id={id}
          type={shown ? "text" : "password"}
          required
          autoComplete={autoComplete}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          aria-describedby={hint ? `${id}-hint` : undefined}
          className={`${FIELD} w-full pr-10`}
        />
        <button
          type="button"
          onClick={() => setShown((s) => !s)}
          aria-label={shown ? "Hide password" : "Show password"}
          aria-pressed={shown}
          className="absolute inset-y-0 right-0 flex w-10 items-center justify-center text-ink-muted transition-colors hover:text-ink"
        >
          <Icon aria-hidden="true" className="size-4" />
        </button>
      </div>
      {hint && (
        <span id={`${id}-hint`} className="text-xs text-ink-muted">
          {hint}
        </span>
      )}
    </div>
  );
}

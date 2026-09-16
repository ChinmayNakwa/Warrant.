"use client";

import { animate, motion, useReducedMotion, type Variants } from "motion/react";
import { useEffect, useState, type ReactNode } from "react";

// One easing and one distance for every entrance, so the pages move alike.
// `Providers` sets `reducedMotion="user"`, which keeps the fades and drops the
// movement for anyone who asked their system for less motion.
export const EASE = [0.22, 1, 0.36, 1] as const;
const RISE = 12;

const ITEM: Variants = {
  hidden: { opacity: 0, y: RISE },
  shown: { opacity: 1, y: 0, transition: { duration: 0.45, ease: EASE } },
};

const VIEWPORT = { once: true, margin: "0px 0px -10% 0px" } as const;

/** Fades its children up the first time they scroll into view. */
export function Reveal({
  children,
  className,
  delay = 0,
}: {
  children: ReactNode;
  className?: string;
  delay?: number;
}) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: RISE }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={VIEWPORT}
      transition={{ duration: 0.45, ease: EASE, delay }}
    >
      {children}
    </motion.div>
  );
}

/** Reveals its `StaggerItem` children one after another. */
export function Stagger({
  children,
  className,
  as = "div",
}: {
  children: ReactNode;
  className?: string;
  as?: "div" | "ul" | "section";
}) {
  const Tag = motion[as];
  return (
    <Tag
      className={className}
      initial="hidden"
      whileInView="shown"
      viewport={VIEWPORT}
      variants={{ hidden: {}, shown: { transition: { staggerChildren: 0.06 } } }}
    >
      {children}
    </Tag>
  );
}

export function StaggerItem({
  children,
  className,
  as = "div",
}: {
  children: ReactNode;
  className?: string;
  as?: "div" | "li";
}) {
  const Tag = motion[as];
  return (
    <Tag className={className} variants={ITEM}>
      {children}
    </Tag>
  );
}

/**
 * Counts up to `value` once, when it mounts. The number shown at the end is
 * `value` exactly; with reduced motion it is shown straight away.
 */
export function CountUp({ value }: { value: number }) {
  const still = useReducedMotion();
  const [shown, setShown] = useState(0);

  useEffect(() => {
    if (still) return;
    const controls = animate(0, value, {
      duration: 0.7,
      ease: EASE,
      onUpdate: (latest) => setShown(Math.round(latest)),
    });
    return () => controls.stop();
  }, [value, still]);

  return <span className="tabular-nums">{still ? value : shown}</span>;
}

/** A grey block that stands in for content while it loads. */
export function Skeleton({ className = "" }: { className?: string }) {
  return <div aria-hidden="true" className={`animate-pulse rounded-md bg-sunken ${className}`} />;
}

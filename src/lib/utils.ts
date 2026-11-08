import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/** Last path segment of a (possibly `/`- or `\`-separated) file path. */
export function basename(p: string): string {
  const norm = p.replace(/\\/g, "/")
  const parts = norm.split("/")
  return parts[parts.length - 1] || p
}

/** The text of a backend error, which arrives as an Error or as a plain string. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

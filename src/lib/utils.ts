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

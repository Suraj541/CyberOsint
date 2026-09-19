/**
 * Deterministic, SSR-safe date and text formatting utilities.
 * Ensures consistent output between Node.js SSR and client hydration.
 * Conforms to zero-hydration mismatch requirement.
 */

const MONTHS = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
];

export function parseValidDate(val?: string | Date | null): Date | null {
  if (!val) return null;
  const d = typeof val === "string" ? new Date(val) : val;
  return isNaN(d.getTime()) ? null : d;
}

export function formatDate(val?: string | Date | null, fallback: string = "Recent"): string {
  const d = parseValidDate(val);
  if (!d) return fallback;
  const month = MONTHS[d.getUTCMonth()];
  const day = d.getUTCDate();
  const year = d.getUTCFullYear();
  return `${month} ${day}, ${year}`;
}

export function formatTime(val?: string | Date | null, fallback: string = "—"): string {
  const d = parseValidDate(val);
  if (!d) return fallback;
  const h24 = d.getUTCHours();
  const m = String(d.getUTCMinutes()).padStart(2, "0");
  const s = String(d.getUTCSeconds()).padStart(2, "0");
  const ampm = h24 >= 12 ? "PM" : "AM";
  const h12 = h24 % 12 || 12;
  return `${String(h12).padStart(2, "0")}:${m}:${s} ${ampm} UTC`;
}

export function formatDateTime(val?: string | Date | null, fallback: string = "Undated"): string {
  const d = parseValidDate(val);
  if (!d) return fallback;
  const dateStr = formatDate(d, fallback);
  const h24 = d.getUTCHours();
  const m = String(d.getUTCMinutes()).padStart(2, "0");
  const ampm = h24 >= 12 ? "PM" : "AM";
  const h12 = h24 % 12 || 12;
  return `${dateStr}, ${String(h12).padStart(2, "0")}:${m} ${ampm} UTC`;
}

export function safeUpper(val?: string | null, fallback: string = ""): string {
  if (typeof val !== "string" || !val) return fallback.toUpperCase();
  return val.toUpperCase();
}

export function safeLower(val?: string | null, fallback: string = ""): string {
  if (typeof val !== "string" || !val) return fallback.toLowerCase();
  return val.toLowerCase();
}

export function safeTrim(val?: string | null, fallback: string = ""): string {
  if (typeof val !== "string" || !val) return fallback;
  return val.trim();
}

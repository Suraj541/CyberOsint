import { redirect } from "next/navigation";

/**
 * Video Feature Removed
 * Any direct navigation to /videos redirects directly to the primary OSINT intelligence dashboard.
 */
export default function VideosPage() {
  redirect("/");
}

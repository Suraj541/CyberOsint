import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "../components/Sidebar";
import { Navbar } from "../components/Navbar";

export const metadata: Metadata = {
  title: "Cybersecurity OSINT Intelligence Platform",
  description:
    "Production-grade Open Source Threat Intelligence aggregation, entity extraction, full-text and hybrid semantic search engine.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="bg-[#F7F3E8] text-[#171714] min-h-screen flex flex-row antialiased selection:bg-[#C2821A]/20 selection:text-[#171714]">
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0 min-h-screen">
          <Navbar />
          <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto">{children}</main>
        </div>
      </body>
    </html>
  );
}

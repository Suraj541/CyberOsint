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
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function() {
              try {
                var stored = localStorage.getItem('theme');
                var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                if (stored === 'dark' || (!stored && prefersDark)) {
                  document.documentElement.classList.add('dark');
                  document.documentElement.setAttribute('data-theme', 'dark');
                } else {
                  document.documentElement.classList.remove('dark');
                  document.documentElement.setAttribute('data-theme', 'light');
                }
              } catch(e) {}
            })();`,
          }}
        />
      </head>
      <body className="bg-[#F7F3E8] dark:bg-[#08090C] text-[#171714] dark:text-[#F8FAFC] min-h-screen flex flex-row antialiased selection:bg-[#C2821A]/20 selection:text-[#171714] dark:selection:text-[#F8FAFC] transition-colors duration-200">
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0 min-h-screen">
          <Navbar />
          <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto">{children}</main>
        </div>
      </body>
    </html>
  );
}

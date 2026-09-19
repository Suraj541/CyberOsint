"use client";

import React, { useEffect, useState } from "react";

export const ThemeToggle: React.FC<{ className?: string }> = ({ className = "" }) => {
  const [theme, setTheme] = useState<"light" | "dark">("light");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    // 1. Check local storage or system preference
    const stored = localStorage.getItem("theme") as "light" | "dark" | null;
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const initialTheme = stored ? stored : prefersDark ? "dark" : "light";

    setTheme(initialTheme);
    if (initialTheme === "dark") {
      document.documentElement.classList.add("dark");
      document.documentElement.setAttribute("data-theme", "dark");
    } else {
      document.documentElement.classList.remove("dark");
      document.documentElement.setAttribute("data-theme", "light");
    }
    setMounted(true);
  }, []);

  const toggleTheme = () => {
    const nextTheme = theme === "dark" ? "light" : "dark";
    setTheme(nextTheme);
    localStorage.setItem("theme", nextTheme);

    if (nextTheme === "dark") {
      document.documentElement.classList.add("dark");
      document.documentElement.setAttribute("data-theme", "dark");
    } else {
      document.documentElement.classList.remove("dark");
      document.documentElement.setAttribute("data-theme", "light");
    }
  };

  if (!mounted) {
    // Render placeholder with same dimensions to prevent layout shift
    return (
      <div className={`w-9 h-9 rounded-lg bg-[#F1EBD8] dark:bg-[#161B26] border border-[#E4DBC8] dark:border-[#2D3446] ${className}`} />
    );
  }

  return (
    <button
      onClick={toggleTheme}
      type="button"
      className={`relative p-2 rounded-lg bg-[#F1EBD8] hover:bg-[#EAE3CE] dark:bg-[#161B26] dark:hover:bg-[#1F2636] border border-[#E4DBC8] dark:border-[#2D3446] text-[#171714] dark:text-[#F8FAFC] transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-[#C2821A] group ${className}`}
      title={theme === "dark" ? "Switch to Light Mode" : "Switch to Night Mode"}
      aria-label={theme === "dark" ? "Switch to Light Mode" : "Switch to Night Mode"}
    >
      <span className="sr-only">Toggle theme</span>
      {theme === "dark" ? (
        // Sun Icon for switching to light
        <svg
          className="w-4 h-4 text-[#E5A93B] group-hover:rotate-45 transition-transform duration-300"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <circle cx="12" cy="12" r="5" />
          <line x1="12" y1="1" x2="12" y2="3" />
          <line x1="12" y1="21" x2="12" y2="23" />
          <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
          <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
          <line x1="1" y1="12" x2="3" y2="12" />
          <line x1="21" y1="12" x2="23" y2="12" />
          <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
          <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
        </svg>
      ) : (
        // Moon Icon for switching to dark
        <svg
          className="w-4 h-4 text-[#68655B] group-hover:-rotate-12 transition-transform duration-300"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
      )}
    </button>
  );
};

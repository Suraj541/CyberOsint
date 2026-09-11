import React, { useState } from "react";

interface Props {
  initialQuery?: string;
  initialMode?: "hybrid" | "keyword";
  onSearch: (query: string, mode: "hybrid" | "keyword") => void;
  placeholder?: string;
}

export const SearchBar: React.FC<Props> = ({
  initialQuery = "",
  initialMode = "hybrid",
  onSearch,
  placeholder = "Search threats, CVEs, malware, threat actors, zero-days...",
}) => {
  const [query, setQuery] = useState(initialQuery);
  const [mode, setMode] = useState<"hybrid" | "keyword">(initialMode);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSearch(query.trim(), mode);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <div className="flex flex-col sm:flex-row items-center gap-2 p-1.5 rounded-xl bg-slate-900/90 border border-slate-700/80 shadow-lg backdrop-blur-md focus-within:border-cyan-500/80 transition-all">
        {/* Search Input */}
        <div className="flex items-center gap-3 flex-1 px-3 w-full">
          <span className="text-cyan-400 font-mono text-base">⌕</span>
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={placeholder}
            className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none py-2"
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery("")}
              className="text-slate-500 hover:text-slate-300 text-xs font-mono"
            >
              ✕
            </button>
          )}
        </div>

        {/* Mode Selector & Submit */}
        <div className="flex items-center gap-1.5 w-full sm:w-auto justify-end px-2 pb-1 sm:pb-0">
          <div className="flex bg-slate-950/80 p-0.5 rounded-lg border border-slate-800 text-xs font-mono">
            <button
              type="button"
              onClick={() => setMode("hybrid")}
              className={`px-2.5 py-1 rounded-md transition-all ${
                mode === "hybrid"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Hybrid (RRF)
            </button>
            <button
              type="button"
              onClick={() => setMode("keyword")}
              className={`px-2.5 py-1 rounded-md transition-all ${
                mode === "keyword"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Keyword
            </button>
          </div>

          <button
            type="submit"
            className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono transition-colors shadow-sm"
          >
            Search
          </button>
        </div>
      </div>
    </form>
  );
};

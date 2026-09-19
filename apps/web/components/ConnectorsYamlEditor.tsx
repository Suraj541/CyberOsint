"use client";

import React, { useEffect, useState } from "react";
import {
  fetchConnectorsYamlConfig,
  fetchRawConnectorsYaml,
  reloadConnectorsYaml,
  saveRawConnectorsYaml,
  updateSingleConnectorYaml,
} from "../lib/api";
import { ConnectorYamlConfigItem } from "../lib/types";
import { formatTime, safeUpper } from "../lib/formatters";

export function ConnectorsYamlEditor() {
  const [viewMode, setViewMode] = useState<"visual" | "raw">("visual");
  const [yamlText, setYamlText] = useState<string>("");
  const [originalYaml, setOriginalYaml] = useState<string>("");
  const [parsedItems, setParsedItems] = useState<ConnectorYamlConfigItem[]>([]);
  const [lastLoadedAt, setLastLoadedAt] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [reloading, setReloading] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<{
    type: "success" | "error" | "info";
    text: string;
  } | null>(null);
  const [secretWarning, setSecretWarning] = useState<string | null>(null);

  // Client-side quick check for potential raw secrets in editor
  const checkClientSecrets = (text: string) => {
    if (/ghp_[A-Za-z0-9_]{20,}/.test(text)) {
      return "Security Warning: Potential GitHub Personal Access Token detected! Use ${GITHUB_TOKEN} or api_key_env instead.";
    }
    if (/(?:api_key|token|secret)\s*:\s*["'][A-Za-z0-9_\-\.]{24,}["']/.test(text)) {
      return "Security Warning: Potential hardcoded secret detected. Never hardcode API keys per IMPLEMENT.md Section 35.";
    }
    return null;
  };

  const loadAll = async () => {
    setLoading(true);
    setStatusMessage(null);
    try {
      const [parsedData, rawData] = await Promise.all([
        fetchConnectorsYamlConfig(),
        fetchRawConnectorsYaml(),
      ]);
      setParsedItems(parsedData.connectors || []);
      setYamlText(rawData.yaml_content || "");
      setOriginalYaml(rawData.yaml_content || "");
      setLastLoadedAt(rawData.last_loaded_at || new Date().toISOString());
      setSecretWarning(checkClientSecrets(rawData.yaml_content || ""));
    } catch (err: any) {
      setStatusMessage({
        type: "error",
        text: `Failed to load configuration: ${err.message}`,
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  const handleYamlChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const val = e.target.value;
    setYamlText(val);
    setSecretWarning(checkClientSecrets(val));
  };

  const handleSaveRaw = async () => {
    const warning = checkClientSecrets(yamlText);
    if (warning) {
      if (!confirm(`${warning}\n\nDo you still wish to attempt saving?`)) {
        return;
      }
    }

    setSaving(true);
    setStatusMessage(null);
    try {
      const res = await saveRawConnectorsYaml(yamlText);
      setStatusMessage({
        type: "success",
        text: `${res.message} (Synced ${res.synced_to_runtime} runtime categories)`,
      });
      setOriginalYaml(yamlText);
      // Refresh parsed view
      const parsedData = await fetchConnectorsYamlConfig();
      setParsedItems(parsedData.connectors || []);
      setLastLoadedAt(res.reloaded_at);
    } catch (err: any) {
      setStatusMessage({
        type: "error",
        text: `Save rejected: ${err.message}`,
      });
    } finally {
      setSaving(false);
    }
  };

  const handleReloadRuntime = async () => {
    setReloading(true);
    setStatusMessage(null);
    try {
      const res = await reloadConnectorsYaml();
      setStatusMessage({
        type: "success",
        text: `Hot-reload successful: ${res.total_loaded} connectors loaded, ${res.synced_to_runtime} runtime categories synchronized.`,
      });
      setLastLoadedAt(res.reloaded_at);
      const parsedData = await fetchConnectorsYamlConfig();
      setParsedItems(parsedData.connectors || []);
    } catch (err: any) {
      setStatusMessage({
        type: "error",
        text: `Hot-reload failed: ${err.message}`,
      });
    } finally {
      setReloading(false);
    }
  };

  const handleToggleItem = async (key: string, currentEnabled: boolean) => {
    try {
      await updateSingleConnectorYaml(key, { enabled: !currentEnabled });
      await loadAll();
      setStatusMessage({
        type: "success",
        text: `Connector '${key}' ${!currentEnabled ? "enabled" : "disabled"} and synced.`,
      });
    } catch (err: any) {
      setStatusMessage({
        type: "error",
        text: `Failed to toggle '${key}': ${err.message}`,
      });
    }
  };

  const isDirty = yamlText !== originalYaml;

  return (
    <div className="space-y-6">
      {/* Top Banner: IMPLEMENT.md Section 35 Policy */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-amber-950/40 via-slate-900 to-slate-900 border border-amber-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-lg">
        <div className="flex items-start gap-3">
          <span className="text-2xl">🔒</span>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-amber-400 uppercase tracking-wider">
                IMPLEMENT.md Section 35 (Step 34)
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                Rule: Never Hardcode API Keys
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1 max-w-2xl">
              Declarative configuration via <code className="text-cyan-300 font-mono">connectors.yaml</code>.
              Credentials must reference environment variables using <code className="text-cyan-300 font-mono">api_key_env: &quot;VAR_NAME&quot;</code> or{" "}
              <code className="text-cyan-300 font-mono">&quot;${`{VAR_NAME:-default}`}&quot;</code>. The backend actively rejects raw tokens.
            </p>
          </div>
        </div>

        {/* View Switcher & Action Buttons */}
        <div className="flex flex-wrap items-center gap-2 self-stretch md:self-auto">
          <div className="flex items-center p-1 rounded-lg bg-slate-950 border border-slate-800">
            <button
              onClick={() => setViewMode("visual")}
              className={`px-3 py-1.5 rounded text-xs font-mono transition-all flex items-center gap-1.5 ${
                viewMode === "visual"
                  ? "bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <span>📊</span>
              <span>Visual Overview</span>
            </button>
            <button
              onClick={() => setViewMode("raw")}
              className={`px-3 py-1.5 rounded text-xs font-mono transition-all flex items-center gap-1.5 ${
                viewMode === "raw"
                  ? "bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <span>📝</span>
              <span>YAML Editor</span>
              {isDirty && <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />}
            </button>
          </div>

          <button
            onClick={handleReloadRuntime}
            disabled={reloading || loading}
            className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-300 text-xs font-mono transition-colors flex items-center gap-1.5 shadow-sm"
            title="Hot-reload connectors.yaml into runtime connector coordinator"
          >
            <span className={reloading ? "animate-spin" : ""}>⚡</span>
            <span>{reloading ? "Reloading..." : "Hot-Reload Manager"}</span>
          </button>
        </div>
      </div>

      {/* Secret Warning Banner if triggered */}
      {secretWarning && (
        <div className="p-3.5 rounded-xl bg-rose-950/50 border border-rose-500/50 flex items-center gap-3 text-rose-300 text-xs font-mono animate-in fade-in">
          <span className="text-lg">⚠️</span>
          <span className="flex-1">{secretWarning}</span>
        </div>
      )}

      {/* Status Notification */}
      {statusMessage && (
        <div
          className={`p-3.5 rounded-xl text-xs font-mono flex items-center justify-between gap-3 animate-in fade-in ${
            statusMessage.type === "success"
              ? "bg-emerald-950/50 border border-emerald-500/40 text-emerald-300"
              : statusMessage.type === "error"
              ? "bg-rose-950/50 border border-rose-500/40 text-rose-300"
              : "bg-blue-950/50 border border-blue-500/40 text-blue-300"
          }`}
        >
          <span>{statusMessage.text}</span>
          <button
            onClick={() => setStatusMessage(null)}
            className="text-slate-400 hover:text-white text-sm"
          >
            ✕
          </button>
        </div>
      )}

      {/* Content Area */}
      {loading ? (
        <div className="p-12 text-center text-slate-400 font-mono text-xs animate-pulse">
          Loading connectors.yaml configuration...
        </div>
      ) : viewMode === "visual" ? (
        /* Visual Overview Mode */
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono px-1">
            <span>
              Configured Sources: <strong className="text-white">{parsedItems.length}</strong>
            </span>
            <span>
              Last Loaded:{" "}
              <strong className="text-slate-300">
                {formatTime(lastLoadedAt, "N/A")}
              </strong>
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {parsedItems.map((item) => {
              const priorityColors: Record<string, string> = {
                critical: "bg-rose-500/20 text-rose-300 border-rose-500/30",
                high: "bg-amber-500/20 text-amber-300 border-amber-500/30",
                medium: "bg-blue-500/20 text-blue-300 border-blue-500/30",
                low: "bg-slate-500/20 text-slate-300 border-slate-500/30",
              };
              const badgeClass =
                priorityColors[(item.priority || "").toLowerCase()] || priorityColors.medium;

              return (
                <div
                  key={item.key}
                  className={`p-4 rounded-xl border transition-all duration-200 ${
                    item.enabled
                      ? "bg-slate-900/80 border-slate-800 hover:border-slate-700 shadow-md"
                      : "bg-slate-950/40 border-slate-900/60 opacity-60"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-bold text-white truncate">
                          {item.key}
                        </span>
                      </div>
                      <span className="text-[11px] font-mono text-cyan-400">
                        {safeUpper(item.type)}
                        {item.category && ` · ${item.category}`}
                      </span>
                    </div>

                    <button
                      onClick={() => handleToggleItem(item.key, item.enabled)}
                      className={`px-2.5 py-1 rounded text-[11px] font-mono font-bold transition-all ${
                        item.enabled
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30"
                          : "bg-slate-800 text-slate-400 border border-slate-700 hover:bg-slate-700 hover:text-white"
                      }`}
                    >
                      {item.enabled ? "ENABLED" : "DISABLED"}
                    </button>
                  </div>

                  <p className="text-xs text-slate-300 mt-2 line-clamp-2">
                    {item.description || "No description provided."}
                  </p>

                  <div className="mt-3 pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-2 text-[10px] font-mono">
                    <span className={`px-2 py-0.5 rounded border ${badgeClass}`}>
                      {safeUpper(item.priority)}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      ⏱ {item.interval_minutes}m interval
                    </span>
                    {item.api_key_env && (
                      <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                        🔑 env:{item.api_key_env}
                      </span>
                    )}
                  </div>

                  {item.url && (
                    <div className="mt-2 text-[10px] font-mono text-slate-400 truncate bg-slate-950 px-2 py-1 rounded border border-slate-800/60">
                      🔗 {item.url}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        /* Raw YAML Editor Mode */
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-slate-900/90 p-3 rounded-xl border border-slate-800">
            <div className="text-xs font-mono text-slate-400 flex items-center gap-2">
              <span>File: <strong className="text-cyan-300">connectors.yaml</strong></span>
              {isDirty && (
                <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 text-[10px] border border-amber-500/30">
                  Unsaved Changes
                </span>
              )}
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  setYamlText(originalYaml);
                  setSecretWarning(checkClientSecrets(originalYaml));
                }}
                disabled={!isDirty || saving}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition-colors disabled:opacity-40"
              >
                Reset
              </button>
              <button
                onClick={handleSaveRaw}
                disabled={!isDirty || saving}
                className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition-colors shadow-sm disabled:opacity-40 flex items-center gap-1.5"
              >
                <span>{saving ? "Saving..." : "Save & Synchronize"}</span>
              </button>
            </div>
          </div>

          <div className="relative rounded-xl overflow-hidden border border-slate-800 bg-slate-950">
            <textarea
              value={yamlText}
              onChange={handleYamlChange}
              spellCheck={false}
              rows={22}
              className="w-full p-4 bg-slate-950 text-slate-200 font-mono text-xs leading-relaxed focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-y"
              placeholder="connectors:\n  example_feed:\n    enabled: true\n    type: rss\n    url: 'https://example.com/feed.xml'\n    interval_minutes: 30\n    priority: high"
            />
          </div>

          <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between px-1">
            <span>
              💡 Tip: Environment variables such as <code className="text-cyan-300">${`{GITHUB_TOKEN}`}</code> or <code className="text-cyan-300">${`{VAR:-default}`}</code> are safely expanded at runtime.
            </span>
            <span>Strict YAML syntax required</span>
          </div>
        </div>
      )}
    </div>
  );
}

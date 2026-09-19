"use client";

import React, { useEffect, useState } from "react";
import {
  fetchSecretsAudit,
  fetchSecretsStatus,
  verifySecret,
  fetchManageableSecrets,
  saveApiKeys,
  testApiKey,
} from "../../lib/api";
import {
  SecretAuditReport,
  SecretVerifyResult,
  ManageableSecretItem,
  SecretTestKeyResponse,
} from "../../lib/types";
import { safeUpper } from "../../lib/formatters";

export default function SecretsPage() {
  const [audit, setAudit] = useState<SecretAuditReport | null>(null);
  const [manageableKeys, setManageableKeys] = useState<ManageableSecretItem[]>([]);
  const [formValues, setFormValues] = useState<Record<string, string>>({});
  const [visibleKeys, setVisibleKeys] = useState<Record<string, boolean>>({});
  const [testResults, setTestResults] = useState<Record<string, SecretTestKeyResponse>>({});
  const [activeTab, setActiveTab] = useState<"all" | "ai" | "feeds" | "infrastructure">("all");

  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [testingKey, setTestingKey] = useState<string | null>(null);
  const [testingAll, setTestingAll] = useState<boolean>(false);
  const [auditing, setAuditing] = useState<boolean>(false);
  const [verifyingKey, setVerifyingKey] = useState<string | null>(null);
  const [verificationResults, setVerificationResults] = useState<Record<string, SecretVerifyResult>>({});
  const [notification, setNotification] = useState<{ type: "success" | "error" | "info"; message: string } | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [statusData, manageData] = await Promise.all([
        fetchSecretsStatus(),
        fetchManageableSecrets(),
      ]);
      setAudit(statusData);
      setManageableKeys(manageData.keys || []);
    } catch (err: any) {
      setNotification({ type: "error", message: `Failed to load secret status: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleInputChange = (key: string, value: string) => {
    setFormValues((prev) => ({ ...prev, [key]: value }));
  };

  const toggleVisibility = (key: string) => {
    setVisibleKeys((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleTestKey = async (key: string) => {
    setTestingKey(key);
    try {
      const editedValue = formValues[key];
      const res = await testApiKey(key, editedValue);
      setTestResults((prev) => ({ ...prev, [key]: res }));
      setNotification({
        type: res.success ? "success" : "error",
        message: `[${key}] ${res.message}${res.latency_ms ? ` (${res.latency_ms}ms)` : ""}`,
      });
      setTimeout(() => setNotification(null), 6000);
    } catch (err: any) {
      setNotification({ type: "error", message: `Test failed for ${key}: ${err.message}` });
    } finally {
      setTestingKey(null);
    }
  };

  const handleTestAll = async () => {
    setTestingAll(true);
    let successCount = 0;
    let failureCount = 0;

    for (const item of manageableKeys) {
      try {
        const val = formValues[item.key];
        const res = await testApiKey(item.key, val);
        setTestResults((prev) => ({ ...prev, [item.key]: res }));
        if (res.success) {
          successCount++;
        } else {
          failureCount++;
        }
      } catch {
        failureCount++;
      }
    }

    setTestingAll(false);
    setNotification({
      type: failureCount === 0 ? "success" : "info",
      message: `Completed automated testing of all services: ${successCount} PASSED, ${failureCount} UNCONFIGURED / FAILED.`,
    });
    setTimeout(() => setNotification(null), 7000);
  };

  const handleSaveAll = async () => {
    const keysToSave: Record<string, string> = {};
    for (const [key, val] of Object.entries(formValues)) {
      if (val !== undefined && typeof val === "string" && val.trim().length > 0) {
        keysToSave[key] = val.trim();
      }
    }

    if (Object.keys(keysToSave).length === 0) {
      setNotification({
        type: "info",
        message: "No modified API keys or credentials to save. Type a value into an input field first.",
      });
      setTimeout(() => setNotification(null), 4000);
      return;
    }

    setSaving(true);
    try {
      const res = await saveApiKeys(keysToSave);
      const isSuccess = Boolean(res.success || res.status === "success");
      const savedList = res.saved_keys || res.updated_keys || [];
      if (isSuccess) {
        setNotification({
          type: "success",
          message: `Successfully saved and hot-reloaded ${savedList.length} credential(s)${savedList.length > 0 ? `: ${savedList.join(", ")}` : ""}.`,
        });
        // Clear saved form values to revert to showing masked backend value
        setFormValues({});
        // Reload statuses
        await loadData();
      } else {
        setNotification({ type: "error", message: `Save error: ${res.message || "Operation failed"}` });
      }
      setTimeout(() => setNotification(null), 6000);
    } catch (err: any) {
      setNotification({ type: "error", message: `Save error: ${err.message}` });
    } finally {
      setSaving(false);
    }
  };

  const handleRunAudit = async () => {
    setAuditing(true);
    try {
      const data = await fetchSecretsAudit();
      setAudit(data);
      setNotification({
        type: "success",
        message: `Repository audit complete: ${data.findings.length} findings, .gitignore compliance: ${data.gitignore_compliant ? "PASSED" : "FAILED"}`,
      });
      setTimeout(() => setNotification(null), 5000);
    } catch (err: any) {
      setNotification({ type: "error", message: `Audit error: ${err.message}` });
    } finally {
      setAuditing(false);
    }
  };

  const handleVerify = async (key: string) => {
    setVerifyingKey(key);
    try {
      const result = await verifySecret(key);
      setVerificationResults((prev) => ({ ...prev, [key]: result }));
      setNotification({
        type: result.accessible ? "success" : "error",
        message: result.message,
      });
      setTimeout(() => setNotification(null), 4000);
    } finally {
      setVerifyingKey(null);
    }
  };

  const SECRET_ICONS: Record<string, string> = {
    MISTRAL_API_KEY: "🌪️",
    AI_API_KEY: "🧠",
    MISTRAL_MODEL: "⚙️",
    GITHUB_TOKEN: "🐙",
    VIDEO_API_KEY: "▶️",
    DATABASE_URL: "🗄️",
    REDIS_URL: "⚡",
    SEARCH_URL: "⌕",
  };

  const filteredKeys = manageableKeys.filter((k) => {
    if (activeTab === "all") return true;
    return k.category === activeTab;
  });

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
              CREDENTIAL SECURITY &amp; INTEGRATION VAULT
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30">
              IMPLEMENT.md Section 36 &bull; Mistral AI &amp; Threat Feeds
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            API Keys &amp; Security Vault
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-3xl">
            Configure live platform API keys (Mistral AI, OpenAI, GitHub GHSA, YouTube Video, Databases), test live connectivity in real-time, and hot-reload credentials without server restarts.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleTestAll}
            disabled={testingAll || loading}
            className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 font-mono text-xs transition-colors border border-cyan-500/30 flex items-center gap-1.5 shadow-sm"
          >
            <span className={testingAll ? "animate-spin" : ""}>🔄</span>
            <span>{testingAll ? "Testing All Services..." : "Test All Services"}</span>
          </button>

          <button
            onClick={handleSaveAll}
            disabled={saving || loading}
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition-colors shadow-sm flex items-center gap-1.5"
          >
            <span>{saving ? "💾 Saving to .env..." : "💾 Save & Apply Keys"}</span>
          </button>

          <button
            onClick={handleRunAudit}
            disabled={auditing}
            className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs transition-colors border border-slate-700 flex items-center gap-1.5"
          >
            <span className={auditing ? "animate-spin" : ""}>🛡️</span>
            <span>{auditing ? "Auditing..." : "Audit Repo"}</span>
          </button>
        </div>
      </div>

      {/* Notification Banner */}
      {notification && (
        <div
          className={`p-3.5 rounded-xl text-xs font-mono flex items-center justify-between gap-3 animate-in fade-in ${
            notification.type === "success"
              ? "bg-emerald-950/70 border border-emerald-500/40 text-emerald-300"
              : notification.type === "error"
              ? "bg-rose-950/70 border border-rose-500/40 text-rose-300"
              : "bg-slate-900 border border-cyan-500/30 text-cyan-300"
          }`}
        >
          <div className="flex items-center gap-2">
            <span>{notification.type === "success" ? "✅" : notification.type === "error" ? "❌" : "ℹ️"}</span>
            <span>{notification.message}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-white font-bold">
            ✕
          </button>
        </div>
      )}

      {/* Deep-Dive Guide on AI_API_KEY vs MISTRAL_API_KEY */}
      <div className="p-5 rounded-xl bg-gradient-to-r from-violet-950/40 via-slate-900 to-slate-900 border border-violet-500/30 shadow-lg space-y-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <span className="text-2xl">🧠</span>
            <div>
              <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                What is AI_API_KEY and How Does the Intelligence Engine Use It?
              </h2>
              <span className="text-[11px] font-mono text-violet-300">
                AI Intelligence Synthesis &amp; Threat Assessment Architecture
              </span>
            </div>
          </div>
          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
            Dual AI Provider Stack
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1 text-xs text-slate-300">
          <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 space-y-1.5">
            <div className="font-bold text-cyan-400 font-mono flex items-center gap-1.5">
              <span>🌪️</span>
              <span>1. Primary Engine: MISTRAL_API_KEY</span>
            </div>
            <p className="text-[12px] text-slate-300 leading-relaxed">
              Powers automatic executive summaries, technical threat analysis, IOC extraction, MITRE ATT&amp;CK tagging, and recommended defenses.
              Supports <strong>automatic model detection</strong>: automatically queries your active Mistral subscription to pick the highest available tier (<code className="text-cyan-300">mistral-large-latest</code> &gt; <code className="text-cyan-300">mistral-small-latest</code> &gt; <code className="text-cyan-300">codestral-latest</code>) or falls back seamlessly.
            </p>
          </div>

          <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 space-y-1.5">
            <div className="font-bold text-violet-400 font-mono flex items-center gap-1.5">
              <span>🧠</span>
              <span>2. Universal Fallback: AI_API_KEY</span>
            </div>
            <p className="text-[12px] text-slate-300 leading-relaxed">
              Defined in <strong>IMPLEMENT.md Section 36</strong> as the universal LLM secret. Used by <code className="text-violet-300 font-mono">services/summarization/service.py</code> and <code className="text-violet-300 font-mono">services/scale/model_router.py</code> when <code className="text-violet-300 font-mono">MISTRAL_API_KEY</code> is unset, or for alternative OpenAI, Anthropic Claude, or local Ollama endpoints.
            </p>
          </div>
        </div>
      </div>

      {/* Manage API Keys Section */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-bold text-white font-mono tracking-tight flex items-center gap-2">
              <span>🔑</span>
              <span>Manage API Keys &amp; Integrations</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Enter or update your credentials below. Click &quot;Test Connection&quot; to verify credentials against live upstream servers before saving.
            </p>
          </div>

          {/* Category Filter Tabs */}
          <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs font-mono">
            {(["all", "ai", "feeds", "infrastructure"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-3 py-1 rounded transition-colors uppercase ${
                  activeTab === tab
                    ? "bg-cyan-500 text-slate-950 font-bold shadow"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                {tab === "all" ? "All Keys" : tab}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs animate-pulse">
            Loading manageable credentials and vault items...
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredKeys.map((item) => {
              const testRes = testResults[item.key];
              const isTesting = testingKey === item.key;
              const hasUnsavedInput = formValues[item.key] !== undefined && formValues[item.key] !== "";
              const isVisible = !!visibleKeys[item.key];

              return (
                <div
                  key={item.key}
                  className={`p-5 rounded-xl border transition-all duration-200 flex flex-col justify-between ${
                    item.configured || hasUnsavedInput
                      ? "bg-slate-900/90 border-slate-800 hover:border-slate-700 shadow-md"
                      : "bg-slate-950/60 border-slate-900"
                  }`}
                >
                  <div>
                    {/* Header */}
                    <div className="flex items-start justify-between gap-3 mb-2">
                      <div className="flex items-center gap-2.5">
                        <span className="text-2xl">{SECRET_ICONS[item.key] || "🔑"}</span>
                        <div>
                          <div className="font-mono text-sm font-bold text-white flex items-center gap-2">
                            <span>{item.key}</span>
                            {item.category === "ai" && (
                              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-violet-500/20 text-violet-300 border border-violet-500/30">
                                AI
                              </span>
                            )}
                            {item.category === "feeds" && (
                              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                                FEED
                              </span>
                            )}
                            {item.category === "infrastructure" && (
                              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30">
                                INFRA
                              </span>
                            )}
                          </div>
                          <span className="text-[10px] font-mono text-slate-400">
                            {item.required ? "REQUIRED FOR BASE OPERATION" : "OPTIONAL EXPANSION"}
                          </span>
                        </div>
                      </div>

                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          hasUnsavedInput
                            ? "bg-amber-500/20 text-amber-300 border border-amber-500/30 animate-pulse"
                            : item.configured
                            ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                            : item.required
                            ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                            : "bg-slate-800 text-slate-400 border border-slate-700"
                        }`}
                      >
                        {hasUnsavedInput ? "UNSAVED CHANGES" : item.configured ? "CONFIGURED" : item.required ? "MISSING" : "UNSET"}
                      </span>
                    </div>

                    <p className="text-xs text-slate-300 mt-2 mb-3">
                      {item.description}
                    </p>

                    {/* Masked Preview if set and not editing */}
                    {item.masked_value && !hasUnsavedInput && (
                      <div className="mb-2 text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
                        <span>Current Vault Value:</span>
                        <code className="text-cyan-300 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                          {item.masked_value}
                        </code>
                      </div>
                    )}

                    {/* Input Field with eye toggle */}
                    <div className="relative">
                      <input
                        type={isVisible ? "text" : "password"}
                        value={formValues[item.key] ?? ""}
                        onChange={(e) => handleInputChange(item.key, e.target.value)}
                        placeholder={item.placeholder || (item.configured ? "•••••••••••• (Leave blank to keep current)" : "Enter API key or URL...")}
                        className="w-full px-3 py-2 pr-16 rounded-lg bg-slate-950 border border-slate-700 font-mono text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
                      />
                      <div className="absolute right-2 top-2 flex items-center gap-1">
                        <button
                          type="button"
                          onClick={() => toggleVisibility(item.key)}
                          className="px-1.5 py-0.5 rounded text-[10px] font-mono text-slate-400 hover:text-white bg-slate-800 border border-slate-700"
                          title={isVisible ? "Hide secret" : "Show secret"}
                        >
                          {isVisible ? "HIDE" : "SHOW"}
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Actions: Test Key */}
                  <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-col gap-2">
                    <div className="flex items-center justify-between gap-2">
                      <button
                        onClick={() => handleTestKey(item.key)}
                        disabled={isTesting}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-mono transition-colors border border-cyan-500/20 flex items-center gap-1.5"
                      >
                        <span className={isTesting ? "animate-spin" : ""}>🔌</span>
                        <span>{isTesting ? "Testing Connection..." : "Test Connection"}</span>
                      </button>

                      {hasUnsavedInput && (
                        <button
                          onClick={() => {
                            const newVals = { ...formValues };
                            delete newVals[item.key];
                            setFormValues(newVals);
                          }}
                          className="text-[11px] font-mono text-slate-400 hover:text-rose-400"
                        >
                          Cancel Edit
                        </button>
                      )}
                    </div>

                    {/* Live Test Result */}
                    {testRes && (
                      <div
                        className={`p-2.5 rounded-lg text-xs font-mono space-y-1 animate-in fade-in ${
                          testRes.success
                            ? "bg-emerald-950/40 text-emerald-300 border border-emerald-500/30"
                            : "bg-rose-950/40 text-rose-300 border border-rose-500/30"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold flex items-center gap-1">
                            <span>{testRes.success || testRes.connected ? "✓" : "✗"}</span>
                            <span>{safeUpper(testRes.status, testRes.connected || testRes.success ? "VALID" : "FAILED")}</span>
                          </span>
                          {testRes.latency_ms && (
                            <span className="text-[10px] text-slate-400">{testRes.latency_ms} ms</span>
                          )}
                        </div>
                        <p className="text-[11px] leading-snug">{testRes.message}</p>
                        {testRes.details && (
                          <div className="pt-1 text-[10px] text-slate-400">
                            {testRes.details.available_models && (
                              <div>
                                Models: <span className="text-cyan-300">{testRes.details.available_models.slice(0, 3).join(", ")}...</span>
                              </div>
                            )}
                            {testRes.details.rate_limit_remaining !== undefined && (
                              <div>
                                Rate limit remaining: <span className="text-cyan-300">{testRes.details.rate_limit_remaining}</span>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Top Stat Overview (Section 36 Compliance) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>ACTIVE BACKEND</span>
            <span className="text-base">🔐</span>
          </div>
          <div className="text-xl font-bold text-white font-mono mt-1 uppercase">
            {audit?.provider || "ENV"}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            {audit?.provider === "env" ? "Environment Variables Mode" : "Dedicated Secret Vault"}
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>CONFIGURED SECRETS</span>
            <span className="text-base">🔑</span>
          </div>
          <div className="text-xl font-bold text-cyan-400 font-mono mt-1">
            {audit?.configured_count || 0} / {audit?.total_tracked || 6}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Mandatory Core Platform Credentials
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>GIT EXCLUSIONS</span>
            <span className="text-base">🛡️</span>
          </div>
          <div className="text-xl font-bold text-emerald-400 font-mono mt-1">
            {audit?.gitignore_compliant ? "COMPLIANT" : "ACTION REQUIRED"}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            .env &amp; Private Certificates Ignored
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>POLICY STATUS</span>
            <span className="text-base">✨</span>
          </div>
          <div className="text-xl font-bold text-purple-400 font-mono mt-1">
            {audit?.is_healthy ? "HEALTHY" : "MISSING REQUIRED"}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Zero Leaked Plaintext Credentials
          </p>
        </div>
      </div>

      {/* 6 Mandatory Secrets Grid (Section 36 Compliance) */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs text-slate-400 font-mono px-1">
          <span className="font-bold text-white uppercase tracking-wider">
            Mandatory Core Platform Secrets Specification (Section 36)
          </span>
          <span>Never Transmits Plaintext</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {audit?.secrets.map((sec) => {
            const verifyRes = verificationResults[sec.key];

            return (
              <div
                key={sec.key}
                className={`p-4 rounded-xl border transition-all duration-200 ${
                  sec.configured
                    ? "bg-slate-900/80 border-slate-800 hover:border-slate-700 shadow-md"
                    : "bg-slate-950/40 border-slate-900/60"
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <span className="text-xl">{SECRET_ICONS[sec.key] || "🔑"}</span>
                    <div>
                      <div className="font-mono text-sm font-bold text-white">
                        {sec.key}
                      </div>
                      <span className="text-[10px] font-mono text-slate-400">
                        {sec.required ? "REQUIRED FOR OPERATION" : "OPTIONAL ENRICHMENT"}
                      </span>
                    </div>
                  </div>

                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      sec.configured
                        ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                        : sec.required
                        ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                        : "bg-slate-800 text-slate-400 border border-slate-700"
                    }`}
                  >
                    {sec.configured ? "CONFIGURED" : sec.required ? "MISSING" : "UNSET"}
                  </span>
                </div>

                <p className="text-xs text-slate-300 mt-2.5 line-clamp-2">
                  {sec.description}
                </p>

                {/* Masked Preview */}
                <div className="mt-3 pt-3 border-t border-slate-800/80">
                  <div className="text-[10px] font-mono text-slate-400 mb-1">
                    MASKED VALUE PREVIEW:
                  </div>
                  <div className="p-2 rounded bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300 truncate">
                    {sec.masked_value || "<not set in environment>"}
                  </div>
                </div>

                {/* Verification action */}
                <div className="mt-3 flex items-center justify-between gap-2">
                  <span className="text-[10px] font-mono text-slate-500">
                    Backend: {sec.provider}
                  </span>
                  <button
                    onClick={() => handleVerify(sec.key)}
                    disabled={verifyingKey === sec.key}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono transition-colors flex items-center gap-1"
                  >
                    <span>{verifyingKey === sec.key ? "Testing..." : "Verify Access"}</span>
                  </button>
                </div>

                {verifyRes && (
                  <div
                    className={`mt-2 p-2 rounded text-[10px] font-mono ${
                      verifyRes.accessible
                        ? "bg-emerald-950/40 text-emerald-300 border border-emerald-500/30"
                        : "bg-rose-950/40 text-rose-300 border border-rose-500/30"
                    }`}
                  >
                    {verifyRes.message}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Gitignore & Security Policy Checklist */}
      <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4 shadow-md">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
              Gitignore &amp; Repository Exclusion Compliance
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Automated audit verifying that sensitive files are excluded from version control.
            </p>
          </div>
          <span
            className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${
              audit?.gitignore_compliant
                ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                : "bg-rose-500/20 text-rose-300 border border-rose-500/30"
            }`}
          >
            {audit?.gitignore_compliant ? "100% COMPLIANT" : "NON-COMPLIANT"}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
          {audit?.verified_patterns.map((pat) => (
            <div
              key={pat}
              className="p-2 rounded-lg bg-slate-950 border border-slate-800/80 text-xs font-mono text-slate-300 flex items-center gap-1.5"
            >
              <span className="text-emerald-400 text-xs">✓</span>
              <span className="truncate">{pat}</span>
            </div>
          ))}
        </div>

        {/* Scan Findings if any */}
        {audit && audit.findings.length > 0 && (
          <div className="mt-4 pt-4 border-t border-slate-800 space-y-2">
            <span className="text-xs font-mono text-amber-400 font-bold block">
              IDENTIFIED SECURITY FINDINGS ({audit.findings.length})
            </span>
            <div className="space-y-1.5">
              {audit.findings.map((f, i) => (
                <div
                  key={i}
                  className="p-2 rounded bg-rose-950/30 border border-rose-500/30 text-xs font-mono text-rose-300 flex items-start gap-2"
                >
                  <span className="text-rose-400">⚠️</span>
                  <div>
                    <span className="font-bold">[{safeUpper(f.severity, "INFO")}]</span> {f.file_path}: {f.description}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Production Dedicated Secret Manager Info */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-3">
        <h3 className="text-xs font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
          <span>🏛️</span>
          <span>Production Secret Manager Integration</span>
        </h3>
        <p className="text-xs text-slate-400 max-w-3xl">
          Conforming to <code className="text-cyan-300 font-mono">IMPLEMENT.md Section 36: Production should use a dedicated secret manager</code>.
          Set <code className="text-cyan-300 font-mono">SECRET_BACKEND=&quot;vault&quot;</code>, <code className="text-cyan-300 font-mono">SECRET_BACKEND=&quot;aws&quot;</code>, or <code className="text-cyan-300 font-mono">SECRET_BACKEND=&quot;encrypted_file&quot;</code>.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1 text-xs font-mono">
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-cyan-300 font-bold">HashiCorp Vault (vault)</div>
            <div className="text-[11px] text-slate-400 mt-1">Config: VAULT_ADDR, VAULT_TOKEN</div>
            <div className="text-[10px] text-slate-500 mt-1">KV v2 dynamic secret leasing</div>
          </div>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-cyan-300 font-bold">AWS Secrets Manager (aws)</div>
            <div className="text-[11px] text-slate-400 mt-1">Config: AWS_REGION, IAM role</div>
            <div className="text-[10px] text-slate-500 mt-1">Cloud-native key rotation</div>
          </div>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-cyan-300 font-bold">Encrypted File (encrypted_file)</div>
            <div className="text-[11px] text-slate-400 mt-1">Config: SECRET_MASTER_KEY</div>
            <div className="text-[10px] text-slate-500 mt-1">Air-gapped AES vault storage</div>
          </div>
        </div>
      </div>
    </div>
  );
}

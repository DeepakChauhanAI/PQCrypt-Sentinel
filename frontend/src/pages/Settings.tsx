import { useState } from "react";
import {
  Lock,
  Globe,
  Database,
  Sliders,
  Save,
} from "lucide-react";

export default function Settings() {
  const [activeTab, setActiveTab] = useState("general");
  const [networkDiscoveryRange, setNetworkDiscoveryRange] = useState("10.0.0.0/24");
  const [dnsDiscoveryDomain, setDnsDiscoveryDomain] = useState("pqc.local");
  const [nmapPath, setNmapPath] = useState("nmap");

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    alert("Configuration parameters updated successfully.");
  };

  return (
    <div className="space-y-6">

      <div className="flex flex-col gap-6 md:flex-row">
        {/* Navigation Sidebar */}
        <div className="w-full md:w-64 shrink-0 rounded-lg border border-border bg-surface p-4 h-fit">
          <nav className="flex flex-col space-y-1">
            <button
              className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors text-left ${
                activeTab === "general"
                  ? "bg-border text-gray-200"
                  : "text-gray-400 hover:bg-border/50 hover:text-gray-200"
              }`}
              onClick={() => setActiveTab("general")}
            >
              <Sliders className="h-4 w-4" />
              General Configuration
            </button>
            <button
              className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors text-left ${
                activeTab === "scanner"
                  ? "bg-border text-gray-200"
                  : "text-gray-400 hover:bg-border/50 hover:text-gray-200"
              }`}
              onClick={() => setActiveTab("scanner")}
            >
              <Globe className="h-4 w-4" />
              Scanner Engine
            </button>
            <button
              className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors text-left ${
                activeTab === "security"
                  ? "bg-border text-gray-200"
                  : "text-gray-400 hover:bg-border/50 hover:text-gray-200"
              }`}
              onClick={() => setActiveTab("security")}
            >
              <Lock className="h-4 w-4" />
              Access & API Keys
            </button>
            <button
              className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors text-left ${
                activeTab === "database"
                  ? "bg-border text-gray-200"
                  : "text-gray-400 hover:bg-border/50 hover:text-gray-200"
              }`}
              onClick={() => setActiveTab("database")}
            >
              <Database className="h-4 w-4" />
              Database Config
            </button>
          </nav>
        </div>

        {/* Content Panel */}
        <div className="flex-1 rounded-lg border border-border bg-surface p-6">
          <form onSubmit={handleSave} className="space-y-6">
            {activeTab === "general" && (
              <div className="space-y-4">
                <h2 className="text-lg font-bold text-gray-200">General Platform Configuration</h2>
                <div className="space-y-4 max-w-lg">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
                      Organization Identifier
                    </label>
                    <input
                      type="text"
                      className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
                      defaultValue="PQCrypt Sentinel Enterprise"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
                      Platform Access Mode
                    </label>
                    <select className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none">
                      <option value="air-gap">Air-Gapped / Standard Local</option>
                      <option value="hybrid">Hybrid Cloud Sync</option>
                    </select>
                  </div>
                </div>
              </div>
            )}

            {activeTab === "scanner" && (
              <div className="space-y-4">
                <h2 className="text-lg font-bold text-gray-200">Scanning Engine Parameters</h2>
                <div className="space-y-4 max-w-lg">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
                      Default Network Target Range (CIDR)
                    </label>
                    <input
                      type="text"
                      className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none font-mono"
                      value={networkDiscoveryRange}
                      onChange={(e) => setNetworkDiscoveryRange(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
                      Default DNS Enum Scope (Domains)
                    </label>
                    <input
                      type="text"
                      className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none font-mono"
                      value={dnsDiscoveryDomain}
                      onChange={(e) => setDnsDiscoveryDomain(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
                      Nmap Binary Path
                    </label>
                    <input
                      type="text"
                      className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none font-mono"
                      value={nmapPath}
                      onChange={(e) => setNmapPath(e.target.value)}
                    />
                  </div>
                </div>
              </div>
            )}

            {activeTab === "security" && (
              <div className="space-y-4">
                <h2 className="text-lg font-bold text-gray-200">Access Control & Credentials</h2>
                <p className="text-xs text-gray-400">
                  Manage active API keys and SSH credential profiles used during active server handshakes.
                </p>
                <div className="rounded-lg border border-border bg-background p-4 space-y-3">
                  <div className="flex justify-between items-center text-sm border-b border-border/50 pb-2">
                    <div>
                      <div className="font-semibold text-gray-200">Default CLI Runner Token</div>
                      <div className="text-xs text-gray-500 font-mono">pqc_agent_9281uashd...</div>
                    </div>
                    <span className="inline-flex rounded-full bg-green-950/40 border border-green-800/50 px-2 py-0.5 text-xs font-semibold text-green-400">
                      Active
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-sm pt-1">
                    <div>
                      <div className="font-semibold text-gray-200">CMDB Write-back Profile</div>
                      <div className="text-xs text-gray-500">ServiceNow Integration Creds</div>
                    </div>
                    <span className="inline-flex rounded-full bg-gray-900/30 border border-gray-800/50 px-2 py-0.5 text-xs font-semibold text-gray-400">
                      Not Configured
                    </span>
                  </div>
                </div>
              </div>
            )}

            {activeTab === "database" && (
              <div className="space-y-4">
                <h2 className="text-lg font-bold text-gray-200">Database & Storage Engine</h2>
                <div className="space-y-4 max-w-lg">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
                      Postgres Host Connection URL
                    </label>
                    <input
                      type="text"
                      className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none font-mono disabled:opacity-50"
                      value="postgresql+asyncpg://pqcrypt:*****@localhost:5432/pqcrypt"
                      disabled
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
                      Redis Cache Broker Address
                    </label>
                    <input
                      type="text"
                      className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none font-mono disabled:opacity-50"
                      value="redis://localhost:6379/0"
                      disabled
                    />
                  </div>
                </div>
              </div>
            )}

            <button
              type="submit"
              className="flex items-center gap-2 rounded-md bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-500 focus:outline-none"
            >
              <Save className="h-4 w-4" />
              Save Changes
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Search,
  Filter,
  ArrowUpDown,
  X,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Server,
  Key,
  FileBadge,
  RefreshCw,
  Eye,
  Settings2,
  Loader2,
  Copy,
  Check,
  Clock,
  Shield,
} from "lucide-react";

interface Algorithm {
  id: string;
  algorithm_name: string;
  algorithm_type: string;
  key_size?: number;
  curve?: string;
  protocol?: string;
  protocol_version?: string;
  cipher_suite?: string;
  pqc_status: "vulnerable" | "transitioning" | "hybrid" | "pqc_ready" | "safe";
  is_quantum_vulnerable: boolean;
  oid?: string;
}

interface Certificate {
  id: string;
  thumbprint: string;
  subject: string;
  issuer: string;
  serial_number?: string;
  sig_algorithm: string;
  pub_key_algorithm: string;
  pub_key_size?: number;
  curve_name?: string;
  not_before: string;
  not_after: string;
  is_self_signed: boolean;
  pqc_capable: boolean;
}

interface Finding {
  id: string;
  finding_type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  status: "open" | "in_progress" | "resolved" | "accepted" | "false_positive";
  risk_score?: number;
}

interface Asset {
  id: string;
  name: string;
  asset_type: string;
  ip_address?: string;
  fqdn?: string;
  port?: number;
  protocol?: string;
  os?: string;
  environment: string;
  business_service?: string;
  owner_id?: string;
  discovery_source?: string;
  first_discovered_at: string;
  last_verified_at?: string;
  asset_metadata: Record<string, any>;
  risk_score: number;
  pqc_status: "vulnerable" | "hybrid" | "pqc_ready" | "safe";
  algorithms?: Algorithm[];
  certificates?: Certificate[];
  findings?: Finding[];
  // Phase B — scan correlation
  first_scan_id?: string;
  last_scan_id?: string;
  // Phase B — scan-group correlation enrichment
  last_scan_group_id?: string | null;
  last_scan_group_name?: string | null;
  first_scan_group_id?: string | null;
  first_scan_group_name?: string | null;
}

  // Copy helper
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      // fallback for older browsers
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    }
  };

export default function Assets() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState("");
  const [assetType, setAssetType] = useState("");
  const [environment, setEnvironment] = useState("");
  const [pqcStatus, setPqcStatus] = useState("");
  const [sortBy, setSortBy] = useState("risk_score");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");

  // Selected Asset Details
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"overview" | "algorithms" | "certificates" | "findings" | "scan_history">("overview");

  // Rescan State
  const [rescanning, setRescanning] = useState(false);
  const [rescanSuccess, setRescanSuccess] = useState<string | null>(null);

  const fetchAssets = async () => {
    try {
      setLoading(true);
      const headers = {
        Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
      };
      const queryParams = new URLSearchParams();
      if (search) queryParams.append("search", search);
      if (assetType) queryParams.append("asset_type", assetType);
      if (environment) queryParams.append("environment", environment);
      if (pqcStatus) queryParams.append("pqc_status", pqcStatus);
      queryParams.append("sort_by", sortBy);
      queryParams.append("sort_order", sortOrder);

      const response = await fetch(`/api/v1/assets?${queryParams.toString()}`, { headers });
      if (!response.ok) {
        throw new Error("Failed to load assets");
      }
      const data = await response.json();
      setAssets(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, [search, assetType, environment, pqcStatus, sortBy, sortOrder]);

  const fetchAssetDetails = async (id: string) => {
    try {
      setDetailLoading(true);
      const headers = {
        Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
      };
      const response = await fetch(`/api/v1/assets/${id}`, { headers });
      if (!response.ok) {
        throw new Error("Failed to load asset details");
      }
      const data = await response.json();
      setSelectedAsset(data);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to load asset details");
    } finally {
      setDetailLoading(false);
    }
  };

  useEffect(() => {
    if (selectedAssetId) {
      fetchAssetDetails(selectedAssetId);
    } else {
      setSelectedAsset(null);
    }
  }, [selectedAssetId]);

  const handleSort = (field: string) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(field);
      setSortOrder("desc");
    }
  };

  const handleRescan = async (asset: Asset) => {
    setRescanning(true);
    setRescanSuccess(null);
    try {
      const target = asset.ip_address || asset.fqdn || asset.name;
      const cleanTarget = target.includes(":") ? target.split(":")[0] : target;
      const scanType = asset.port === 443 ? "tls_only" : asset.port === 22 ? "ssh_only" : "full";

      const headers = {
        "Content-Type": "application/json",
        Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
      };

      const response = await fetch("/api/v1/scans", {
        method: "POST",
        headers,
        body: JSON.stringify({
          scan_type: scanType,
          target: cleanTarget,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to queue scan job");
      }

      setRescanSuccess("Scan job queued successfully. Check Scans page for progress.");
      setTimeout(() => setRescanSuccess(null), 5000);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error scanning asset");
    } finally {
      setRescanning(false);
    }
  };

  const getPqcStatusBadge = (status: string) => {
    switch (status) {
      case "pqc_ready":
        return (
          <span className="inline-flex items-center gap-1 rounded-full bg-green-950/40 px-2 py-0.5 text-xs font-semibold text-green-400 border border-green-800/50">
            <ShieldCheck className="h-3.5 w-3.5" />
            PQC Ready
          </span>
        );
      case "hybrid":
        return (
          <span className="inline-flex items-center gap-1 rounded-full bg-blue-950/40 px-2 py-0.5 text-xs font-semibold text-blue-400 border border-blue-800/50">
            <ShieldCheck className="h-3.5 w-3.5 text-blue-400" />
            Hybrid
          </span>
        );
      case "safe":
        return (
          <span className="inline-flex items-center gap-1 rounded-full bg-emerald-950/40 px-2 py-0.5 text-xs font-semibold text-emerald-400 border border-emerald-800/50">
            <ShieldCheck className="h-3.5 w-3.5" />
            Safe
          </span>
        );
      case "vulnerable":
      default:
        return (
          <span className="inline-flex items-center gap-1 rounded-full bg-red-950/40 px-2 py-0.5 text-xs font-semibold text-red-400 border border-red-800/50">
            <ShieldAlert className="h-3.5 w-3.5" />
            Vulnerable
          </span>
        );
    }
  };

  const getSeverityBadge = (severity: string) => {
    const map = {
      critical: "bg-red-950/40 text-red-400 border-red-800/50",
      high: "bg-orange-950/40 text-orange-400 border-orange-800/50",
      medium: "bg-yellow-950/40 text-yellow-400 border-yellow-800/50",
      low: "bg-green-950/40 text-green-400 border-green-800/50",
      info: "bg-blue-950/40 text-blue-400 border-blue-800/50",
    };
    const style = map[severity as keyof typeof map] || "bg-gray-950/40 text-gray-400 border-gray-800/50";
    return (
      <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold border ${style}`}>
        {severity.toUpperCase()}
      </span>
    );
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return "text-red-400";
    if (score >= 50) return "text-orange-400";
    if (score >= 20) return "text-yellow-400";
    return "text-green-400";
  };

  return (
    <div className="space-y-6">

      {/* Filter Bar */}
      <div className="grid gap-4 rounded-lg border border-border bg-surface p-4 md:grid-cols-4">
        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search IP, domain, name..."
            className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-4 text-sm text-gray-200 placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {/* Asset Type */}
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-gray-400 shrink-0" />
          <select
            className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
            value={assetType}
            onChange={(e) => setAssetType(e.target.value)}
          >
            <option value="">All Asset Types</option>
            <option value="server">Server</option>
            <option value="endpoint">Endpoint</option>
            <option value="network_device">Network Device</option>
            <option value="load_balancer">Load Balancer</option>
            <option value="vpn_gateway">VPN Gateway</option>
            <option value="database">Database</option>
            <option value="web_app">Web App</option>
            <option value="api">API</option>
            <option value="hsm">HSM</option>
            <option value="kms">KMS</option>
            <option value="certificate_authority">Certificate Authority</option>
          </select>
        </div>

        {/* Environment */}
        <div className="flex items-center gap-2">
          <Settings2 className="h-4 w-4 text-gray-400 shrink-0" />
          <select
            className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
          >
            <option value="">All Environments</option>
            <option value="production">Production</option>
            <option value="staging">Staging</option>
            <option value="development">Development</option>
            <option value="testing">Testing</option>
            <option value="unknown">Unknown</option>
          </select>
        </div>

        {/* PQC Status */}
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-gray-400 shrink-0" />
          <select
            className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
            value={pqcStatus}
            onChange={(e) => setPqcStatus(e.target.value)}
          >
            <option value="">All PQC Statuses</option>
            <option value="vulnerable">Vulnerable</option>
            <option value="hybrid">Hybrid</option>
            <option value="pqc_ready">PQC Ready</option>
            <option value="safe">Safe</option>
          </select>
        </div>
      </div>

      {/* Summary Cards — derived from the current filtered data */}
      {!loading && !error && assets.length > 0 && (() => {
        const total = assets.length;
        const vulnerable = assets.filter(a => a.pqc_status === "vulnerable").length;
        const hybrid = assets.filter(a => a.pqc_status === "hybrid").length;
        const pqcReady = assets.filter(a => a.pqc_status === "pqc_ready").length;
        const safe = assets.filter(a => a.pqc_status === "safe").length;
        const avgRisk = Math.round(assets.reduce((s, a) => s + a.risk_score, 0) / total);
        return (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
            {[
              { label: "Total Assets", value: total, icon: Server, color: "text-gray-200", bg: "bg-gray-800/50", border: "border-gray-700/50" },
              { label: "Vulnerable", value: vulnerable, icon: ShieldAlert, color: "text-red-400", bg: "bg-red-950/30", border: "border-red-800/50" },
              { label: "Hybrid", value: hybrid, icon: Shield, color: "text-blue-400", bg: "bg-blue-950/30", border: "border-blue-800/50" },
              { label: "PQC Ready", value: pqcReady, icon: ShieldCheck, color: "text-green-400", bg: "bg-green-950/30", border: "border-green-800/50" },
              { label: "Safe", value: safe, icon: Check, color: "text-emerald-400", bg: "bg-emerald-950/30", border: "border-emerald-800/50" },
              { label: "Avg Risk Score", value: avgRisk, icon: AlertTriangle, color: avgRisk >= 50 ? "text-orange-400" : "text-yellow-400", bg: "bg-yellow-950/20", border: "border-yellow-800/40" },
            ].map((card) => (
              <div key={card.label} className={`rounded-lg border ${card.border} ${card.bg} px-4 py-3 flex items-center gap-3`}>
                <card.icon className={`h-5 w-5 shrink-0 ${card.color}`} />
                <div>
                  <div className={`text-lg font-bold ${card.color}`}>{card.value}</div>
                  <div className="text-[11px] font-medium text-gray-400 uppercase tracking-wider">{card.label}</div>
                </div>
              </div>
            ))}
          </div>
        );
      })()}

      {/* Main Table */}
      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        {loading ? (
          <div className="flex h-64 items-center justify-center">
            <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
          </div>
        ) : error ? (
          <div className="flex h-64 items-center justify-center p-4 text-center">
            <div className="space-y-3">
              <AlertTriangle className="mx-auto h-10 w-10 text-red-500" />
              <p className="text-gray-200 font-medium">Failed to load assets</p>
              <p className="text-sm text-gray-400">{error}</p>
              <button
                onClick={fetchAssets}
                className="rounded-md border border-border bg-surface px-4 py-2 text-sm font-semibold text-gray-200 hover:bg-border transition-colors"
              >
                <RefreshCw className="h-3.5 w-3.5 inline mr-1.5" />
                Retry
              </button>
            </div>
          </div>
        ) : assets.length === 0 ? (
          <div className="flex h-64 flex-col items-center justify-center p-8 text-center space-y-4">
            <Server className="h-12 w-12 text-gray-500" />
            <div>
              <p className="text-lg font-medium text-gray-200">No assets discovered yet</p>
              <p className="text-sm text-gray-400">Run a network scan or import your CMDB data to populate assets.</p>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="border-b border-border bg-background text-xs font-semibold uppercase tracking-wider text-gray-400">
                  <th className="py-3 px-4">
                    <button className="flex items-center gap-1 hover:text-gray-200" onClick={() => handleSort("name")}>
                      Asset Name <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Environment</th>
                  <th className="py-3 px-4">PQC Status</th>
                  <th className="py-3 px-4">
                    <button className="flex items-center gap-1 hover:text-gray-200" onClick={() => handleSort("risk_score")}>
                      Risk Score <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </th>
                  <th className="py-3 px-4">
                    <button className="flex items-center gap-1 hover:text-gray-200" onClick={() => handleSort("last_scanned")}>
                      Last Verified <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </th>
                  <th className="py-3 px-4">Last Scan</th>
                  <th className="py-3 px-4">Scan Group</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border text-sm text-gray-300">
                {assets.map((asset) => (
                  <tr
                    key={asset.id}
                    className="hover:bg-border/30 transition-colors cursor-pointer"
                    onClick={() => setSelectedAssetId(asset.id)}
                  >
                    <td className="py-3 px-4">
                      <div className="font-semibold text-gray-200">{asset.name}</div>
                      <div className="text-xs text-gray-500">
                        {asset.ip_address || "No IP"}{asset.port ? `:${asset.port}` : ""}
                        {asset.fqdn && <span className="text-gray-400"> ({asset.fqdn})</span>}
                      </div>
                    </td>
                    <td className="py-3 px-4 capitalize">{asset.asset_type.replace("_", " ")}</td>
                    <td className="py-3 px-4">
                      <span className="capitalize">{asset.environment}</span>
                    </td>
                    <td className="py-3 px-4">{getPqcStatusBadge(asset.pqc_status)}</td>
                    <td className="py-3 px-4 font-bold">
                      <span className={getRiskScoreColor(asset.risk_score)}>{asset.risk_score}</span>
                    </td>
                    <td className="py-3 px-4 text-xs text-gray-400">
                      {asset.last_verified_at
                        ? new Date(asset.last_verified_at).toLocaleDateString()
                        : "Never"}
                    </td>
                    <td className="py-3 px-4 text-xs">
                      {asset.last_scan_id ? (
                        <Link
                          to={`/scans/${asset.last_scan_id}`}
                          className="font-mono text-cyan-400 hover:underline"
                          onClick={(e) => e.stopPropagation()}
                        >
                          #{asset.last_scan_id.slice(0, 8)}
                        </Link>
                      ) : (
                        <span className="text-gray-500">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-xs">
                      {asset.last_scan_group_id ? (
                        <Link
                          to={`/scan-groups/${asset.last_scan_group_id}`}
                          className="text-cyan-400 hover:underline"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {asset.last_scan_group_name || `#${asset.last_scan_group_id.slice(0, 8)}`}
                        </Link>
                      ) : (
                        <span className="text-gray-500">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                      <button
                        className="rounded-md border border-border px-2.5 py-1.5 text-xs text-gray-300 hover:bg-border hover:text-gray-100"
                        onClick={() => setSelectedAssetId(asset.id)}
                      >
                        <Eye className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Asset Details Drawer (Slide-over panel) */}
      {selectedAssetId && (
        <div className="fixed inset-0 z-50 overflow-hidden" role="dialog" aria-modal="true">
          <div className="absolute inset-0 overflow-hidden">
            {/* Overlay */}
            <div
              className="absolute inset-0 bg-black/60 transition-opacity"
              onClick={() => setSelectedAssetId(null)}
            />

            <div className="pointer-events-none fixed inset-y-0 right-0 flex max-w-full pl-10">
              <div className="pointer-events-auto w-screen max-w-2xl transform bg-surface border-l border-border transition-all duration-300">
                {detailLoading ? (
                  <div className="flex h-full items-center justify-center">
                    <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
                  </div>
                ) : selectedAsset ? (
                  <div className="flex h-full flex-col overflow-y-scroll">
                    {/* Header */}
                    <div className="border-b border-border bg-background p-6">
                      <div className="flex items-start justify-between">
                        <div className="space-y-1">
                          <div className="flex items-center gap-3">
                            <h2 className="text-xl font-bold text-gray-200">{selectedAsset.name}</h2>
                            {getPqcStatusBadge(selectedAsset.pqc_status)}
                          </div>
                          <p className="text-sm text-gray-400 capitalize">
                            {selectedAsset.asset_type.replace("_", " ")} &bull; {selectedAsset.ip_address || "No IP"}
                            {selectedAsset.port ? `:${selectedAsset.port}` : ""}
                            {selectedAsset.fqdn && ` (${selectedAsset.fqdn})`}
                          </p>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            className="rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-semibold text-gray-200 hover:bg-border disabled:opacity-50"
                            onClick={() => handleRescan(selectedAsset)}
                            disabled={rescanning}
                          >
                            {rescanning ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : (
                              <RefreshCw className="h-3.5 w-3.5 inline mr-1" />
                            )}
                            Re-scan
                          </button>
                          <button
                            className="rounded-md p-1.5 text-gray-400 hover:bg-border hover:text-gray-200"
                            onClick={() => setSelectedAssetId(null)}
                          >
                            <X className="h-5 w-5" />
                          </button>
                        </div>
                      </div>
                      {rescanSuccess && (
                        <div className="mt-3 rounded border border-green-800/50 bg-green-950/20 p-2.5 text-xs text-green-400">
                          {rescanSuccess}
                        </div>
                      )}
                      <div className="mt-4 flex items-center gap-6">
                        <div>
                          <div className="text-xs text-gray-500 uppercase tracking-wider">Risk Score</div>
                          <div className={`text-2xl font-bold ${getRiskScoreColor(selectedAsset.risk_score)}`}>
                            {selectedAsset.risk_score}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs text-gray-500 uppercase tracking-wider">Environment</div>
                          <div className="text-sm font-semibold capitalize text-gray-300">
                            {selectedAsset.environment}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs text-gray-500 uppercase tracking-wider">Owner</div>
                          <div className="text-sm font-semibold text-gray-300">
                            {selectedAsset.owner_id ? "Owner Configured" : "None"}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Tabs */}
                    <div className="border-b border-border bg-background px-6">
                      <nav className="-mb-px flex space-x-6">
                        {(["overview", "algorithms", "certificates", "findings", "scan_history"] as const).map((tab) => (
                          <button
                            key={tab}
                            className={`border-b-2 py-4 text-xs font-semibold uppercase tracking-wider focus:outline-none transition-colors ${
                              activeTab === tab
                                ? "border-cyan-500 text-cyan-400"
                                : "border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-500"
                            }`}
                            onClick={() => setActiveTab(tab)}
                          >
                            {tab}
                          </button>
                        ))}
                      </nav>
                    </div>

                    {/* Tab Contents */}
                    <div className="flex-1 p-6 space-y-6">
                      {activeTab === "overview" && (
                        <div className="space-y-6">
                          <div className="grid grid-cols-2 gap-4 rounded-lg border border-border bg-background p-4">
                            <div>
                              <div className="text-xs text-gray-500">Business Service</div>
                              <div className="text-sm text-gray-300">{selectedAsset.business_service || "N/A"}</div>
                            </div>
                            <div>
                              <div className="text-xs text-gray-500">Discovery Source</div>
                              <div className="text-sm text-gray-300 capitalize">{selectedAsset.discovery_source || "N/A"}</div>
                            </div>
                            <div>
                              <div className="text-xs text-gray-500">First Discovered</div>
                              <div className="text-sm text-gray-300">
                                {new Date(selectedAsset.first_discovered_at).toLocaleString()}
                              </div>
                            </div>
                            <div>
                              <div className="text-xs text-gray-500">Last Verified</div>
                              <div className="text-sm text-gray-300">
                                {selectedAsset.last_verified_at
                                  ? new Date(selectedAsset.last_verified_at).toLocaleString()
                                  : "Never"}
                              </div>
                            </div>
                          </div>

                          <div>
                            <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-2">
                              CI / Metadata Attributes
                            </h3>
                            <div className="rounded-lg border border-border bg-background p-4 font-mono text-xs text-gray-400 overflow-x-auto">
                              <pre>{JSON.stringify(selectedAsset.asset_metadata, null, 2)}</pre>
                            </div>
                          </div>
                        </div>
                      )}

                      {activeTab === "algorithms" && (
                        <div className="space-y-4">
                          <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400">
                            Cryptographic Algorithms Used
                          </h3>
                          {!selectedAsset.algorithms || selectedAsset.algorithms.length === 0 ? (
                            <div className="text-center py-8 text-gray-500 text-sm">
                              No algorithm negotiation history captured for this asset.
                            </div>
                          ) : (
                            <div className="space-y-3">
                              {selectedAsset.algorithms.map((algo) => (
                                <div
                                  key={algo.id}
                                  className="flex items-start justify-between gap-4 rounded-lg border border-border bg-background p-4"
                                >
                                  <div className="space-y-1.5 min-w-0">
                                    <div className="flex items-center gap-2">
                                      <Key className="h-4 w-4 text-cyan-400 shrink-0" />
                                      <span className="font-mono text-sm text-gray-200 font-semibold">{algo.algorithm_name}</span>
                                    </div>
                                    <div className="text-xs text-gray-500 space-x-2">
                                      <span className="capitalize">{algo.algorithm_type.replace(/_/g, " ")}</span>
                                      {algo.key_size && <span>· Size: {algo.key_size} bits</span>}
                                      {algo.curve && <span>· Curve: {algo.curve}</span>}
                                    </div>
                                    {algo.protocol && (
                                      <div className="text-xs text-gray-500">
                                        Protocol: <span className="font-mono text-gray-400">{algo.protocol}</span>
                                        {algo.protocol_version && <span className="text-gray-600"> v{algo.protocol_version}</span>}
                                      </div>
                                    )}
                                    {algo.cipher_suite && (
                                      <div className="text-xs text-gray-500 font-mono text-gray-400">
                                        Cipher Suite: {algo.cipher_suite}
                                      </div>
                                    )}
                                    {algo.oid && (
                                      <div className="flex items-center gap-1.5 text-[11px] text-gray-600">
                                        OID: <code className="bg-surface rounded px-1.5 py-0.5 text-gray-500 font-mono">{algo.oid}</code>
                                        <button
                                          onClick={() => copyToClipboard(algo.oid!, `oid:${algo.id}`)}
                                          className="text-gray-600 hover:text-gray-400"
                                          title="Copy OID"
                                        >
                                          {copiedId === `oid:${algo.id}` ? (
                                            <Check className="h-3 w-3 text-green-400" />
                                          ) : (
                                            <Copy className="h-3 w-3" />
                                          )}
                                        </button>
                                      </div>
                                    )}
                                  </div>
                                  <div className="shrink-0 pt-0.5">{getPqcStatusBadge(algo.pqc_status)}</div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}

                      {activeTab === "certificates" && (
                        <div className="space-y-4">
                          <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400">
                            X.509 Certificates Exposed
                          </h3>
                          {!selectedAsset.certificates || selectedAsset.certificates.length === 0 ? (
                            <div className="text-center py-8 text-gray-500 text-sm">
                              No X.509 certificates discovered on this asset.
                            </div>
                          ) : (
                            <div className="space-y-3">
                              {selectedAsset.certificates.map((cert) => (
                                <div
                                  key={cert.id}
                                  className="rounded-lg border border-border bg-background p-4 space-y-3"
                                >
                                  <div className="flex items-start justify-between gap-3">
                                    <div className="space-y-1 min-w-0">
                                      <div className="flex items-center gap-2">
                                        <FileBadge className="h-4 w-4 text-purple-400 shrink-0" />
                                        <span className="font-semibold text-sm text-gray-200 truncate">
                                          {cert.subject.split("CN=")[1]?.split(",")[0] || cert.subject}
                                        </span>
                                      </div>
                                      <div className="text-xs text-gray-500">Issuer: {cert.issuer}</div>
                                    </div>
                                    <span
                                      className={`inline-flex rounded-full px-2 py-0.5 text-[11px] font-semibold border shrink-0 ${
                                        cert.pqc_capable
                                          ? "bg-green-950/40 text-green-400 border-green-800/50"
                                          : "bg-red-950/40 text-red-400 border-red-800/50"
                                      }`}
                                    >
                                      {cert.pqc_capable ? "PQC Capable" : "Classical Only"}
                                    </span>
                                  </div>

                                  <div className="space-y-1.5 text-xs border-t border-border/50 pt-2.5">
                                    <div className="flex items-center justify-between gap-2">
                                      <span className="text-gray-500">Thumbprint</span>
                                      <button
                                        onClick={() => copyToClipboard(cert.thumbprint, `thumb:${cert.id}`)}
                                        className="flex items-center gap-1.5 font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
                                        title="Copy thumbprint"
                                      >
                                        <span className="text-gray-300">{cert.thumbprint.slice(0, 24)}…</span>
                                        {copiedId === `thumb:${cert.id}` ? (
                                          <Check className="h-3 w-3 text-green-400" />
                                        ) : (
                                          <Copy className="h-3 w-3" />
                                        )}
                                      </button>
                                    </div>
                                    {cert.serial_number && (
                                      <div className="flex items-center justify-between gap-2">
                                        <span className="text-gray-500">Serial</span>
                                        <span className="font-mono text-gray-400">{cert.serial_number}</span>
                                      </div>
                                    )}
                                    <div className="grid grid-cols-2 gap-2 text-gray-400">
                                      <div className="flex items-center gap-1.5">
                                        <span className="text-gray-600">Signature:</span>
                                        <span className="font-mono truncate">{cert.sig_algorithm}</span>
                                      </div>
                                      <div className="flex items-center gap-1.5">
                                        <span className="text-gray-600">Key:</span>
                                        <span className="font-mono truncate">{cert.pub_key_algorithm}</span>
                                      </div>
                                    </div>
                                    {cert.pub_key_size && (
                                      <div className="text-gray-400">
                                        Key Size: <span className="font-mono text-gray-300">{cert.pub_key_size} bits</span>
                                      </div>
                                    )}
                                    <div className="flex items-center justify-between gap-2">
                                      <span className="text-gray-500 flex items-center gap-1">
                                        <Clock className="h-3 w-3" />
                                        Expires
                                      </span>
                                      <span className="font-mono text-gray-300">{new Date(cert.not_after).toLocaleDateString()}</span>
                                    </div>
                                    <div className="flex items-center justify-between gap-2">
                                      <span className="text-gray-500">Valid From</span>
                                      <span className="font-mono text-gray-300">{new Date(cert.not_before).toLocaleDateString()}</span>
                                    </div>
                                    {cert.curve_name && (
                                      <div className="text-gray-400">
                                        Curve: <span className="font-mono text-gray-300">{cert.curve_name}</span>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}

                      {activeTab === "findings" && (
                        <div className="space-y-4">
                          <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400">
                            Cryptographic Vulnerabilities / Findings
                          </h3>
                          {!selectedAsset.findings || selectedAsset.findings.length === 0 ? (
                            <div className="text-center py-8 text-gray-500 text-sm">
                              No active findings. The asset looks quantum-safe!
                            </div>
                          ) : (
                            <div className="space-y-3">
                              {selectedAsset.findings.map((finding) => (
                                <div
                                  key={finding.id}
                                  className="flex items-start justify-between rounded-lg border border-border bg-background p-4"
                                >
                                  <div className="space-y-1">
                                    <div className="font-semibold text-gray-200">{finding.title}</div>
                                    <div className="text-xs text-gray-500 capitalize">
                                      Type: {finding.finding_type.replace("_", " ")} &bull; Status:{" "}
                                      <span className="font-semibold">{finding.status}</span>
                                    </div>
                                  </div>
                                  <div className="flex flex-col items-end gap-1.5">
                                    {getSeverityBadge(finding.severity)}
                                    {finding.risk_score !== undefined && (
                                      <div className="text-xs text-gray-500">
                                        Risk:{" "}
                                        <span className="font-bold text-gray-300">{finding.risk_score}</span>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Scan History tab (Phase B - correlation) */}
                      {activeTab === "scan_history" && (
                        <div className="space-y-4">
                          <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400">
                            Scan History
                          </h3>
                          {selectedAsset.first_scan_id || selectedAsset.last_scan_id ? (
                            <div className="space-y-2">
                              {selectedAsset.first_scan_id && (
                                <div className="rounded-lg border border-border bg-background p-3 flex items-center justify-between">
                                  <div>
                                    <div className="text-xs text-gray-500">First discovered by</div>
                                    <Link
                                      to={`/scans/${selectedAsset.first_scan_id}`}
                                      className="font-mono text-sm text-cyan-400 hover:underline"
                                    >
                                      scan #{selectedAsset.first_scan_id.slice(0, 8)}
                                    </Link>
                                  </div>
                                </div>
                              )}
                              {selectedAsset.last_scan_id &&
                                selectedAsset.last_scan_id !== selectedAsset.first_scan_id && (
                                  <div className="rounded-lg border border-border bg-background p-3 flex items-center justify-between">
                                    <div>
                                      <div className="text-xs text-gray-500">Last verified by</div>
                                      <Link
                                        to={`/scans/${selectedAsset.last_scan_id}`}
                                        className="font-mono text-sm text-cyan-400 hover:underline"
                                      >
                                        scan #{selectedAsset.last_scan_id.slice(0, 8)}
                                      </Link>
                                    </div>
                                    {selectedAsset.last_verified_at && (
                                      <div className="text-xs text-gray-500">
                                        {new Date(selectedAsset.last_verified_at).toLocaleString()}
                                      </div>
                                    )}
                                  </div>
                                )}
                              {selectedAsset.first_discovered_at && (
                                <div className="rounded-lg border border-border bg-background p-3">
                                  <div className="text-xs text-gray-500">First discovered</div>
                                  <div className="text-sm text-gray-300">
                                    {new Date(selectedAsset.first_discovered_at).toLocaleString()}
                                  </div>
                                </div>
                              )}
                            </div>
                          ) : (
                            <p className="text-sm text-gray-500">No scan history available.</p>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

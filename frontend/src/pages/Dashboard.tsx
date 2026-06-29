import { useEffect, useState, useRef } from "react";
import { Link } from "react-router-dom";
import {
  Shield,
  AlertTriangle,
  Server,
  Activity,
  CheckCircle,
  Loader2,
  RefreshCw,
  Plus
} from "lucide-react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  LineChart,
  Line,
  CartesianGrid,
  Legend,
  RadialBarChart,
  RadialBar
} from "recharts";

interface SummaryData {
  pqc_readiness_score: number;
  total_assets: number;
  vulnerable_count: number;
  hybrid_count: number;
  pqc_ready_count: number;
  safe_count: number;
  critical_findings: number;
  high_findings: number;
  drift_alerts_count: number;
}

interface RiskDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface ProgressItem {
  scan_date: string;
  vulnerable: number;
  hybrid: number;
  pqc_ready: number;
}

interface Asset {
  id: string;
  name: string;
  asset_type: string;
  ip_address?: string;
  fqdn?: string;
  environment: string;
  risk_score: number;
  pqc_status: "vulnerable" | "hybrid" | "pqc_ready" | "safe";
  last_verified_at?: string;
}

interface LayerCoverage {
  layers: LayerCoverageItem[];
  overall_coverage_pct: number;
}

interface LayerCoverageItem {
  layer_id: string;
  layer_name: string;
  description: string;
  total_assets: number;
  scanned_assets: number;
  vulnerable_assets: number;
  hybrid_assets: number;
  pqc_ready_assets: number;
  coverage_pct: number;
  risk_score_avg: number;
}

export default function Dashboard() {
  const [summary, setSummary] = useState<SummaryData | null>(null);
  const [distribution, setDistribution] = useState<RiskDistribution | null>(null);
  const [progress, setProgress] = useState<ProgressItem[]>([]);
  const [topAssets, setTopAssets] = useState<Asset[]>([]);
  const [layerCoverage, setLayerCoverage] = useState<LayerCoverage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  useEffect(() => {
    // Check reduced motion preference
    const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    setPrefersReducedMotion(mediaQuery.matches);
    const handler = (e: MediaQueryListEvent) => setPrefersReducedMotion(e.matches);
    mediaQuery.addEventListener("change", handler);
    return () => mediaQuery.removeEventListener("change", handler);
  }, []);

  const cacheRef = useRef<{ data: any; timestamp: number } | null>(null);
  const CACHE_TTL_MS = 30_000; // 30 seconds

  const fetchData = async (force = false) => {
    const now = Date.now();
    if (!force && cacheRef.current && now - cacheRef.current.timestamp < CACHE_TTL_MS) {
      const cached = cacheRef.current.data;
      setSummary(cached.summary);
      setDistribution(cached.distribution);
      setProgress(cached.progress);
      setTopAssets(cached.topAssets);
      setLayerCoverage(cached.layerCoverage);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      setError(null);
      const headers = {
        Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
      };

      const [summaryRes, distRes, progressRes, assetsRes, layerRes] = await Promise.all([
        fetch("/api/v1/dashboard/summary", { headers }),
        fetch("/api/v1/dashboard/risk-distribution", { headers }),
        fetch("/api/v1/dashboard/progress", { headers }),
        fetch("/api/v1/assets?limit=10&sort_by=risk_score&sort_order=desc", { headers }),
        fetch("/api/v1/dashboard/layer-coverage", { headers }).catch(() => null)
      ]);

      if (!summaryRes.ok || !distRes.ok || !progressRes.ok || !assetsRes.ok) {
        throw new Error("Failed to load dashboard metrics.");
      }

      const summaryData = await summaryRes.json();
      const distData = await distRes.json();
      const progressData = await progressRes.json();
      const assetsData = await assetsRes.json();
      const layerData = layerRes && layerRes.ok ? await layerRes.json() : null;

      setSummary(summaryData);
      setDistribution(distData);
      setProgress(progressData);
      setTopAssets(assetsData);
      setLayerCoverage(layerData);

      cacheRef.current = {
        data: {
          summary: summaryData,
          distribution: distData,
          progress: progressData,
          topAssets: assetsData,
          layerCoverage: layerData,
        },
        timestamp: Date.now(),
      };
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error loading dashboard");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    const handleRefresh = () => {
      fetchData(true);
    };
    window.addEventListener("dashboard:refresh", handleRefresh);
    return () => {
      window.removeEventListener("dashboard:refresh", handleRefresh);
    };
  }, []);

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-blue-500" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-800/50 bg-red-950/30 p-5 text-center text-red-400">
        <p className="font-semibold">Failed to load dashboard metrics</p>
        <p className="mt-1 text-sm text-red-500">{error}</p>
        <button
          onClick={() => fetchData(true)}
          className="mt-4 inline-flex items-center gap-1.5 rounded-md border border-red-800 bg-red-950/50 px-3.5 py-1.5 text-xs text-red-300 hover:bg-red-900/50"
        >
          <RefreshCw className="h-3 w-3" />
          Retry Load
        </button>
      </div>
    );
  }

  // If no scans run or zero assets found, show onboarding
  const hasNoData = !summary || summary.total_assets === 0;

  if (hasNoData) {
    return (
      <div className="flex h-96 flex-col items-center justify-center text-center p-8 rounded-lg border border-border bg-surface bg-[#0d1117]">
        <Shield className="h-12 w-12 text-gray-500 mb-4" />
        <h2 className="text-xl font-semibold text-gray-200">No cryptographic scans have been run yet</h2>
        <p className="mt-2 text-sm text-gray-400 max-w-md">
          Run your first Post-Quantum Cryptography target scan or connect a CMDB data source to begin auditing algorithms.
        </p>
        <div className="mt-6 flex gap-3">
          <Link
            to="/scans"
            className="flex items-center gap-1.5 rounded-md bg-[#2ea043] px-4 py-2 text-sm font-semibold text-white hover:bg-[#23863c] shadow-sm transition"
          >
            <Plus className="h-4 w-4" />
            Run First Scan
          </Link>
        </div>
      </div>
    );
  }

  // Donut chart data
  const donutData = [
    { name: "Critical", value: distribution?.critical || 0, color: "#f85149" },
    { name: "High", value: distribution?.high || 0, color: "#f0883e" },
    { name: "Medium", value: distribution?.medium || 0, color: "#dbab09" },
    { name: "Low", value: distribution?.low || 0, color: "#56d364" },
  ].filter(d => d.value > 0);

  // If no findings, show a placeholder segment so piechart renders
  if (donutData.length === 0) {
    donutData.push({ name: "No active findings", value: 1, color: "#21262d" });
  }

  // HNDL buckets calculation:
  // Bucket group criteria: 0-3, 4-7, 8-12, 13+
  const hndlBuckets = [
    { range: "0-3 years", count: 0, fill: "#f85149" },
    { range: "4-7 years", count: 0, fill: "#f0883e" },
    { range: "8-12 years", count: 0, fill: "#dbab09" },
    { range: "13+ years", count: 0, fill: "#56d364" }
  ];

  topAssets.forEach(asset => {
    if (asset.pqc_status === "pqc_ready" || asset.pqc_status === "hybrid" || asset.pqc_status === "safe") {
      hndlBuckets[3].count += 1;
    } else {
      // Vulnerable assets: default mock deadline is 2030 (4 years away, bucket 4-7)
      hndlBuckets[1].count += 1;
    }
  });

  // Gauge data for readiness score
  const score = summary?.pqc_readiness_score || 0;
  const gaugeData = [
    {
      name: "Readiness",
      value: score,
      fill: score > 70 ? "#56d364" : score > 30 ? "#dbab09" : "#f85149"
    }
  ];

  return (
    <div className="space-y-6">

      {/* Top Level Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <div className="rounded-lg border border-border bg-surface p-5 flex items-center justify-between shadow-sm">
          <div>
            <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">Total Assets</p>
            <p className="mt-2 text-2xl font-bold text-gray-100 font-mono">{summary?.total_assets}</p>
          </div>
          <div className="rounded-full bg-blue-950/30 border border-blue-800/50 p-2 text-blue-400">
            <Server className="h-5 w-5" />
          </div>
        </div>

        <div className="rounded-lg border border-border bg-surface p-5 flex items-center justify-between shadow-sm">
          <div>
            <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">Vulnerable</p>
            <p className="mt-2 text-2xl font-bold text-red-400 font-mono">{summary?.vulnerable_count}</p>
          </div>
          <div className="rounded-full bg-red-950/30 border border-red-800/50 p-2 text-red-400">
            <AlertTriangle className="h-5 w-5" />
          </div>
        </div>

        <div className="rounded-lg border border-border bg-surface p-5 flex items-center justify-between shadow-sm">
          <div>
            <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">PQC Ready</p>
            <p className="mt-2 text-2xl font-bold text-green-400 font-mono">
              {(summary?.pqc_ready_count || 0) + (summary?.hybrid_count || 0)}
            </p>
          </div>
          <div className="rounded-full bg-green-950/30 border border-green-800/50 p-2 text-green-400">
            <CheckCircle className="h-5 w-5" />
          </div>
        </div>

        <div className="rounded-lg border border-border bg-surface p-5 flex items-center justify-between shadow-sm">
          <div>
            <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">Safe</p>
            <p className="mt-2 text-2xl font-bold text-emerald-400 font-mono">{summary?.safe_count}</p>
          </div>
          <div className="rounded-full bg-emerald-950/30 border border-emerald-800/50 p-2 text-emerald-400">
            <Shield className="h-5 w-5" />
          </div>
        </div>

        {summary && summary.drift_alerts_count > 0 ? (
          <Link
            to="/findings?finding_type=pqc_downgrade"
            className="rounded-lg border border-yellow-800/50 bg-yellow-950/10 p-5 flex items-center justify-between shadow-sm hover:bg-yellow-950/20 transition cursor-pointer"
          >
            <div>
              <p className="text-xs font-medium text-yellow-400 uppercase tracking-wider">Drift Alerts</p>
              <p className="mt-2 text-2xl font-bold text-yellow-400 font-mono">{summary.drift_alerts_count}</p>
            </div>
            <div className="rounded-full bg-yellow-950/30 border border-yellow-800/50 p-2 text-yellow-400">
              <Activity className="h-5 w-5" />
            </div>
          </Link>
        ) : (
          <div className="rounded-lg border border-border bg-surface p-5 flex items-center justify-between shadow-sm">
            <div>
              <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">Drift Alerts</p>
              <p className="mt-2 text-2xl font-bold text-gray-400 font-mono">0</p>
            </div>
            <div className="rounded-full bg-gray-800 border border-gray-700 p-2 text-gray-500">
              <Activity className="h-5 w-5" />
            </div>
          </div>
        )}
      </div>

      {/* Row 2: Gauge & Donut & HNDL */}
      <div className="grid gap-4 md:grid-cols-3">
        {/* Gauge Card */}
        <div className="rounded-lg border border-border bg-surface p-5 flex flex-col items-center justify-between min-h-[300px]">
          <div className="w-full">
            <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">PQC Readiness</h3>
            <p className="text-xs text-gray-500">Percentage of inventory running secure hybrid or PQC algorithms.</p>
          </div>
          <div className="relative w-full h-44 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <RadialBarChart
                cx="50%"
                cy="50%"
                innerRadius="70%"
                outerRadius="100%"
                barSize={14}
                data={gaugeData}
                startAngle={180}
                endAngle={0}
              >
                <RadialBar
                  background
                  dataKey="value"
                  cornerRadius={10}
                  isAnimationActive={!prefersReducedMotion}
                />
              </RadialBarChart>
            </ResponsiveContainer>
            <div className="absolute mt-12 flex flex-col items-center justify-center">
              <span className="text-4xl font-bold text-gray-100 font-mono">{score.toFixed(0)}%</span>
              <span className="text-xs font-semibold text-gray-500 uppercase mt-1">Readiness</span>
            </div>
          </div>
          <div className="text-center text-xs text-gray-400">
            {score > 70 ? (
              <span className="text-green-400 font-medium">Strong posture. Maintain hybrid transition.</span>
            ) : score > 30 ? (
              <span className="text-yellow-400 font-medium">Transition in progress. Target legacy protocols next.</span>
            ) : (
              <span className="text-red-400 font-medium">Action required. Legacy public key infrastructure in use.</span>
            )}
          </div>
        </div>

        {/* Donut Card */}
        <div className="rounded-lg border border-border bg-surface p-5 flex flex-col justify-between min-h-[300px]">
          <div>
            <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">Risk Distribution</h3>
            <p className="text-xs text-gray-500">Active cryptographic vulnerabilities grouped by severity.</p>
          </div>
          <div className="h-44">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={donutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="value"
                  isAnimationActive={!prefersReducedMotion}
                >
                  {donutData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: "#161b22", borderColor: "#30363d" }}
                  itemStyle={{ color: "#c9d1d9" }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-4 text-xs">
            {donutData.map((d) => (
              <div key={d.name} className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: d.color }} />
                <span className="text-gray-400">{d.name}</span>
                <span className="text-gray-500 font-mono">({d.value})</span>
              </div>
            ))}
          </div>
        </div>

        {/* HNDL Timeline Card */}
        <div className="rounded-lg border border-border bg-surface p-5 flex flex-col justify-between min-h-[300px]">
          <div>
            <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">HNDL Exposure Timeline</h3>
            <p className="text-xs text-gray-500">Assets grouped by years remaining until quantum decryption risk.</p>
          </div>
          <div className="h-44">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={hndlBuckets} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <XAxis dataKey="range" tick={{ fill: "#8b949e", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "#8b949e", fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#161b22", borderColor: "#30363d" }}
                  labelStyle={{ color: "#8b949e" }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]} isAnimationActive={!prefersReducedMotion}>
                  {hndlBuckets.map((entry, idx) => (
                    <Cell key={`cell-${idx}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="text-center text-[10px] text-gray-500 italic">
            Estimated quantum timeline deadline: 2030 (CISA/NIST)
          </p>
        </div>
      </div>

      {/* Row 2b: Layer Coverage Heatmap (L1-L7) */}
      {layerCoverage && layerCoverage.layers && layerCoverage.layers.length > 0 && (
        <div className="rounded-lg border border-border bg-surface p-5 shadow-sm">
          <div className="flex items-baseline justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">
                Infrastructure Layer Coverage
              </h3>
              <p className="text-xs text-gray-500 mt-0.5">
                PQC scanning coverage across the 7-layer infrastructure model (L1–L7).
              </p>
            </div>
            <div className="text-right">
              <p className="text-[10px] text-gray-500 uppercase tracking-wider">Overall Coverage</p>
              <p className="text-xl font-bold font-mono text-gray-100">
                {layerCoverage.overall_coverage_pct.toFixed(1)}%
              </p>
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-7">
            {layerCoverage.layers.map((layer) => {
              const coverage = layer.coverage_pct;
              const intensity = Math.min(1, coverage / 100);
              // Heat color: red < 30, yellow 30-70, green >= 70
              const heatColor =
                coverage >= 70
                  ? `rgba(86, 211, 100, ${0.15 + intensity * 0.4})`
                  : coverage >= 30
                  ? `rgba(219, 171, 9, ${0.15 + intensity * 0.4})`
                  : `rgba(248, 81, 73, ${0.15 + intensity * 0.4})`;
              const textColor =
                coverage >= 70
                  ? "text-green-400"
                  : coverage >= 30
                  ? "text-yellow-400"
                  : "text-red-400";
              return (
                <div
                  key={layer.layer_id}
                  className="rounded-md border border-border p-3 flex flex-col justify-between min-h-[110px]"
                  style={{ backgroundColor: heatColor }}
                  title={layer.description}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold text-gray-300 uppercase">
                      {layer.layer_id}
                    </span>
                    <span className={`text-[10px] font-mono font-bold ${textColor}`}>
                      {coverage.toFixed(0)}%
                    </span>
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-gray-100">{layer.layer_name}</p>
                    <p className="text-[10px] text-gray-400 mt-0.5 line-clamp-2">
                      {layer.description}
                    </p>
                  </div>
                  <div className="mt-2 flex items-center justify-between text-[10px] font-mono">
                    <span className="text-gray-400">
                      {layer.scanned_assets}/{layer.total_assets}
                    </span>
                    {layer.risk_score_avg > 0 && (
                      <span className={textColor}>avg {layer.risk_score_avg}</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Row 3: Progress & Top 10 */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Migration Progress Line Chart */}
        <div className="rounded-lg border border-border bg-surface p-5">
          <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wider mb-2">Migration Progress</h3>
          <p className="text-xs text-gray-500 mb-4">Historical transition counts over the last 12 scans.</p>
          <div className="h-72">
            {progress.length === 0 ? (
              <div className="flex h-full items-center justify-center text-xs text-gray-500 italic">
                Insufficient historical scan history.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={progress} margin={{ top: 10, right: 20, left: -25, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262d" vertical={false} />
                  <XAxis dataKey="scan_date" tick={{ fill: "#8b949e", fontSize: 10 }} />
                  <YAxis tick={{ fill: "#8b949e", fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "#161b22", borderColor: "#30363d" }}
                    labelStyle={{ color: "#8b949e" }}
                  />
                  <Legend wrapperStyle={{ fontSize: 11, paddingTop: 10 }} />
                  <Line
                    type="monotone"
                    dataKey="vulnerable"
                    name="Vulnerable"
                    stroke="#f85149"
                    strokeWidth={2}
                    activeDot={{ r: 6 }}
                    isAnimationActive={!prefersReducedMotion}
                  />
                  <Line
                    type="monotone"
                    dataKey="hybrid"
                    name="Hybrid"
                    stroke="#f0883e"
                    strokeWidth={2}
                    isAnimationActive={!prefersReducedMotion}
                  />
                  <Line
                    type="monotone"
                    dataKey="pqc_ready"
                    name="PQC Ready"
                    stroke="#56d364"
                    strokeWidth={2}
                    isAnimationActive={!prefersReducedMotion}
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Top 10 Vulnerable Assets Table */}
        <div className="rounded-lg border border-border bg-surface p-5 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wider mb-2">
              Top Cryptographic Vulnerability Targets
            </h3>
            <p className="text-xs text-gray-500 mb-4">Highest risk-scored assets in open findings queue.</p>
          </div>
          <div className="h-72 overflow-y-auto border border-border rounded">
            <table className="w-full text-left text-xs text-gray-300">
              <thead className="bg-background text-gray-400 border-b border-border sticky top-0">
                <tr>
                  <th className="px-4 py-2">Asset Name</th>
                  <th className="px-4 py-2">Env</th>
                  <th className="px-4 py-2">PQC Status</th>
                  <th className="px-4 py-2 text-right">Risk Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {topAssets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-background/20 transition">
                    <td className="px-4 py-3 font-medium">
                      <Link to={`/assets/${asset.id}`} className="text-blue-400 hover:underline">
                        {asset.name}
                      </Link>
                    </td>
                    <td className="px-4 py-3 capitalize text-gray-400">{asset.environment}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold border ${
                          asset.pqc_status === "safe"
                            ? "bg-emerald-950/40 text-emerald-400 border-emerald-800/50"
                            : asset.pqc_status === "pqc_ready"
                            ? "bg-green-950/40 text-green-400 border-green-800/50"
                            : asset.pqc_status === "hybrid"
                            ? "bg-blue-950/40 text-blue-400 border-blue-800/50"
                            : "bg-red-950/40 text-red-400 border-red-800/50"
                        }`}
                      >
                        {asset.pqc_status.replace("_", "-")}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right font-mono font-bold">
                      <span
                        style={{
                          color:
                            asset.risk_score > 75
                              ? "#f85149"
                              : asset.risk_score > 35
                              ? "#f0883e"
                              : "#56d364"
                        }}
                      >
                        {asset.risk_score}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import {
  TrendingUp,
  Award,
  Calendar,
  CheckCircle,
  Activity,
  ArrowRight,
  Loader2,
  RefreshCw,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";

interface MigrationHistoryItem {
  month: string;
  classical: number;
  hybrid: number;
  pqc_ready: number;
}

interface MigrationData {
  overall_pqc_transition_pct: number;
  hybrid_deployment_pct: number;
  pqc_ready_count: number;
  estimated_deadline: string;
  mosca_risk_level: string;
  data_longevity_d: number;
  migration_duration_t: number;
  cryptographic_collapse_y: number;
  history: MigrationHistoryItem[];
}

export default function Migration() {
  const [data, setData] = useState<MigrationData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);
      const headers = {
        Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
      };
      const res = await fetch("/api/v1/dashboard/migration", { headers });
      if (!res.ok) {
        throw new Error("Failed to load migration data.");
      }
      const jsonData = await res.json();
      setData(jsonData);
    } catch (err: any) {
      setError(err.message || "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-cyan-400" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded-lg border border-red-800 bg-red-950/20 p-6 text-center text-red-400 space-y-3">
        <p className="font-semibold">Error Loading Data</p>
        <p className="text-sm">{error || "Could not retrieve migration metrics."}</p>
        <button
          onClick={() => fetchData()}
          className="inline-flex items-center gap-2 rounded bg-red-900/40 px-4 py-2 text-xs font-semibold hover:bg-red-900/60 transition-colors"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Retry
        </button>
      </div>
    );
  }

  const isSafe = data.data_longevity_d + data.migration_duration_t < data.cryptographic_collapse_y;

  return (
    <div className="space-y-6">

      <div className="grid gap-6 md:grid-cols-4">
        {/* KPI Cards */}
        <div className="rounded-lg border border-border bg-surface p-6 space-y-2">
          <div className="flex items-center justify-between text-xs text-gray-500 uppercase font-semibold">
            <span>Overall PQC Transition</span>
            <TrendingUp className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-gray-200">{data.overall_pqc_transition_pct}%</div>
          <div className="text-xs text-green-400 font-semibold">Transitioning algorithms</div>
        </div>

        <div className="rounded-lg border border-border bg-surface p-6 space-y-2">
          <div className="flex items-center justify-between text-xs text-gray-500 uppercase font-semibold">
            <span>Hybrid Deployment</span>
            <Award className="h-4 w-4 text-blue-450" />
          </div>
          <div className="text-2xl font-bold text-gray-200">{data.hybrid_deployment_pct}%</div>
          <div className="text-xs text-gray-400">Targeting 80% by Q4</div>
        </div>

        <div className="rounded-lg border border-border bg-surface p-6 space-y-2">
          <div className="flex items-center justify-between text-xs text-gray-500 uppercase font-semibold">
            <span>PQC Ready Nodes</span>
            <CheckCircle className="h-4 w-4 text-green-400" />
          </div>
          <div className="text-2xl font-bold text-gray-200">{data.pqc_ready_count}</div>
          <div className="text-xs text-gray-400">{data.pqc_ready_count} endpoints pure quantum safe</div>
        </div>

        <div className="rounded-lg border border-border bg-surface p-6 space-y-2">
          <div className="flex items-center justify-between text-xs text-gray-500 uppercase font-semibold">
            <span>Estimated Deadline</span>
            <Calendar className="h-4 w-4 text-yellow-450" />
          </div>
          <div className="text-2xl font-bold text-gray-200">{data.estimated_deadline}</div>
          <div className="text-xs text-yellow-450 font-semibold">Mosca's Theorem Risk Level: {data.mosca_risk_level.toUpperCase()}</div>
        </div>
      </div>

      {/* Migration Trend Chart */}
      <div className="rounded-lg border border-border bg-surface p-6 space-y-4">
        <h2 className="text-lg font-bold text-gray-200">Crypto Transition Timeline (Last 6 Months)</h2>
        <div className="h-80 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data.history}>
              <defs>
                <linearGradient id="pqc" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#2ea043" stopOpacity={0.2}/>
                  <stop offset="95%" stopColor="#2ea043" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="hybrid" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#58a6ff" stopOpacity={0.2}/>
                  <stop offset="95%" stopColor="#58a6ff" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="classical" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f85149" stopOpacity={0.2}/>
                  <stop offset="95%" stopColor="#f85149" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
              <XAxis dataKey="month" stroke="#8b949e" tick={{ fontSize: 12 }} />
              <YAxis stroke="#8b949e" tick={{ fontSize: 12 }} />
              <Tooltip
                contentStyle={{ backgroundColor: "#161b22", borderColor: "#30363d" }}
                itemStyle={{ color: "#f0f6fc" }}
              />
              <Area type="monotone" dataKey="pqc_ready" stackId="1" stroke="#2ea043" fillOpacity={1} fill="url(#pqc)" name="PQC Ready" />
              <Area type="monotone" dataKey="hybrid" stackId="1" stroke="#58a6ff" fillOpacity={1} fill="url(#hybrid)" name="Hybrid Transition" />
              <Area type="monotone" dataKey="classical" stackId="1" stroke="#f85149" fillOpacity={1} fill="url(#classical)" name="Quantum Vulnerable" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Active Migration Pipelines */}
        <div className="rounded-lg border border-border bg-surface p-6 space-y-4">
          <h2 className="text-lg font-bold text-gray-200">Recommended Algorithmic Pipelines</h2>
          <div className="space-y-4">
            <div className="rounded-lg border border-border bg-background p-4 flex items-center justify-between">
              <div className="space-y-1">
                <div className="text-xs text-gray-500 font-semibold uppercase">Signature Verification</div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm text-red-400">RSA-2048</span>
                  <ArrowRight className="h-4 w-4 text-gray-400" />
                  <span className="font-mono text-sm text-green-400 font-bold">ML-DSA-65</span>
                </div>
              </div>
              <span className="inline-flex rounded-full bg-green-950/40 border border-green-800/50 px-2 py-0.5 text-xs font-semibold text-green-400">
                Primary Path
              </span>
            </div>

            <div className="rounded-lg border border-border bg-background p-4 flex items-center justify-between">
              <div className="space-y-1">
                <div className="text-xs text-gray-500 font-semibold uppercase">Key Exchange & KEM</div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm text-red-400">ECDH-P256</span>
                  <ArrowRight className="h-4 w-4 text-gray-400" />
                  <span className="font-mono text-sm text-green-400 font-bold">ML-KEM-768</span>
                </div>
              </div>
              <span className="inline-flex rounded-full bg-green-950/40 border border-green-800/50 px-2 py-0.5 text-xs font-semibold text-green-400">
                Primary Path
              </span>
            </div>

            <div className="rounded-lg border border-border bg-background p-4 flex items-center justify-between">
              <div className="space-y-1">
                <div className="text-xs text-gray-500 font-semibold uppercase">SSH Key Exchange</div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm text-red-400">ecdh-sha2-nistp256</span>
                  <ArrowRight className="h-4 w-4 text-gray-400" />
                  <span className="font-mono text-sm text-blue-400 font-bold">X25519MLKEM768</span>
                </div>
              </div>
              <span className="inline-flex rounded-full bg-blue-950/40 border border-blue-800/50 px-2 py-0.5 text-xs font-semibold text-blue-400">
                Hybrid Stage
              </span>
            </div>
          </div>
        </div>

        {/* Mosca's Theorem Risk Assessment */}
        <div className="rounded-lg border border-border bg-surface p-6 space-y-4">
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-cyan-400" />
            <h2 className="text-lg font-bold text-gray-200">Mosca's Theorem Assessment</h2>
          </div>
          <p className="text-xs text-gray-400 leading-relaxed">
            Mosca's Theorem defines risk by evaluating: <code className="text-cyan-400">D + T &gt; Y</code>.
            If data shelf-life (D) plus migration execution time (T) is larger than the years until quantum computers break classical public keys (Y), then your secrets are exposed today.
          </p>
          <div className="rounded-lg border border-border bg-background p-4 space-y-3 font-mono text-xs text-gray-305">
            <div className="flex justify-between">
              <span className="text-gray-500">Data Longevity (D)</span>
              <span>{data.data_longevity_d} Years</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Migration Duration (T)</span>
              <span>{data.migration_duration_t} Years</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Years until Cryptographic Collapse (Y)</span>
              <span>{data.cryptographic_collapse_y} Years</span>
            </div>
            <div className="border-t border-border pt-2 flex justify-between font-bold">
              <span className="text-gray-500">Risk Assessment Equation</span>
              {isSafe ? (
                <span className="text-green-400">{data.data_longevity_d} + {data.migration_duration_t} &lt; {data.cryptographic_collapse_y} (Safe Margin)</span>
              ) : (
                <span className="text-red-400">{data.data_longevity_d} + {data.migration_duration_t} &gt;= {data.cryptographic_collapse_y} (Exposure Risk!)</span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

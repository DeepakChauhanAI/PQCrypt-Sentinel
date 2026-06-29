import { useEffect, useState, useRef } from "react";
import { useParams, Link } from "react-router-dom";
import {
  ArrowLeft,
  Calendar,
  Clock,
  Loader2,
  Terminal,
  ShieldAlert,
  Shield,
  Activity,
  AlertOctagon,
  ChevronDown,
  ChevronRight,
} from "lucide-react";

interface Scan {
  id: string;
  scan_type: string;
  target: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  config?: string;
  credential_profile?: string;
  started_at?: string;
  completed_at?: string;
  duration_seconds?: number;
  assets_found: number;
  findings_created: number;
  error_message?: string;
  created_at: string;
}

interface ScanLog {
  id: string;
  scan_id: string;
  level: "debug" | "info" | "warn" | "error" | "fatal";
  phase?: string;
  message: string;
  details?: Record<string, any>;
  timestamp: string;
}

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedLog, setExpandedLog] = useState<string | null>(null);

  const consoleEndRef = useRef<HTMLDivElement>(null);

  const fetchScanAndLogs = async () => {
    if (!id) return;
    try {
      // Fetch scan
      const scanRes = await fetch(`/api/v1/scans/${id}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
      });
      if (!scanRes.ok) throw new Error("Failed to load scan details");
      const scanData = await scanRes.json();
      setScan(scanData);

      // Fetch logs
      const logsRes = await fetch(`/api/v1/scans/${id}/logs`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
      });
      if (logsRes.ok) {
        const logsData = await logsRes.json();
        setLogs(logsData);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScanAndLogs();
  }, [id]);

  // Polling logic when scan is active
  useEffect(() => {
    if (!scan) return;
    const isRunning = scan.status === "running" || scan.status === "queued";
    let interval: number | undefined;

    if (isRunning) {
      interval = window.setInterval(fetchScanAndLogs, 3000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [scan?.status]);

  // Auto-scroll logs console
  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const handleCancelScan = async () => {
    if (!id) return;
    try {
      const response = await fetch(`/api/v1/scans/${id}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
      });

      if (!response.ok) throw new Error("Failed to cancel scan");
      await fetchScanAndLogs();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error cancelling scan");
    }
  };

  const getLogLevelColor = (level: ScanLog["level"]) => {
    switch (level) {
      case "debug":
        return "text-gray-500";
      case "info":
        return "text-blue-400";
      case "warn":
        return "text-yellow-500 font-medium";
      case "error":
        return "text-red-400 font-semibold";
      case "fatal":
        return "text-red-600 font-extrabold uppercase bg-red-950/30 px-1 rounded";
      default:
        return "text-gray-300";
    }
  };

  if (loading && !scan) {
    return (
      <div className="flex h-96 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="rounded-lg border border-red-800/50 bg-red-950/30 p-6 text-center">
        <ShieldAlert className="mx-auto h-12 w-12 text-red-500 mb-3" />
        <h3 className="text-lg font-semibold text-red-400">Scan not found</h3>
        <p className="mt-2 text-sm text-gray-400">
          {error ?? "The scan details could not be retrieved. Please check the ID."}
        </p>
        <Link
          to="/scans"
          className="mt-4 inline-flex items-center gap-1.5 rounded-md bg-surface border border-border px-4 py-2 text-sm font-semibold text-gray-300 hover:bg-border transition duration-150"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Scans
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header breadcrumb */}
      <div>
        <Link
          to="/scans"
          className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-gray-200 transition duration-150"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Scans
        </Link>
        <div className="flex items-center justify-between mt-2">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-gray-100">
              Scan: {scan.target}
            </h1>
            <p className="text-xs text-gray-500 font-mono mt-0.5">ID: {scan.id}</p>
          </div>
          <div className="flex items-center gap-3">
            {(scan.status === "queued" || scan.status === "running") && (
              <button
                onClick={handleCancelScan}
                className="rounded-md border border-red-900/50 bg-red-950/20 px-3.5 py-2 text-sm font-semibold text-red-400 hover:bg-red-950/50 transition duration-150"
              >
                Cancel Scan
              </button>
            )}
            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-sm font-medium ${
                scan.status === "completed"
                  ? "bg-green-950/40 text-green-400 border-green-800/50"
                  : scan.status === "failed"
                  ? "bg-red-950/40 text-red-400 border-red-800/50"
                  : scan.status === "cancelled"
                  ? "bg-gray-800/50 text-gray-400 border-gray-700/50"
                  : "bg-yellow-950/40 text-yellow-400 border-yellow-800/50"
              }`}
            >
              {(scan.status === "running" || scan.status === "queued") && (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              )}
              {scan.status.toUpperCase()}
            </span>
          </div>
        </div>
      </div>

      {/* Grid of stats */}
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-lg border border-border bg-surface p-5">
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Type</p>
          <p className="mt-2 text-2xl font-bold text-gray-200 capitalize">
            {scan.scan_type.replace("_", " ")}
          </p>
        </div>
        <div className="rounded-lg border border-border bg-surface p-5">
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Assets Discovered</p>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-gray-100">{scan.assets_found}</span>
            <Shield className="h-4 w-4 text-green-400" />
          </div>
        </div>
        <div className="rounded-lg border border-border bg-surface p-5">
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Findings Created</p>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-red-400">{scan.findings_created}</span>
            <ShieldAlert className="h-4 w-4 text-red-400" />
          </div>
        </div>
        <div className="rounded-lg border border-border bg-surface p-5">
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Time Info</p>
          <div className="mt-2 text-sm text-gray-400 space-y-1">
            <p className="flex items-center gap-1.5">
              <Calendar className="h-4 w-4 shrink-0 text-gray-500" />
              Started: {scan.started_at ? new Date(scan.started_at).toLocaleTimeString() : "Pending"}
            </p>
            <p className="flex items-center gap-1.5">
              <Clock className="h-4 w-4 shrink-0 text-gray-500" />
              Duration: {scan.duration_seconds !== null && scan.duration_seconds !== undefined ? `${scan.duration_seconds}s` : "In Progress"}
            </p>
          </div>
        </div>
      </section>

      {scan.error_message && (
        <div className="rounded-lg border border-red-800/50 bg-red-950/30 p-4">
          <div className="flex items-start gap-3">
            <AlertOctagon className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
            <div>
              <h4 className="text-sm font-semibold text-red-400">Scan Error</h4>
              <p className="mt-1 text-sm text-gray-300 font-mono bg-background/50 p-2.5 rounded border border-border mt-2">
                {scan.error_message}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Logs Console */}
      <div className="rounded-lg border border-border bg-[#0d1117] shadow-xl overflow-hidden flex flex-col h-[500px]">
        {/* Console Header */}
        <div className="flex items-center justify-between border-b border-border bg-[#161b22] px-4 py-3">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-blue-400" />
            <span className="text-sm font-semibold text-gray-200">Live Execution Console</span>
          </div>
          {(scan.status === "running" || scan.status === "queued") && (
            <div className="flex items-center gap-2 text-xs text-yellow-500">
              <Activity className="h-3.5 w-3.5 animate-pulse" />
              <span>Polling updates...</span>
            </div>
          )}
        </div>

        {/* Console Body */}
        <div className="flex-1 overflow-y-auto p-4 font-mono text-xs leading-relaxed space-y-1.5 scrollbar-thin">
          {logs.length === 0 ? (
            <p className="text-gray-600 italic">No execution logs generated yet.</p>
          ) : (
            logs.map((log) => (
              <div key={log.id} className="border-b border-gray-900/20 pb-1">
                <div className="flex items-start gap-2">
                  <span className="text-gray-600 shrink-0 select-none">
                    [{new Date(log.timestamp).toLocaleTimeString()}]
                  </span>
                  {log.phase && (
                    <span className="text-cyan-600 shrink-0 font-semibold uppercase tracking-wider text-[10px]">
                      {log.phase}
                    </span>
                  )}
                  <span className={`${getLogLevelColor(log.level)} shrink-0 font-semibold text-[10px] w-12`}>
                    {log.level.toUpperCase()}
                  </span>
                  <div className="flex-1 whitespace-pre-wrap text-gray-200">
                    {log.message}
                  </div>
                  {log.details && (
                    <button
                      onClick={() =>
                        setExpandedLog(expandedLog === log.id ? null : log.id)
                      }
                      className="text-gray-500 hover:text-gray-300"
                    >
                      {expandedLog === log.id ? (
                        <ChevronDown className="h-4 w-4" />
                      ) : (
                        <ChevronRight className="h-4 w-4" />
                      )}
                    </button>
                  )}
                </div>
                {log.details && expandedLog === log.id && (
                  <pre className="mt-2 ml-14 overflow-x-auto rounded bg-surface p-3 border border-border text-gray-400 font-mono text-[11px]">
                    {JSON.stringify(log.details, null, 2)}
                  </pre>
                )}
              </div>
            ))
          )}
          <div ref={consoleEndRef} />
        </div>
      </div>
    </div>
  );
}

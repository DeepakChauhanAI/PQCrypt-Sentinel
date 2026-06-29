import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Play,
  XCircle,
  AlertCircle,
  CheckCircle2,
  Loader2,
  Calendar,
  Clock,
  Plus,
  Shield,
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

export default function ScanList() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Modal State
  const [showModal, setShowModal] = useState(false);
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("full");
  const [credentialProfile, setCredentialProfile] = useState("");
  const [advancedTools, setAdvancedTools] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const fetchScans = async () => {
    try {
      const response = await fetch("/api/v1/scans", {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
      });
      if (!response.ok) {
        throw new Error("Failed to load scans");
      }
      const data = await response.json();
      setScans(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  useEffect(() => {
    const interval = window.setInterval(fetchScans, 4000);
    return () => window.clearInterval(interval);
  }, [fetchScans]);

  const handleCreateScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      const response = await fetch("/api/v1/scans", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify({
          scan_type: scanType,
          target: target,
          credential_profile: credentialProfile || null,
          advanced_tools: advancedTools,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to start scan");
      }

      await fetchScans();
      setShowModal(false);
      setTarget("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error starting scan");
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancelScan = async (scanId: string) => {
    try {
      const response = await fetch(`/api/v1/scans/${scanId}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
      });

      if (!response.ok) {
        throw new Error("Failed to cancel scan");
      }

      await fetchScans();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error cancelling scan");
    }
  };

  const getStatusBadge = (status: Scan["status"]) => {
    const badges = {
      queued: {
        bg: "bg-blue-900/30 text-blue-400 border-blue-800/50",
        icon: Loader2,
        label: "Queued",
        animate: "animate-spin",
      },
      running: {
        bg: "bg-yellow-950/40 text-yellow-400 border-yellow-800/50",
        icon: Loader2,
        label: "Running",
        animate: "animate-spin",
      },
      completed: {
        bg: "bg-green-950/40 text-green-400 border-green-800/50",
        icon: CheckCircle2,
        label: "Completed",
        animate: "",
      },
      failed: {
        bg: "bg-red-950/40 text-red-400 border-red-800/50",
        icon: AlertCircle,
        label: "Failed",
        animate: "",
      },
      cancelled: {
        bg: "bg-gray-800/50 text-gray-400 border-gray-700/50",
        icon: XCircle,
        label: "Cancelled",
        animate: "",
      },
    };

    const b = badges[status] || badges.queued;
    const Icon = b.icon;

    return (
      <span
        className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${b.bg}`}
      >
        <Icon className={`h-3 w-3 ${b.animate}`} />
        {b.label}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-end">
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-1.5 rounded-md bg-[#2ea043] px-3.5 py-2 text-sm font-semibold text-white hover:bg-[#23863c] transition duration-150 shadow-sm"
        >
          <Plus className="h-4 w-4" />
          New Scan
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-800/50 bg-red-950/30 p-4 text-sm text-red-400">
          {error}
        </div>
      )}

      {loading ? (
        <div className="flex h-64 items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
        </div>
      ) : scans.length === 0 ? (
        <div className="flex h-64 flex-col items-center justify-center rounded-lg border border-border bg-surface p-8 text-center">
          <Shield className="h-10 w-10 text-gray-500 mb-3" />
          <h3 className="text-base font-semibold text-gray-200">No scans found</h3>
          <p className="mt-1 text-sm text-gray-400 max-w-sm">
            Ready to audit your environment? Start by initiating your first cryptographic scan.
          </p>
          <button
            onClick={() => setShowModal(true)}
            className="mt-4 inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-4 py-2 text-sm font-semibold text-gray-300 hover:bg-border transition duration-150"
          >
            <Plus className="h-4 w-4" />
            Trigger Scan
          </button>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border bg-surface shadow-md">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-sm text-gray-300">
              <thead className="bg-background text-xs font-semibold uppercase tracking-wider text-gray-400 border-b border-border">
                <tr>
                  <th className="px-6 py-4">Target</th>
                  <th className="px-6 py-4">Type</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4">Assets</th>
                  <th className="px-6 py-4">Findings</th>
                  <th className="px-6 py-4">Triggered At</th>
                  <th className="px-6 py-4">Duration</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="hover:bg-background/40 transition duration-150"
                  >
                    <td className="whitespace-nowrap px-6 py-4">
                      <Link
                        to={`/scans/${scan.id}`}
                        className="font-medium text-blue-400 hover:underline"
                      >
                        {scan.target || "N/A"}
                      </Link>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 capitalize">
                      {scan.scan_type.replace("_", " ")}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4">
                      {getStatusBadge(scan.status)}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 font-mono">
                      {scan.assets_found}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 font-mono text-red-400">
                      {scan.findings_created}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-xs text-gray-400">
                      <span className="flex items-center gap-1">
                        <Calendar className="h-3.5 w-3.5" />
                        {new Date(scan.created_at).toLocaleString()}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-xs text-gray-400 font-mono">
                      {scan.duration_seconds !== null &&
                      scan.duration_seconds !== undefined ? (
                        <span className="flex items-center gap-1">
                          <Clock className="h-3.5 w-3.5" />
                          {scan.duration_seconds}s
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-right text-xs">
                      {(scan.status === "queued" || scan.status === "running") && (
                        <button
                          onClick={() => handleCancelScan(scan.id)}
                          className="rounded border border-red-900/50 bg-red-950/20 px-2.5 py-1 font-semibold text-red-400 hover:bg-red-950/50 transition duration-150"
                        >
                          Cancel
                        </button>
                      )}
                      <Link
                        to={`/scans/${scan.id}`}
                        className="ml-2 inline-block rounded border border-border px-2.5 py-1 font-semibold text-gray-300 hover:bg-border transition duration-150"
                      >
                        View Logs
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* New Scan Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-lg border border-border bg-surface p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <h2 className="text-xl font-semibold text-gray-100 mb-4">Start Scan</h2>
            <form onSubmit={handleCreateScan} className="space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider" htmlFor="target">
                  Scan Target
                </label>
                <input
                  id="target"
                  type="text"
                  required
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="e.g. 10.0.0.0/24, localhost, scanme.pqc"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-gray-100 outline-none focus:border-blue-500 placeholder:text-gray-600"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider" htmlFor="scanType">
                  Scan Type
                </label>
                <select
                  id="scanType"
                  value={scanType}
                  onChange={(e) => setScanType(e.target.value)}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-gray-100 outline-none focus:border-blue-500"
                >
                  <option value="full">Full Scan</option>
                  <option value="tls_only">TLS Scan only</option>
                  <option value="ssh_only">SSH Scan only</option>
                  <option value="targeted">Targeted Scan</option>
                  <option value="ct_monitor">CT Log Monitor</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider" htmlFor="profile">
                  Credential Profile (Optional)
                </label>
                <input
                  id="profile"
                  type="text"
                  value={credentialProfile}
                  onChange={(e) => setCredentialProfile(e.target.value)}
                  placeholder="e.g. ssh-default-key"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-gray-100 outline-none focus:border-blue-500 placeholder:text-gray-600"
                />
              </div>

              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input
                  type="checkbox"
                  checked={advancedTools}
                  onChange={(e) => setAdvancedTools(e.target.checked)}
                  className="rounded border-border bg-background"
                />
                Use advanced tools (SSLyze, scapy, pqcscan, ssh-audit)
              </label>

              <div className="mt-6 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="rounded-md border border-border px-4 py-2 text-sm text-gray-300 hover:bg-border transition duration-150"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="flex items-center gap-1.5 rounded-md bg-[#2ea043] px-4 py-2 text-sm font-semibold text-white hover:bg-[#23863c] disabled:opacity-75 transition duration-150 shadow-sm"
                >
                  {submitting ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Starting...
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4 fill-current" />
                      Run Scan
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

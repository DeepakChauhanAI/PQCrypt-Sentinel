import { useEffect, useState } from "react";
import {
  FileText,
  Plus,
  Loader2,
  Download,
  Trash2,
  AlertTriangle,
  CheckCircle,
  Clock,
  RefreshCw,
} from "lucide-react";

interface Report {
  id: string;
  report_type: string;
  format: string;
  scope_filters: Record<string, any>;
  status: "pending" | "generating" | "ready" | "failed";
  file_path?: string;
  error_message?: string;
  created_at: string;
  updated_at: string;
}

export default function Reports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Form State
  const [reportType, setReportType] = useState("cbom");
  const [format, setFormat] = useState("json");
  const [generating, setGenerating] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const fetchReports = async () => {
    try {
      const headers = {
        Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
      };
      const response = await fetch("/api/v1/reports", { headers });
      if (!response.ok) {
        throw new Error("Failed to fetch reports");
      }
      const data = await response.json();
      setReports(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error loading reports");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();

    const reportsRef = reports;
    const interval = setInterval(() => {
      const hasActive = reportsRef.some((r) => r.status === "pending" || r.status === "generating");
      if (hasActive) {
        fetchReports();
      }
    }, 4000);

    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setGenerating(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const headers = {
        "Content-Type": "application/json",
        Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
      };

      const response = await fetch("/api/v1/reports", {
        method: "POST",
        headers,
        body: JSON.stringify({
          report_type: reportType,
          format: format,
          scope_filters: {},
        }),
      });

      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "Failed to generate report");
      }

      setSuccessMsg("CBOM inventory generation triggered successfully.");
      await fetchReports();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error starting report generation");
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (reportId: string, format: string) => {
    try {
      const response = await fetch(`/api/v1/reports/${reportId}/download`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
      });

      if (!response.ok) {
        throw new Error("Download failed");
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cbom-inventory-${reportId}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error downloading report file");
    }
  };

  const handleDelete = async (reportId: string) => {
    if (!confirm("Are you sure you want to delete this report? This will remove the file from the server.")) {
      return;
    }

    try {
      const response = await fetch(`/api/v1/reports/${reportId}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
      });

      if (!response.ok) {
        throw new Error("Failed to delete report");
      }

      await fetchReports();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error deleting report");
    }
  };

  const getStatusBadge = (status: Report["status"]) => {
    switch (status) {
      case "pending":
        return (
          <span className="inline-flex items-center gap-1 rounded-full bg-blue-900/30 px-2 py-0.5 text-xs font-semibold text-blue-400 border border-blue-800/50">
            <Clock className="h-3 w-3" />
            Pending
          </span>
        );
      case "generating":
        return (
          <span className="inline-flex items-center gap-1 rounded-full bg-yellow-950/40 px-2 py-0.5 text-xs font-semibold text-yellow-400 border border-yellow-800/50">
            <Loader2 className="h-3 w-3 animate-spin" />
            Generating
          </span>
        );
      case "ready":
        return (
          <span className="inline-flex items-center gap-1 rounded-full bg-green-950/40 px-2 py-0.5 text-xs font-semibold text-green-400 border border-green-800/50">
            <CheckCircle className="h-3 w-3" />
            Ready
          </span>
        );
      case "failed":
      default:
        return (
          <span className="inline-flex items-center gap-1 rounded-full bg-red-950/40 px-2 py-0.5 text-xs font-semibold text-red-400 border border-red-800/50">
            <AlertTriangle className="h-3 w-3" />
            Failed
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">

      <div className="grid gap-6 md:grid-cols-3">
        {/* Left Form Panel */}
        <div className="md:col-span-1 rounded-lg border border-border bg-surface p-6 h-fit space-y-4">
          <h2 className="text-lg font-bold text-gray-200">New Export Job</h2>
          <form onSubmit={handleGenerateReport} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
                Report Type
              </label>
              <select
                className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
                onChange={(e) => {
                  const v = e.target.value;
                  if (v !== "cbom") return;
                  setReportType(v);
                }}
                value={reportType}
              >
                <option value="cbom">CycloneDX CBOM Inventory</option>
                <option value="executive" disabled>
                  Executive Posture Summary (PDF - Phase 5)
                </option>
                <option value="compliance" disabled>
                  NIST / CISA Compliance Audit (Phase 5)
                </option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
                Format
              </label>
              <select
                className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
                onChange={(e) => {
                  const v = e.target.value;
                  if (v !== "json") return;
                  setFormat(v);
                }}
                value={format}
              >
                <option value="json">JSON (CycloneDX Compliant)</option>
                <option value="pdf" disabled>
                  PDF Document (Phase 5)
                </option>
              </select>
            </div>

            {error && (
              <div className="rounded border border-red-800/50 bg-red-950/20 p-3 text-xs text-red-400">
                {error}
              </div>
            )}

            {successMsg && (
              <div className="rounded border border-green-800/50 bg-green-950/20 p-3 text-xs text-green-400">
                {successMsg}
              </div>
            )}

            <button
              type="submit"
              className="w-full flex items-center justify-center gap-2 rounded-md bg-cyan-600 py-2.5 text-sm font-semibold text-white hover:bg-cyan-500 focus:outline-none disabled:opacity-50"
              disabled={generating}
            >
              {generating ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Plus className="h-4 w-4" />
              )}
              Generate Export
            </button>
          </form>
        </div>

        {/* Right List Panel */}
        <div className="md:col-span-2 rounded-lg border border-border bg-surface p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-gray-200">Export History</h2>
            <button
              className="rounded p-1.5 text-gray-400 hover:bg-border hover:text-gray-200"
              onClick={fetchReports}
              aria-label="Refresh report history"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
          </div>

          <div className="overflow-hidden rounded-lg border border-border bg-background">
            {loading ? (
              <div className="flex h-48 items-center justify-center">
                <Loader2 className="h-6 w-6 animate-spin text-gray-400" />
              </div>
            ) : reports.length === 0 ? (
              <div className="flex h-48 flex-col items-center justify-center p-8 text-center space-y-3">
                <FileText className="h-10 w-10 text-gray-500" />
                <div>
                  <p className="text-sm font-medium text-gray-200">No reports exported yet</p>
                  <p className="text-xs text-gray-500">Configure parameters on the left to start a CBOM export.</p>
                </div>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left">
                  <thead>
                    <tr className="border-b border-border bg-surface text-xs font-semibold uppercase tracking-wider text-gray-400">
                      <th className="py-3 px-4">Report Type / Format</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">Created At</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border text-sm text-gray-300">
                    {reports.map((report) => (
                      <tr key={report.id} className="hover:bg-border/20 transition-colors">
                        <td className="py-3 px-4">
                          <div className="font-semibold uppercase text-gray-200">
                            {report.report_type} Export
                          </div>
                          <div className="text-xs text-gray-500 font-mono">
                            Format: {report.format.toUpperCase()}
                          </div>
                        </td>
                        <td className="py-3 px-4">{getStatusBadge(report.status)}</td>
                        <td className="py-3 px-4 text-xs text-gray-400">
                          {new Date(report.created_at).toLocaleString()}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            {report.status === "ready" && (
                              <button
                                className="rounded p-1.5 text-cyan-400 hover:bg-border hover:text-cyan-300"
                                onClick={() => handleDownload(report.id, report.format)}
                                title="Download File"
                              >
                                <Download className="h-4 w-4" />
                              </button>
                            )}
                            <button
                              className="rounded p-1.5 text-red-400 hover:bg-border hover:text-red-300"
                              onClick={() => handleDelete(report.id)}
                              title="Delete Report"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

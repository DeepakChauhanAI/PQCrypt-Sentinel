/**
 * Scan Groups list page.
 *
 * Shows all logical scan groups (Phase B). Each group is a parent for
 * multiple member scans (e.g. a Q2 Estate Audit running TLS + AWS + SSH).
 * Clicking a group navigates to the unified Scan-Run Detail view that
 * renders per-target columns.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Layers, Calendar, ChevronRight } from "lucide-react";
import { api, ScanGroup } from "../lib/api";

function getStatusBadge(status: string) {
  const map: Record<string, string> = {
    queued: "bg-gray-800/50 text-gray-300 border-gray-700",
    running: "bg-blue-950/40 text-blue-300 border-blue-800/50",
    completed: "bg-green-950/40 text-green-300 border-green-800/50",
    failed: "bg-red-950/40 text-red-300 border-red-800/50",
    cancelled: "bg-gray-900/40 text-gray-400 border-gray-700/50",
  };
  const cls = map[status] || map.queued;
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold border ${cls}`}>
      <span className="capitalize">{status}</span>
    </span>
  );
}

export default function ScanGroups() {
  const [groups, setGroups] = useState<ScanGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      const data = await api.listScanGroups();
      setGroups(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load scan groups");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    const i = window.setInterval(load, 8000);
    return () => window.clearInterval(i);
  }, []);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center text-gray-400">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-t-transparent border-gray-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <Layers className="h-6 w-6 text-cyan-400" />
            Scan Groups
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Logical groupings of related scans (e.g. Q2 Estate Audit) that fan out to multiple scan types.
          </p>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-red-800/50 bg-red-950/20 p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {groups.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border bg-surface p-12 text-center">
          <Layers className="mx-auto h-10 w-10 text-gray-500" />
          <p className="mt-3 text-sm text-gray-400">
            No scan groups yet. Trigger a scan group via the API to bundle multiple scan types into a single campaign.
          </p>
          <p className="mt-1 text-xs text-gray-500 font-mono">
            POST /api/v1/scan-groups
          </p>
        </div>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
          {groups.map((g) => (
            <Link
              key={g.id}
              to={`/scan-groups/${g.id}`}
              className="rounded-lg border border-border bg-surface p-4 transition-colors hover:border-cyan-700 hover:bg-surface/80"
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <div className="font-semibold text-gray-200 truncate">{g.name}</div>
                {getStatusBadge(g.status)}
              </div>
              {g.description && (
                <p className="text-xs text-gray-400 mb-3 line-clamp-2">{g.description}</p>
              )}
              <div className="grid grid-cols-3 gap-2 text-center text-xs">
                <div className="rounded border border-border bg-background p-1.5">
                  <div className="text-gray-500">Members</div>
                  <div className="text-sm font-mono text-gray-200">{g.member_count}</div>
                </div>
                <div className="rounded border border-border bg-background p-1.5">
                  <div className="text-gray-500">Assets</div>
                  <div className="text-sm font-mono text-gray-200">{g.assets_found}</div>
                </div>
                <div className="rounded border border-border bg-background p-1.5">
                  <div className="text-gray-500">Findings</div>
                  <div className={`text-sm font-mono ${g.findings_created > 0 ? "text-red-300" : "text-gray-200"}`}>
                    {g.findings_created}
                  </div>
                </div>
              </div>
              <div className="mt-3 flex items-center justify-between text-[10px] text-gray-500">
                <span className="flex items-center gap-1">
                  <Calendar className="h-3 w-3" />
                  {new Date(g.created_at).toLocaleString()}
                </span>
                <ChevronRight className="h-3.5 w-3.5" />
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Unified scan-run detail page.
 *
 * Renders BOTH single scans AND scan groups, addressing the correlation
 * problem where grouped scans (TLS + AWS + SSH) were previously shown
 * as disconnected entries.
 *
 * Mode A: route /scans/:id where :id is a Scan.id  -> single-scan view
 * Mode B: route /scan-groups/:id                    -> group view
 *   - Header: name, status, started, members, assets, findings
 *   - Per-target column: one card per member scan, each shows its
 *     assets and findings inline. This is the key correlation UI.
 */
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Clock,
  Loader2,
  Cloud,
  Server,
  GitBranch,
  Globe,
  Box,
  Target,
  Network,
  Wifi,
} from "lucide-react";
import { api, ScanGroupDetail } from "../lib/api";

const targetKindIcon: Record<string, any> = {
  host: Server,
  cloud_account: Cloud,
  code_repo: GitBranch,
  domain: Globe,
  saas_tenant: Box,
  network_range: Network,
  interface: Wifi,
  other: Target,
};

function targetKindBadge(kind?: string | null) {
  const Icon = (kind && targetKindIcon[kind]) || Target;
  return (
    <span className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-0.5 text-xs text-gray-300">
      <Icon className="h-3.5 w-3.5 text-cyan-400" />
      {kind || "target"}
    </span>
  );
}

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
      {status === "running" && <Loader2 className="h-3 w-3 animate-spin" />}
      <span className="capitalize">{status}</span>
    </span>
  );
}

function Stat({ label, value, accent, small }: { label: string; value: any; accent?: "red" | "green"; small?: boolean }) {
  const accentClass = accent === "red" ? "text-red-300" : accent === "green" ? "text-green-300" : "text-gray-200";
  return (
    <div className="rounded-lg border border-border bg-surface p-3">
      <div className="text-xs text-gray-500">{label}</div>
      <div className={`mt-1 ${small ? "text-sm" : "text-2xl"} font-mono ${accentClass}`}>{value}</div>
    </div>
  );
}

function TargetColumn({ scan }: { scan: ScanGroupDetail["members"][number] }) {
  const [assets, setAssets] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const [a, f] = await Promise.all([
          api.listScanAssets(scan.id),
          api.listFindings({ scanId: scan.id }),
        ]);
        if (mounted) {
          setAssets(a);
          setFindings(f);
        }
      } catch {
        // best-effort
      } finally {
        if (mounted) setLoading(false);
      }
    })();
    return () => { mounted = false; };
  }, [scan.id]);

  return (
    <div className="rounded-lg border border-border bg-surface p-4 min-w-0">
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            {targetKindBadge(scan.target_kind)}
            <span className="text-[10px] font-mono uppercase tracking-wider text-gray-500">
              {scan.scan_type.replace(/_/g, " ")}
            </span>
          </div>
          <div className="font-mono text-sm text-gray-200 break-all">
            {scan.target_label || scan.target}
          </div>
        </div>
        <Link
          to={`/scans/${scan.id}`}
          className="shrink-0 rounded border border-border px-2 py-0.5 text-[10px] text-gray-400 hover:bg-border hover:text-gray-200"
        >
          Logs
        </Link>
      </div>
      <div className="flex items-center gap-2 text-xs text-gray-400 mb-3">
        {getStatusBadge(scan.status)}
        {scan.duration_seconds != null && (
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" /> {scan.duration_seconds}s
          </span>
        )}
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs mb-3">
        <div className="rounded border border-border bg-background p-2">
          <div className="text-gray-500">Assets</div>
          <div className="text-lg font-mono text-gray-200">{assets.length}</div>
        </div>
        <div className="rounded border border-border bg-background p-2">
          <div className="text-gray-500">Findings</div>
          <div className={`text-lg font-mono ${findings.length > 0 ? "text-red-300" : "text-gray-200"}`}>
            {findings.length}
          </div>
        </div>
      </div>
      {loading ? (
        <div className="flex items-center gap-2 text-xs text-gray-500">
          <Loader2 className="h-3 w-3 animate-spin" /> loading...
        </div>
      ) : (
        <div className="space-y-1.5">
          {assets.slice(0, 5).map((a) => (
            <div key={a.id} className="rounded border border-border bg-background px-2 py-1 text-xs">
              <div className="font-mono text-gray-300 truncate">{a.name}</div>
              <div className="flex items-center gap-2 text-gray-500 text-[10px]">
                <span className="capitalize">{a.pqc_status || "classical"}</span>
                {a.risk_score != null && <span>risk {a.risk_score}</span>}
              </div>
            </div>
          ))}
          {assets.length > 5 && (
            <div className="text-[10px] text-gray-500">+{assets.length - 5} more</div>
          )}
          {findings.slice(0, 3).map((f) => (
            <div key={f.id} className="rounded border border-red-900/40 bg-red-950/10 px-2 py-1 text-xs">
              <div className="text-gray-200 truncate">{f.title}</div>
              <div className="text-[10px] text-gray-500 capitalize">{f.severity}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ScanRunDetail() {
  const { id } = useParams<{ id: string }>();
  const [group, setGroup] = useState<ScanGroupDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let mounted = true;
    (async () => {
      try {
        const g = await api.getScanGroup(id);
        if (mounted) setGroup(g);
      } catch (e) {
        if (mounted) setError(e instanceof Error ? e.message : "Failed to load group");
      } finally {
        if (mounted) setLoading(false);
      }
    })();
    return () => { mounted = false; };
  }, [id]);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
      </div>
    );
  }
  if (error || !group) {
    return (
      <div className="rounded-md border border-red-800/50 bg-red-950/20 p-4 text-sm text-red-300">
        {error || "Group not found"}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link to="/scan-groups" className="rounded-md p-1.5 text-gray-400 hover:bg-border hover:text-gray-200">
          <ArrowLeft className="h-4 w-4" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-gray-100">{group.name}</h1>
          {group.description && <p className="text-sm text-gray-400">{group.description}</p>}
        </div>
        <div className="ml-auto">{getStatusBadge(group.status)}</div>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Members" value={group.member_count} />
        <Stat label="Assets" value={group.assets_found} />
        <Stat label="Findings" value={group.findings_created} accent={group.findings_created > 0 ? "red" : undefined} />
        <Stat label="Started" value={group.started_at ? new Date(group.started_at).toLocaleString() : "—"} small />
        <Stat
          label="Completed"
          value={group.completed_at ? new Date(group.completed_at).toLocaleString() : "—"}
          small
        />
      </div>

      <div>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-gray-400">
          Targets ({group.members.length})
        </h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {group.members.map((m) => (
            <TargetColumn key={m.id} scan={m} />
          ))}
        </div>
      </div>
    </div>
  );
}

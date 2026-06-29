import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  Layers,
  Loader2,
  RefreshCw,
  Filter,
  ScanSearch,
  User as UserIcon,
  ShieldAlert,
  ArrowRight,
  X,
  FileWarning,
  AlertCircle,
  Flame,
  Info,
} from "lucide-react";
import { useAuth } from "@/lib/authContext";
import { EvidenceRenderer } from "../components/evidence/EvidenceRenderer";

// Severity configuration map for consistent badge styling
const SEVERITY_CONFIG: Record<string, { className: string; icon: typeof AlertTriangle }> = {
  critical: { className: "bg-red-950/40 text-red-400 border-red-800/50", icon: Flame },
  high:     { className: "bg-orange-950/40 text-orange-400 border-orange-800/50", icon: AlertCircle },
  medium:   { className: "bg-yellow-950/40 text-yellow-400 border-yellow-800/50", icon: AlertTriangle },
  low:      { className: "bg-green-950/40 text-green-400 border-green-800/50", icon: CheckCircle },
  info:     { className: "bg-blue-950/40 text-blue-400 border-blue-800/50", icon: Info },
};

interface Asset {
  id: string;
  name: string;
  asset_type: string;
  ip_address?: string;
  fqdn?: string;
  environment: string;
  risk_score: number;
}

interface Finding {
  id: string;
  asset_id: string;
  scan_id: string;
  finding_type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description?: string;
  algorithm?: string;
  algorithm_type?: string;
  pqc_status?: string;
  risk_score?: number;
  evidence?: Record<string, any>;
  remediation?: string;
  recommended_algorithm?: string;
  status: "open" | "in_progress" | "resolved" | "accepted" | "false_positive";
  assigned_to?: string;
  ticket_id?: string;
  first_detected_at: string;
  last_verified_at?: string;
  resolved_at?: string;
  asset?: Asset;
  scan_type?: string;
  scan_target?: string;
  scan_target_label?: string;
  scan_group_id?: string;
  scan_group_name?: string;
  layer?: string;
  hndl_exposure?: string;
}

export default function Findings() {
  const { user } = useAuth();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [severity, setSeverity] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [findingType, setFindingType] = useState("");
  const [assignedToFilter, setAssignedToFilter] = useState("");

  // Grouping (Phase B). When a finding has a scan_group_id, the page
  // groups findings under that group; otherwise it falls back to the
  // parent scan_id so a standalone scan of a single host still gets
  // visual grouping. "off" turns grouping off (legacy flat list).
  type GroupMode = "scan_group" | "scan" | "off";
  const [groupMode, setGroupMode] = useState<GroupMode>("scan_group");
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());

  // Selection
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Action states
  const [updating, setUpdating] = useState(false);
  const [statusUpdate, setStatusUpdate] = useState("");
  const [reasonUpdate, setReasonUpdate] = useState("");
  const [assigneeUpdate, setAssigneeUpdate] = useState("");
  const [rescanning, setRescanning] = useState(false);
  const [rescanSuccess, setRescanSuccess] = useState<string | null>(null);

  // ── Group findings by their parent scan / scan-group ──────────────────
  // When groupMode is "scan_group", every finding lands in its
  // scan_group_id bucket (or scan_id if no group). When "scan", the
  // bucket key is always scan_id (so two grouped scans stay separate).
  // When "off", the renderer uses a single pseudo-group so the existing
  // flat layout keeps working.
  type Group = {
    key: string;
    label: string;
    sublabel: string;
    scanGroupId?: string | null;
    scanId?: string | null;
    scanType?: string | null;
    findings: Finding[];
  };

  const groupedFindings: Group[] = useMemo(() => {
    if (groupMode === "off" || findings.length === 0) {
      return [{
        key: "__all__",
        label: `All findings (${findings.length})`,
        sublabel: "",
        scanGroupId: null,
        scanId: null,
        scanType: null,
        findings,
      }];
    }

    const buckets = new Map<string, Group>();
    for (const f of findings) {
      let key: string;
      let label: string;
      let sublabel: string;
      let scanGroupId: string | null | undefined;
      let scanId: string | null | undefined = f.scan_id;
      let scanType: string | null | undefined = f.scan_type;

      if (groupMode === "scan_group" && f.scan_group_id) {
        key = `g:${f.scan_group_id}`;
        label = f.scan_group_name || "Scan group";
        sublabel = `${f.scan_type?.replace(/_/g, " ") || "scan"}${f.scan_target_label ? ` on ${f.scan_target_label}` : ""}`;
        scanGroupId = f.scan_group_id;
      } else {
        // Fall back to scan_id for findings without a group, or when the
        // user has explicitly switched to "scan" grouping.
        key = `s:${f.scan_id}`;
        label = f.scan_target_label || f.scan_target || (f.scan_id ? `scan #${f.scan_id.slice(0, 8)}` : "Standalone finding");
        sublabel = f.scan_type?.replace(/_/g, " ") || "scan";
      }

      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = { key, label, sublabel, scanGroupId, scanId, scanType, findings: [] };
        buckets.set(key, bucket);
      }
      bucket.findings.push(f);
    }

    // Stable order: by group label so the page is deterministic.
    return Array.from(buckets.values()).sort((a, b) => a.label.localeCompare(b.label));
  }, [findings, groupMode]);

  const toggleGroup = (key: string) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  const fetchFindings = async () => {
    try {
      setLoading(true);
      const headers = {
        Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
      };
      const queryParams = new URLSearchParams();
      if (severity) queryParams.append("severity", severity);
      if (statusFilter) queryParams.append("status", statusFilter);
      if (findingType) queryParams.append("finding_type", findingType);
      if (assignedToFilter) queryParams.append("assigned_to", assignedToFilter);

      const response = await fetch(`/api/v1/findings?${queryParams.toString()}`, { headers });
      if (!response.ok) {
        throw new Error("Failed to load findings");
      }
      const data = await response.json();
      setFindings(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [severity, statusFilter, findingType, assignedToFilter]);

  const fetchFindingDetails = async (id: string) => {
    try {
      setDetailLoading(true);
      const headers = {
        Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
      };
      const response = await fetch(`/api/v1/findings/${id}`, { headers });
      if (!response.ok) {
        throw new Error("Failed to load finding details");
      }
      const data = await response.json();
      setSelectedFinding(data);
      setStatusUpdate(data.status);
      setAssigneeUpdate(data.assigned_to ?? "");
      setReasonUpdate(data.evidence?.status_change_reason ?? "");
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to load finding details");
    } finally {
      setDetailLoading(false);
    }
  };

  useEffect(() => {
    if (selectedFindingId) {
      fetchFindingDetails(selectedFindingId);
    } else {
      setSelectedFinding(null);
    }
  }, [selectedFindingId]);

  const handleUpdateFinding = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFinding) return;

    setUpdating(true);
    try {
      const headers = {
        "Content-Type": "application/json",
        Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
      };

      const payload: Record<string, any> = {};
      if (statusUpdate !== selectedFinding.status) {
        payload.status = statusUpdate;
        if (["accepted", "false_positive", "resolved"].includes(statusUpdate) && reasonUpdate) {
          payload.reason = reasonUpdate;
        }
      }
      if (assigneeUpdate !== (selectedFinding.assigned_to ?? "")) {
        payload.assigned_to = assigneeUpdate || null;
      }

      if (Object.keys(payload).length === 0) {
        setUpdating(false);
        return;
      }

      const response = await fetch(`/api/v1/findings/${selectedFinding.id}`, {
        method: "PATCH",
        headers,
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "Failed to update finding");
      }

      await fetchFindingDetails(selectedFinding.id);
      await fetchFindings();
      alert("Finding updated successfully.");
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error updating finding");
    } finally {
      setUpdating(false);
    }
  };

  const handleRescan = async (finding: Finding) => {
    setRescanning(true);
    setRescanSuccess(null);
    try {
      const headers = {
        Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
      };
      const response = await fetch(`/api/v1/findings/${finding.id}/rescan`, {
        method: "POST",
        headers,
      });

      if (!response.ok) {
        throw new Error("Failed to trigger re-scan");
      }

      setRescanSuccess("Asset re-scan job queued successfully.");
      setTimeout(() => setRescanSuccess(null), 5000);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error scanning asset");
    } finally {
      setRescanning(false);
    }
  };

  const getStatusBadge = (status: string) => {
    const map = {
      open: "bg-red-900/30 text-red-400 border-red-800/50",
      in_progress: "bg-yellow-950/40 text-yellow-400 border-yellow-850/50",
      resolved: "bg-green-950/40 text-green-400 border-green-800/50",
      accepted: "bg-gray-900/30 text-gray-400 border-gray-800/50",
      false_positive: "bg-gray-900/30 text-gray-400 border-gray-800/50",
    };
    const style = map[status as keyof typeof map] || "bg-gray-950/40 text-gray-400 border-gray-800/50";
    return (
      <span className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold border capitalize ${style}`}>
        {status.replace("_", " ")}
      </span>
    );
  };

  const getSeverityBadge = (sev: string) => {
    const cfg = SEVERITY_CONFIG[sev];
    if (!cfg) {
      return (
        <span className="inline-flex rounded-full px-2 py-0.5 text-xs font-semibold border bg-gray-800 text-gray-400 border-gray-700">
          {sev.toUpperCase()}
        </span>
      );
    }
    return (
      <span className={"inline-flex rounded-full px-2 py-0.5 text-xs font-semibold border " + cfg.className}>
        {sev.toUpperCase()}
      </span>
    );
  };

  return (
    <div className="space-y-5">

      {/* Summary Cards */}
      {(() => {
        const _bySev: Record<string, number> = {};
        const _byStatus: Record<string, number> = {};
        for (const _f of findings) {
          _bySev[_f.severity] = (_bySev[_f.severity] || 0) + 1;
          _byStatus[_f.status] = (_byStatus[_f.status] || 0) + 1;
        }
        const _avg = findings.length
          ? Math.round(findings.reduce((_s, _x) => _s + (_x.risk_score ?? 0), 0) / findings.length)
          : 0;
        const cards: { label: string; value: number; icon: any; color: string; bg: string; border: string }[] = [
          { label: "Total Findings", value: findings.length, icon: FileWarning, color: "text-gray-200", bg: "bg-gray-800/50", border: "border-gray-700/50" },
          { label: "Open", value: _byStatus.open ?? 0, icon: AlertTriangle, color: "text-red-400", bg: "bg-red-950/30", border: "border-red-800/50" },
          { label: "In Progress", value: _byStatus.in_progress ?? 0, icon: Loader2, color: "text-yellow-400", bg: "bg-yellow-950/30", border: "border-yellow-800/40" },
          { label: "Critical", value: _bySev.critical ?? 0, icon: Flame, color: "text-red-400", bg: "bg-red-950/30", border: "border-red-800/50" },
          { label: "High", value: _bySev.high ?? 0, icon: AlertCircle, color: "text-orange-400", bg: "bg-orange-950/30", border: "border-orange-800/50" },
          { label: "Avg Risk", value: _avg, icon: AlertTriangle, color: _avg >= 70 ? "text-red-400" : _avg >= 40 ? "text-orange-400" : "text-yellow-400", bg: "bg-yellow-950/20", border: "border-yellow-800/40" },
        ];
        return (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
            {cards.map((card) => (
              <div key={card.label} className={"rounded-lg border " + card.border + " " + card.bg + " px-4 py-3 flex items-center gap-3"}>
                <card.icon className={"h-5 w-5 shrink-0 " + card.color} />
                <div>
                  <div className={"text-lg font-bold " + card.color}>{card.value}</div>
                  <div className="text-[11px] font-medium text-gray-400 uppercase tracking-wider">{card.label}</div>
                </div>
              </div>
            ))}
          </div>
        );
      })()}

      {/* Filters */}
      <div className="space-y-3">
        <div className="grid gap-3 rounded-lg border border-border bg-surface p-4 md:grid-cols-5">
          {/* Search */}
          <div className="relative md:col-span-1">
            <Filter className="absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search findings…"
              className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-4 text-sm text-gray-200 placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          {/* Severity */}
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-gray-400 shrink-0" />
            <select
              className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>

          {/* Status */}
          <div className="flex items-center gap-2">
            <CheckCircle className="h-4 w-4 text-gray-400 shrink-0" />
            <select
              className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="accepted">Accepted</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>

          {/* Finding Type */}
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-gray-400 shrink-0" />
            <select
              className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
              value={findingType}
              onChange={(e) => setFindingType(e.target.value)}
            >
              <option value="">All Finding Types</option>
              <option value="weak_algorithm">Weak Algorithm</option>
              <option value="weak_key_size">Weak Key Size</option>
              <option value="tls_version">Weak TLS Version</option>
              <option value="pqc_not_supported">PQC Not Supported</option>
              <option value="pqc_downgrade">PQC Downgrade Drift</option>
              <option value="cert_expiring">Cert Expiring</option>
              <option value="cert_expired">Cert Expired</option>
              <option value="self_signed">Self-Signed Cert</option>
              <option value="ssh_weak_kex">SSH Weak KEX</option>
              <option value="config_drift">Config Drift</option>
            </select>
          </div>

          {/* Assignment */}
          <div className="flex items-center gap-2">
            <UserIcon className="h-4 w-4 text-gray-400 shrink-0" />
            <select
              className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
              value={assignedToFilter}
              onChange={(e) => setAssignedToFilter(e.target.value)}
            >
              <option value="">All Assignments</option>
              {user && <option value={user.id}>Assigned to Me</option>}
            </select>
          </div>
        </div>

        {/* Severity quick-filter pills + group mode + clear */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-gray-500 mr-1">Quick:</span>
          {(["", "critical", "high", "medium", "low", "info"] as const).map((sev) => {
            const active = severity === sev;
            const cfg = sev ? SEVERITY_CONFIG[sev] : null;
            const count = sev ? (() => {
              const c: Record<string, number> = {};
              for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
              return c[sev] ?? 0;
            })() : findings.length;
            return (
              <button
                key={sev || "all"}
                onClick={() => setSeverity(sev)}
                className={`rounded-full px-3 py-1 text-xs font-semibold border transition-colors ${
                  active
                    ? cfg
                      ? `${cfg.className} ring-1 ring-offset-1 ring-offset-surface ring-current`
                      : "bg-gray-700 text-gray-200 border-gray-500"
                    : "border-border bg-surface text-gray-400 hover:text-gray-200 hover:border-gray-500"
                }`}
              >
                {sev ? sev.toUpperCase() : "ALL"} ({count})
              </button>
            );
          })}

          <div className="h-5 w-px bg-border mx-2" />

          <div className="flex items-center gap-2">
            <Layers className="h-3.5 w-3.5 text-gray-500" />
            <select
              className="rounded-md border border-border bg-background py-1 pl-2 pr-6 text-xs text-gray-300 focus:border-cyan-500 focus:outline-none"
              value={groupMode}
              onChange={(e) => setGroupMode(e.target.value as typeof groupMode)}
            >
              <option value="scan_group">Group: scan group</option>
              <option value="scan">Group: scan</option>
              <option value="off">Flat list</option>
            </select>
          </div>

          {(severity || statusFilter || findingType || assignedToFilter) && (
            <button
              onClick={() => { setSeverity(""); setStatusFilter(""); setFindingType(""); setAssignedToFilter(""); }}
              className="ml-auto rounded-md border border-border bg-surface px-3 py-1 text-xs font-semibold text-gray-300 hover:text-gray-100 hover:bg-border transition-colors"
            >
              <X className="h-3 w-3 inline mr-1" />
              Clear filters
            </button>
          )}
        </div>
      </div>

      {/* Findings Table */}
      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        {loading ? (
          <div className="flex h-64 items-center justify-center">
            <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
          </div>
        ) : error ? (
          <div className="flex h-64 items-center justify-center p-4 text-center">
            <div className="space-y-3">
              <AlertTriangle className="mx-auto h-10 w-10 text-red-500" />
              <p className="text-gray-200 font-medium">Failed to load findings</p>
              <p className="text-sm text-gray-400">{error}</p>
              <button
                onClick={fetchFindings}
                className="rounded-md border border-border bg-surface px-4 py-2 text-sm font-semibold text-gray-200 hover:bg-border transition-colors"
              >
                <RefreshCw className="h-3.5 w-3.5 inline mr-1.5" />
                Retry
              </button>
            </div>
          </div>
        ) : findings.length === 0 ? (
          <div className="flex h-64 flex-col items-center justify-center p-8 text-center space-y-4">
            <FileWarning className="h-12 w-12 text-gray-500" />
            <div>
              <p className="text-lg font-medium text-gray-200">No findings found</p>
              <p className="text-sm text-gray-400">Your cryptographic posture is clear or matches current filters.</p>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="border-b border-border bg-background text-xs font-semibold uppercase tracking-wider text-gray-400">
                  <th className="py-3 px-4">Title / Target</th>
                  <th className="py-3 px-4">Scan / Group</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">PQC Status</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border text-sm text-gray-300">
                {groupedFindings.flatMap((group, groupIdx) => {
                  const isCollapsed = collapsedGroups.has(group.key);
                  const isGroupable = group.key !== "__all__";
                  const sevCounts = group.findings.reduce<Record<string, number>>((acc, f) => {
                    acc[f.severity] = (acc[f.severity] || 0) + 1;
                    return acc;
                  }, {});

                  const headerRow = (
                    <tr
                      key={`hdr:${group.key}`}
                      className="bg-background/80 border-y border-border"
                    >
                      <td colSpan={7} className="py-2.5 px-4">
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2.5 min-w-0">
                            {isGroupable && (
                              <button
                                onClick={() => toggleGroup(group.key)}
                                className="rounded p-1 text-gray-400 hover:bg-border hover:text-gray-200 transition-colors shrink-0"
                                aria-label={isCollapsed ? "Expand group" : "Collapse group"}
                              >
                                {isCollapsed ? (
                                  <ChevronRight className="h-4 w-4" />
                                ) : (
                                  <ChevronDown className="h-4 w-4" />
                                )}
                              </button>
                            )}
                            {group.scanGroupId ? (
                              <Layers className="h-4 w-4 text-cyan-400 shrink-0" />
                            ) : (
                              <ScanSearch className="h-4 w-4 text-gray-500 shrink-0" />
                            )}
                            <div className="min-w-0 flex items-center gap-2">
                              <span className="text-[10px] font-mono text-gray-600 shrink-0">
                                {group.scanGroupId ? "GROUP" : "SCAN"}
                              </span>
                              {group.scanGroupId ? (
                                <Link
                                  to={`/scan-groups/${group.scanGroupId}`}
                                  className="font-semibold text-cyan-300 hover:underline truncate text-sm transition-colors hover:text-cyan-200"
                                  onClick={(e) => e.stopPropagation()}
                                >
                                  {group.label}
                                </Link>
                              ) : (
                                <span className="font-semibold text-gray-200 truncate text-sm">
                                  {group.label}
                                </span>
                              )}
                              {group.sublabel && (
                                <span className="hidden sm:inline text-[10px] text-gray-500 capitalize truncate">
                                  · {group.sublabel}
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-1.5 shrink-0">
                            {Object.entries(sevCounts).map(([sev, n]) => {
                              const cfg = SEVERITY_CONFIG[sev];
                              return (
                                <span
                                  key={sev}
                                  className={`rounded border px-1.5 py-0.5 text-[10px] font-bold ${cfg ? cfg.className : "bg-gray-800 text-gray-400 border-gray-700"}`}
                                  title={`${n} ${sev}`}
                                >
                                  {n} {sev.slice(0, 1).toUpperCase()}
                                </span>
                              );
                            })}
                            <span className="rounded border border-border bg-surface px-2 py-0.5 font-mono text-gray-300 text-[11px]">
                              {group.findings.length}
                            </span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  );

                  if (isCollapsed) {
                    return [headerRow];
                  }

                  const dataRows = group.findings.map((finding) => (
                    <tr
                      key={finding.id}
                      className="hover:bg-border/30 hover:pl-2 transition-all cursor-pointer group"
                      onClick={() => setSelectedFindingId(finding.id)}
                    >
                      <td className="py-3 px-4">
                        <div className="font-semibold text-gray-200 group-hover:text-cyan-200 transition-colors">{finding.title}</div>
                        <div className="text-xs text-gray-500">
                          {finding.asset?.name || "Unknown asset"}
                          {finding.scan_target_label && (
                            <span className="ml-1 text-gray-400">— {finding.scan_target_label}</span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-xs">
                        {finding.scan_group_name ? (
                          <Link
                            to={`/scan-groups/${finding.scan_group_id}`}
                            className="text-cyan-400 hover:underline inline-flex items-center gap-1"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <Layers className="h-3 w-3 shrink-0" />
                            <span className="truncate max-w-[120px]">{finding.scan_group_name}</span>
                          </Link>
                        ) : finding.scan_id ? (
                          <Link
                            to={`/scans/${finding.scan_id}`}
                            className="text-gray-400 hover:text-gray-200 hover:underline inline-flex items-center gap-1 font-mono"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <ScanSearch className="h-3 w-3 shrink-0" />
                            scan #{finding.scan_id.slice(0, 8)}
                          </Link>
                        ) : (
                          <span className="text-gray-500">—</span>
                        )}
                        <div className="text-[10px] text-gray-500 capitalize mt-0.5">
                          {finding.scan_type?.replace(/_/g, " ") || "scan"}
                        </div>
                      </td>
                       <td className="py-3 px-4">
                        <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold border ${SEVERITY_CONFIG[finding.severity]?.className || "bg-gray-800 text-gray-400 border-gray-700"}`}>
                          {finding.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`capitalize font-medium ${
                          finding.pqc_status === "vulnerable" ? "text-red-400" :
                          finding.pqc_status === "transitioning" ? "text-yellow-400" :
                          finding.pqc_status === "hybrid" ? "text-blue-400" :
                          finding.pqc_status === "pqc_ready" ? "text-green-400" :
                          "text-gray-400"
                        }`}>
                          {finding.pqc_status || "Classical"}
                        </span>
                      </td>
                      <td className="py-3 px-4">{getStatusBadge(finding.status)}</td>
                      <td className="py-3 px-4">
                        <span className={`font-bold ${
                          (finding.risk_score ?? 0) >= 80 ? "text-red-400" :
                          (finding.risk_score ?? 0) >= 50 ? "text-orange-400" :
                          (finding.risk_score ?? 0) >= 20 ? "text-yellow-400" : "text-green-400"
                        }`}>
                          {finding.risk_score ?? "—"}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                        <button
                          className="rounded border border-border px-2.5 py-1.5 text-xs font-semibold text-gray-300 hover:bg-cyan-900/30 hover:text-cyan-200 hover:border-cyan-700/50 transition-colors opacity-0 group-hover:opacity-100 focus:opacity-100"
                          onClick={() => setSelectedFindingId(finding.id)}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ));

                  // Add a thin divider between groups (skip the first one).
                  if (groupIdx === 0) {
                    return [headerRow, ...dataRows];
                  }
                  return [
                    <tr key={`spacer:${group.key}`} aria-hidden="true">
                      <td colSpan={7} className="p-0">
                        <div className="h-1 bg-background" />
                      </td>
                    </tr>,
                    headerRow,
                    ...dataRows,
                  ];
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Findings Slide-over Panel */}
      {selectedFindingId && (
        <div className="fixed inset-0 z-50 overflow-hidden" role="dialog" aria-modal="true">
          <div className="absolute inset-0 overflow-hidden">
            <div
              className="absolute inset-0 bg-black/60 transition-opacity"
              onClick={() => setSelectedFindingId(null)}
            />

            <div className="pointer-events-none fixed inset-y-0 right-0 flex max-w-full pl-10">
              <div className="pointer-events-auto w-screen max-w-2xl transform bg-surface border-l border-border transition-all duration-300">
                {detailLoading ? (
                  <div className="flex h-full items-center justify-center">
                    <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
                  </div>
                ) : selectedFinding ? (
                  <div className="flex h-full flex-col overflow-y-scroll">
                    {/* Header */}
                    <div className="border-b border-border bg-background p-6">
                      <div className="flex items-start justify-between">
                        <div className="space-y-1 pr-6">
                          <h2 className="text-lg font-bold text-gray-200">{selectedFinding.title}</h2>
                          <div className="flex items-center gap-2">
                            {getSeverityBadge(selectedFinding.severity)}
                            {getStatusBadge(selectedFinding.status)}
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <button
                            className="rounded border border-border bg-surface px-3 py-1.5 text-xs font-semibold text-gray-200 hover:bg-border disabled:opacity-50"
                            onClick={() => handleRescan(selectedFinding)}
                            disabled={rescanning}
                          >
                            {rescanning ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : (
                              <RefreshCw className="h-3.5 w-3.5 inline mr-1" />
                            )}
                            Re-scan Target
                          </button>
                          <button
                            className="rounded-md p-1.5 text-gray-400 hover:bg-border hover:text-gray-200"
                            onClick={() => setSelectedFindingId(null)}
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
                    </div>

                    <div className="flex-1 p-6 space-y-6">
                      {/* Description & Target */}
                      <div className="space-y-4">
                        <div className="grid grid-cols-2 gap-4 rounded-lg border border-border bg-background p-4">
                          <div>
                            <div className="text-xs text-gray-500">Asset Target</div>
                            <div className="text-sm font-semibold text-gray-300">
                              {selectedFinding.asset?.name || "N/A"}
                            </div>
                            <div className="text-xs text-gray-500">
                              {selectedFinding.asset?.ip_address || "No IP Address"}
                              {selectedFinding.asset?.fqdn && ` (${selectedFinding.asset.fqdn})`}
                            </div>
                          </div>
                          <div>
                            <div className="text-xs text-gray-500">Risk Score</div>
                            <div className="text-sm font-semibold text-gray-300">
                              {selectedFinding.risk_score ?? "N/A"}
                            </div>
                          </div>
                          <div>
                            <div className="text-xs text-gray-500">First Detected</div>
                            <div className="text-sm text-gray-350">
                              {new Date(selectedFinding.first_detected_at).toLocaleString()}
                            </div>
                          </div>
                          <div>
                            <div className="text-xs text-gray-500">Assigned To</div>
                            <div className="text-sm text-gray-350">
                              {selectedFinding.assigned_to ? "Configured" : "Unassigned"}
                            </div>
                          </div>
                        </div>

                        {/* Phase B - scan context: which group/scan this finding belongs to */}
                        {(selectedFinding.scan_group_name || selectedFinding.scan_type) && (
                          <div className="rounded-lg border border-cyan-900/30 bg-cyan-950/10 p-3.5 text-sm">
                            <div className="text-xs text-cyan-400 uppercase tracking-wider mb-1">
                              Discovered By
                            </div>
                            <div className="text-gray-200">
                              {selectedFinding.scan_group_name ? (
                                <>
                                  <Link
                                    to={`/scan-groups/${selectedFinding.scan_group_id}`}
                                    className="font-semibold text-cyan-300 hover:underline"
                                  >
                                    {selectedFinding.scan_group_name}
                                  </Link>
                                  <span className="text-gray-500"> › </span>
                                </>
                              ) : null}
                              <span className="font-mono text-gray-300">
                                {selectedFinding.scan_type?.replace(/_/g, " ") || "scan"}
                              </span>
                              {selectedFinding.scan_target_label && (
                                <span className="text-gray-400"> on {selectedFinding.scan_target_label}</span>
                              )}
                            </div>
                            {selectedFinding.scan_id && (
                              <div className="mt-1 text-[10px] font-mono text-gray-500">
                                scan #{selectedFinding.scan_id.slice(0, 8)}
                              </div>
                            )}
                          </div>
                        )}

                        <div>
                          <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-1">
                            Description
                          </h4>
                          <p className="text-sm text-gray-300 leading-relaxed">
                            {selectedFinding.description || "No description provided."}
                          </p>
                        </div>
                      </div>

                      {/* Cryptography evidence - typed renderer */}
                      <div className="space-y-4 border-t border-border/50 pt-4">
                        <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400">
                          Cryptographic Discovery Evidence
                        </h3>
                        <EvidenceRenderer
                          findingType={selectedFinding.finding_type}
                          algorithm={selectedFinding.algorithm}
                          algorithmType={selectedFinding.algorithm_type}
                          pqcStatus={selectedFinding.pqc_status}
                          evidence={selectedFinding.evidence}
                          recommendedAlgorithm={selectedFinding.recommended_algorithm}
                          layer={selectedFinding.layer}
                          hndlExposure={selectedFinding.hndl_exposure}
                        />
                      </div>

                      {/* Remediation & Recommendation */}
                      <div className="space-y-4 border-t border-border/50 pt-4">
                        <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400">Remediation</h3>
                        {selectedFinding.recommended_algorithm && (
                          <div className="flex items-center gap-3 rounded-lg border border-cyan-800/30 bg-cyan-950/10 p-3.5 text-sm">
                            <span className="font-mono text-gray-300">{selectedFinding.algorithm}</span>
                            <ArrowRight className="h-4 w-4 text-cyan-400" />
                            <span className="font-mono text-cyan-300 font-semibold">
                              {selectedFinding.recommended_algorithm}
                            </span>
                          </div>
                        )}
                        <div className="rounded-lg border border-border bg-background p-4">
                          <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-1">
                            Actionable Steps
                          </h4>
                          <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-line">
                            {selectedFinding.remediation || "No remediation recommendation provided."}
                          </p>
                        </div>
                      </div>

                      {/* Workflow management actions */}
                      <div className="space-y-4 border-t border-border/50 pt-4 pb-6">
                        <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400">
                          Workflow Management
                        </h3>
                        <form onSubmit={handleUpdateFinding} className="space-y-4">
                          <div className="grid grid-cols-2 gap-4">
                            {/* Status selector */}
                            <div>
                              <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
                                Change Status
                              </label>
                              <select
                                className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
                                value={statusUpdate}
                                onChange={(e) => setStatusUpdate(e.target.value)}
                              >
                                <option value="open">Open</option>
                                <option value="in_progress">In Progress</option>
                                <option value="resolved">Resolved</option>
                                <option value="accepted">Accepted (Risk Exception)</option>
                                <option value="false_positive">False Positive</option>
                              </select>
                            </div>

                            {/* Assignee */}
                            <div>
                              <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
                                Assignee
                              </label>
                              <select
                                className="w-full rounded-md border border-border bg-background py-2 px-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
                                value={assigneeUpdate}
                                onChange={(e) => setAssigneeUpdate(e.target.value)}
                              >
                                <option value="">Unassigned</option>
                                {user && <option value={user.id}>Assign to Me ({user.email})</option>}
                              </select>
                            </div>
                          </div>

                          {/* Reason for accepted or false positive */}
                          {["accepted", "false_positive", "resolved"].includes(statusUpdate) && (
                            <div>
                              <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
                                Change Reason / Remediation Description
                              </label>
                              <textarea
                                className="w-full rounded-md border border-border bg-background p-3 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
                                rows={3}
                                placeholder="Explain why this risk exception is being accepted, why it is a false positive, or how it was resolved..."
                                value={reasonUpdate}
                                onChange={(e) => setReasonUpdate(e.target.value)}
                              />
                            </div>
                          )}

                          <button
                            type="submit"
                            className="w-full rounded-md bg-cyan-600 py-2.5 text-sm font-semibold text-white hover:bg-cyan-500 focus:outline-none disabled:opacity-50"
                            disabled={updating}
                          >
                            {updating ? (
                              <Loader2 className="mx-auto h-4 w-4 animate-spin" />
                            ) : (
                              "Apply Changes"
                            )}
                          </button>
                        </form>
                      </div>
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

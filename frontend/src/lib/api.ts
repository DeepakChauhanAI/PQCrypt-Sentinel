/**
 * Shared API helper for the PQC scanner frontend.
 *
 * Centralises:
 *  - Auth header (Bearer token from localStorage)
 *  - JSON content-type defaults
 *  - Scan Group endpoints (Phase B)
 *  - Per-scan assets endpoint (Phase B)
 *  - Typed error / response handling
 */
export interface ScanGroupMemberSpec {
  scan_type: string;
  target: string;
  target_label?: string | null;
  target_kind?: string | null;
  config?: string | null;
  credential_profile?: string | null;
  advanced_tools?: boolean | null;
}

export interface ScanGroupCreate {
  name: string;
  description?: string | null;
  members: ScanGroupMemberSpec[];
  advanced_tools?: boolean;
}

export interface ScanGroup {
  id: string;
  name: string;
  description?: string | null;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  started_at?: string | null;
  completed_at?: string | null;
  created_at: string;
  updated_at: string;
  member_count: number;
  assets_found: number;
  findings_created: number;
}

export interface ScanGroupDetail extends ScanGroup {
  members: Array<{
    id: string;
    scan_type: string;
    target: string;
    status: string;
    scan_group_id?: string | null;
    target_label?: string | null;
    target_kind?: string | null;
    assets_found: number;
    findings_created: number;
    started_at?: string | null;
    completed_at?: string | null;
    duration_seconds?: number | null;
    error_message?: string | null;
    created_at: string;
    updated_at: string;
  }>;
}

export interface Asset {
  id: string;
  name: string;
  asset_type: string;
  ip_address?: string | null;
  fqdn?: string | null;
  port?: number | null;
  protocol?: string | null;
  environment?: string | null;
  first_scan_id?: string | null;
  last_scan_id?: string | null;
  first_discovered_at?: string | null;
  last_verified_at?: string | null;
  risk_score?: number | null;
  pqc_status?: string | null;
  business_service?: string | null;
  // Phase B — scan-group correlation enrichment (populated by
  // app.api.assets._enrich_assets_with_scan_groups)
  last_scan_group_id?: string | null;
  last_scan_group_name?: string | null;
  first_scan_group_id?: string | null;
  first_scan_group_name?: string | null;
}

const BASE = "/api/v1";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("access_token") ?? "";
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

async function handle<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    let detail = `HTTP ${resp.status}`;
    try {
      const body = await resp.json();
      detail = body.detail ?? detail;
    } catch {
      // ignore
    }
    throw new Error(detail);
  }
  return resp.json() as Promise<T>;
}

export const api = {
  /* ---- Scan Groups ---- */
  async listScanGroups(): Promise<ScanGroup[]> {
    return handle<ScanGroup[]>(await fetch(`${BASE}/scan-groups`, { headers: authHeaders() }));
  },
  async getScanGroup(id: string): Promise<ScanGroupDetail> {
    return handle<ScanGroupDetail>(
      await fetch(`${BASE}/scan-groups/${id}`, { headers: authHeaders() })
    );
  },
  async createScanGroup(payload: ScanGroupCreate): Promise<ScanGroupDetail> {
    return handle<ScanGroupDetail>(
      await fetch(`${BASE}/scan-groups`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify(payload),
      })
    );
  },
  async cancelScanGroup(id: string): Promise<ScanGroup> {
    return handle<ScanGroup>(
      await fetch(`${BASE}/scan-groups/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      })
    );
  },
  /* ---- Per-scan assets ---- */
  async listScanAssets(scanId: string): Promise<Asset[]> {
    return handle<Asset[]>(
      await fetch(`${BASE}/scans/${scanId}/assets`, { headers: authHeaders() })
    );
  },
  /* ---- Findings (with scan-group filter) ---- */
  async listFindings(opts: { scanGroupId?: string; scanId?: string } = {}): Promise<any[]> {
    const params = new URLSearchParams();
    if (opts.scanGroupId) params.set("scan_group_id", opts.scanGroupId);
    if (opts.scanId) params.set("scan_id", opts.scanId);
    const qs = params.toString();
    return handle<any[]>(
      await fetch(`${BASE}/findings${qs ? `?${qs}` : ""}`, { headers: authHeaders() })
    );
  },
};

export { authHeaders, handle, BASE };

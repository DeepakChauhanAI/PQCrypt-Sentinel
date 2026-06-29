import { Bell, LogOut, User2, RefreshCw } from "lucide-react";
import { useAuth } from "@/lib/authContext";
import { useLocation } from "react-router-dom";

interface RouteMeta {
  title: string;
  subtitle: string;
}

const ROUTE_META: Record<string, RouteMeta> = {
  "/": {
    title: "Executive Dashboard",
    subtitle: "Real-time Post-Quantum Cryptography transition readiness and quantum vulnerability tracking."
  },
  "/scans": {
    title: "Scans",
    subtitle: "Configure, trigger, and monitor post-quantum cryptography scanning tasks."
  },
  "/assets": {
    title: "Assets Explorer",
    subtitle: "Search, filter, and drill down into the cryptographic posture of discovered endpoints."
  },
  "/findings": {
    title: "Findings Console",
    subtitle: "Manage and remediate discovered cryptographic vulnerabilities and configuration drifts."
  },
  "/reports": {
    title: "Reports & Export Centre",
    subtitle: "Generate and export CycloneDX 1.5 Cryptographic Bill of Materials (CBOM) inventories."
  },
  "/connectors": {
    title: "Integration Connectors",
    subtitle: "Sync asset databases, CMDB inventories, and cloud KMS providers with PQCrypt Sentinel."
  },
  "/settings": {
    title: "System Settings",
    subtitle: "Configure scanning engine defaults, discovery IP ranges, database connections, and API profiles."
  },
  "/settings/users": {
    title: "User Directory",
    subtitle: "Manage administrative, analyst, and audit compliance team members access privileges."
  }
};

export function Header() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const path = location.pathname;

  let meta = ROUTE_META[path];
  if (!meta) {
    if (path.startsWith("/scans/")) {
      meta = {
        title: "Scan Details",
        subtitle: "Monitor active cryptographic audits, review detailed reports, and access logs."
      };
    } else {
      meta = {
        title: "PQCrypt Sentinel",
        subtitle: "Enterprise Post-Quantum Cryptography transition assurance platform."
      };
    }
  }

  const triggerRefresh = () => {
    window.dispatchEvent(new CustomEvent("dashboard:refresh"));
  };

  return (
    <header className="flex h-20 items-center justify-between border-b border-border bg-surface px-6">
      <div className="flex flex-col gap-0.5 min-w-0 pr-4">
        <span className="text-sm font-bold text-gray-200 truncate">{meta.title}</span>
        <span className="text-[10px] text-gray-500 truncate hidden sm:block max-w-[650px]">{meta.subtitle}</span>
      </div>
      <div className="flex items-center gap-3 shrink-0">
        {path === "/" && (
          <button
            onClick={triggerRefresh}
            className="rounded-md p-2 text-gray-400 hover:bg-border hover:text-gray-200 transition-colors"
            title="Refresh Dashboard"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        )}
        <button className="rounded-md p-2 text-gray-400 hover:bg-border hover:text-gray-200">
          <Bell className="h-4 w-4" />
        </button>
        <div className="flex items-center gap-3 rounded-md border border-border px-3 py-1.5 bg-[#0d1117]/50">
          <div className="flex items-center gap-1.5">
            <User2 className="h-4 w-4 text-gray-400" />
            <span className="text-sm text-gray-300 font-medium">
              {user?.email || "User"}
            </span>
          </div>
          <button
            onClick={logout}
            className="flex items-center text-gray-400 hover:text-red-400 transition-colors"
            title="Log out"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </header>
  );
}


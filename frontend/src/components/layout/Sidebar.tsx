import { Link } from "react-router-dom";
import {
  BarChart3,
  Boxes,
  FileWarning,
  LayoutDashboard,
  Layers,
  Plug2,
  PanelLeftClose,
  PanelLeftOpen,
  ScanSearch,
  Settings2,
  Users,
} from "lucide-react";
import { Logo } from "@/components/ui/Logo";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/scans", label: "Scans", icon: ScanSearch },
  { to: "/scan-groups", label: "Scan Groups", icon: Layers },
  { to: "/assets", label: "Assets", icon: Boxes },
  { to: "/findings", label: "Findings", icon: FileWarning },
  { to: "/reports", label: "Reports", icon: BarChart3 },
  { to: "/connectors", label: "Connectors", icon: Plug2 },
  { to: "/settings", label: "Settings", icon: Settings2 },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  return (
    <aside
      className={`sticky top-0 group flex h-screen flex-col border-r border-border bg-surface transition-all duration-200 ${
        collapsed ? "w-16" : "w-60"
      }`}
    >
      <div className="flex h-20 items-center justify-between px-3 border-b border-border/40">
        {collapsed ? (
          <div className="relative mx-auto flex h-8 w-8 items-center justify-center">
            {/* Show logo by default, hide on group hover */}
            <div className="group-hover:hidden transition-all duration-200">
              <Logo className="h-8 w-8" />
            </div>
            {/* Hide toggle by default, show on group hover */}
            <button
              onClick={onToggle}
              className="hidden group-hover:flex items-center justify-center rounded-md p-1.5 text-gray-400 hover:bg-border hover:text-gray-200 transition-all duration-200"
              aria-label="Expand sidebar"
              title="Expand sidebar"
            >
              <PanelLeftOpen className="h-5 w-5" />
            </button>
          </div>
        ) : (
          <>
            <div className="flex items-center gap-2">
              <Logo className="h-8 w-8" />
              <span className="text-xs font-semibold tracking-widest text-gray-200">PQC SENTINEL</span>
            </div>
            <button
              onClick={onToggle}
              className="rounded-md p-2 text-gray-400 hover:bg-border hover:text-gray-200 transition-colors"
              aria-label="Collapse sidebar"
              title="Collapse sidebar"
            >
              <PanelLeftClose className="h-5 w-5" />
            </button>
          </>
        )}
      </div>
      <nav className="flex-1 space-y-2 overflow-y-auto px-2 py-4">
        {NAV_ITEMS.map((item) => (
          <Link
            key={item.to}
            to={item.to}
            title={collapsed ? item.label : undefined}
            className={`flex items-center rounded-md text-sm hover:bg-border hover:text-gray-200 transition-all ${
              collapsed ? "justify-center h-10 w-10 mx-auto" : "gap-3 px-3 py-2"
            }`}
          >
            <item.icon className="h-5 w-5 shrink-0" />
            {!collapsed && <span>{item.label}</span>}
          </Link>
        ))}
      </nav>
      <div className="border-t border-border p-2">
        <Link
          to="/settings/users"
          title={collapsed ? "Users" : undefined}
          className={`flex items-center rounded-md text-sm text-gray-400 hover:bg-border hover:text-gray-200 transition-all ${
            collapsed ? "justify-center h-10 w-10 mx-auto" : "gap-3 px-3 py-2"
          }`}
        >
          <Users className="h-5 w-5 shrink-0" />
          {!collapsed && <span>Users</span>}
        </Link>
      </div>
    </aside>
  );
}


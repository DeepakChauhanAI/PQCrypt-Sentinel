import { lazy, Suspense } from "react";
import {
  Navigate,
  Route,
  Routes,
} from "react-router-dom";

import { AppShell } from "@/components/layout/AppShell";
import { AuthProvider, useAuth } from "@/lib/authContext";

const Dashboard = lazy(() => import("@/pages/Dashboard"));
const Login = lazy(() => import("@/pages/Login"));
const ScanList = lazy(() => import("@/pages/ScanList"));
const ScanDetail = lazy(() => import("@/pages/ScanDetail"));
const ScanRunDetail = lazy(() => import("@/pages/ScanRunDetail"));
const ScanGroups = lazy(() => import("@/pages/ScanGroups"));
const Assets = lazy(() => import("@/pages/Assets"));
const Findings = lazy(() => import("@/pages/Findings"));
const Reports = lazy(() => import("@/pages/Reports"));
const Connectors = lazy(() => import("@/pages/Connectors"));
const Migration = lazy(() => import("@/pages/Migration"));
const Settings = lazy(() => import("@/pages/Settings"));
const Users = lazy(() => import("@/pages/Users"));

function LoadingFallback() {
  return (
    <div className="flex h-screen items-center justify-center bg-background">
      <div className="text-center space-y-2">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-t-transparent border-gray-400 mx-auto" />
        <p className="text-sm text-gray-400">Loading…</p>
      </div>
    </div>
  );
}

import { Link } from "react-router-dom";

function Forbidden() {
  return (
    <div className="flex h-screen flex-col items-center justify-center bg-background text-gray-250">
      <div className="rounded-lg border border-border bg-surface p-8 text-center max-w-md space-y-4">
        <h1 className="text-5xl font-extrabold text-red-500 tracking-tight">403</h1>
        <p className="text-xl font-bold">Access Denied</p>
        <p className="text-sm text-gray-400">
          You do not have the required permissions to view this resource.
        </p>
        <Link
          to="/"
          className="inline-block rounded-md bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-500 transition-colors"
        >
          Back to Dashboard
        </Link>
      </div>
    </div>
  );
}

function ProtectedRoute({
  children,
  allowedRoles,
}: {
  children: React.ReactNode;
  allowedRoles?: string[];
}) {
  const { user, loading } = useAuth();

  if (loading) {
    return <LoadingFallback />;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return <Forbidden />;
  }

  return <>{children}</>;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();

  if (loading) {
    return <LoadingFallback />;
  }

  if (user) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}

export default function App() {
  return (
    <AuthProvider>
      <Suspense fallback={<LoadingFallback />}>
        <Routes>
          <Route
            path="/login"
            element={
              <PublicRoute>
                <Login />
              </PublicRoute>
            }
          />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <AppShell>
                  <Dashboard />
                </AppShell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/scans"
            element={
              <ProtectedRoute>
                <AppShell>
                  <ScanList />
                </AppShell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/scans/:id"
            element={
              <ProtectedRoute>
                <AppShell>
                  <ScanDetail />
                </AppShell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/scan-groups"
            element={
              <ProtectedRoute>
                <AppShell>
                  <ScanGroups />
                </AppShell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/scan-groups/:id"
            element={
              <ProtectedRoute>
                <AppShell>
                  <ScanRunDetail />
                </AppShell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/assets"
            element={
              <ProtectedRoute>
                <AppShell>
                  <Assets />
                </AppShell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/findings"
            element={
              <ProtectedRoute>
                <AppShell>
                  <Findings />
                </AppShell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/reports"
            element={
              <ProtectedRoute>
                <AppShell>
                  <Reports />
                </AppShell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/connectors"
            element={
              <ProtectedRoute allowedRoles={["admin", "analyst"]}>
                <AppShell>
                  <Connectors />
                </AppShell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/migration"
            element={
              <ProtectedRoute>
                <AppShell>
                  <Migration />
                </AppShell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute allowedRoles={["admin"]}>
                <AppShell>
                  <Settings />
                </AppShell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings/users"
            element={
              <ProtectedRoute allowedRoles={["admin"]}>
                <AppShell>
                  <Users />
                </AppShell>
              </ProtectedRoute>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </AuthProvider>
  );
}



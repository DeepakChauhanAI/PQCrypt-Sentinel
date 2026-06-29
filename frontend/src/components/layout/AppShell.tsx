import { useState } from "react";
import { Sidebar } from "./Sidebar";
import { Header } from "./Header";

interface AppShellProps {
  children: React.ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="flex min-h-screen bg-background">
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((value) => !value)} />
      <div className="flex min-h-screen flex-1 flex-col">
        <Header />
        <main className="relative mx-auto w-full max-w-[1400px] flex-1 px-6 py-8">
          {children}
        </main>
      </div>
    </div>
  );
}

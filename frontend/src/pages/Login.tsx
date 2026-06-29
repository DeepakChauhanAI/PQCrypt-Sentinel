import { useState } from "react";
import type { FormEvent } from "react";
import { useAuth } from "@/lib/authContext";
import { Logo } from "@/components/ui/Logo";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await login(email, password);
    } catch (loginError) {
      setError(loginError instanceof Error ? loginError.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-md rounded-lg border border-border bg-surface p-6 shadow-lg">
        <div className="flex flex-col items-center mb-6 text-center">
          <Logo className="h-24 w-24 mb-3" />
          <h1 className="text-2xl font-bold tracking-tight text-gray-100">PQCrypt Sentinel</h1>
          <p className="mt-1 text-xs text-gray-400">Post-Quantum Cryptography Discovery Platform</p>
        </div>
        <div className="border-t border-border/60 my-5" />
        <h2 className="text-lg font-semibold text-gray-200">Sign in</h2>
        <p className="mt-1 text-sm text-gray-400">Access your dashboard with credentials.</p>
        <form className="mt-6 space-y-4" onSubmit={handleSubmit}>
          <div className="space-y-1">
            <label className="text-sm text-gray-300" htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-gray-100 outline-none placeholder:text-gray-500 focus:border-gray-400"
              placeholder="you@company.com"
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm text-gray-300" htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-gray-100 outline-none placeholder:text-gray-500 focus:border-gray-400"
              placeholder="••••••••"
            />
          </div>
          {error ? <p className="text-sm text-critical">{error}</p> : null}
          <button
            type="submit"
            disabled={loading}
            className="flex w-full items-center justify-center rounded-md bg-[#2ea043] px-3 py-2 text-sm font-semibold text-white hover:bg-[#23863c] disabled:opacity-70"
          >
            {loading ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}

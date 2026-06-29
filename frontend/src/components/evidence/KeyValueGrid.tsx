/**
 * Generic key-value grid for typed evidence rendering.
 *
 * Supports mono / badge / list / accent colour hints so the typed
 * evidence renderer (EvidenceRenderer) can highlight specific fields
 * without per-case component code.
 */
import { ReactNode } from "react";

export interface KeyValueItem {
  label: string;
  value: string | number | boolean | string[] | number[] | boolean[] | any;
  mono?: boolean;
  badge?: boolean;
  list?: boolean;
  accent?: "cyan" | "red" | "yellow" | "green";
}

export interface KeyValueGridProps {
  items: KeyValueItem[];
  columns?: 1 | 2;
}

export function KeyValueGrid({ items, columns = 2 }: KeyValueGridProps) {
  if (items.length === 0) {
    return <div className="text-sm text-gray-500">No structured evidence available.</div>;
  }
  const colClass = columns === 1 ? "grid-cols-1" : "grid-cols-2";
  return (
    <div className={`grid gap-x-6 gap-y-3 rounded-lg border border-border bg-background p-4 ${colClass}`}>
      {items.map((it, i) => (
        <div key={i} className="min-w-0">
          <div className="text-xs text-gray-500">{it.label}</div>
          <div className="mt-0.5 text-sm text-gray-300 break-words">
            {renderValue(it)}
          </div>
        </div>
      ))}
    </div>
  );
}

function renderValue(it: KeyValueItem): ReactNode {
  const accentClass: Record<string, string> = {
    cyan: "text-cyan-300",
    red: "text-red-300",
    yellow: "text-yellow-300",
    green: "text-green-300",
  };
  const baseMono = "font-mono text-xs";
  const valueStr = String(it.value);

  if (it.badge) {
    return (
      <span className="inline-flex rounded-full bg-cyan-950/40 border border-cyan-800/50 px-2 py-0.5 text-xs font-semibold text-cyan-300 uppercase">
        {valueStr}
      </span>
    );
  }
  if (it.list && Array.isArray(it.value)) {
    return (
      <ul className="space-y-0.5">
        {it.value.map((v, i) => (
          <li key={i} className="font-mono text-xs text-gray-300">
            {String(v)}
          </li>
        ))}
      </ul>
    );
  }
  const className = [
    it.mono ? baseMono : "text-sm",
    it.accent ? accentClass[it.accent] : "",
    "break-words",
  ].join(" ");
  return <span className={className}>{valueStr}</span>;
}

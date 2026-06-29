# UI/UX Design Brief

**Product:** PQCrypt Sentinel PQC Discovery Platform  
**Version:** 1.0  
**Date:** June 2026  
**Author:** Design Team  
**Status:** Draft  

---

## 1. Design Philosophy

### Core Principles

1. **Clarity over decoration** — Every element must communicate information. No decorative graphics that don't serve a purpose.
2. **Progressive disclosure** — Show summary first, details on demand. Don't overwhelm non-technical users.
3. **Actionable by default** — Every screen should answer "what do I do next?" Not just display data.
4. **Security-first dark mode** — Primary theme is dark mode (reduces eye strain for security analysts during long sessions). Light mode available.
5. **Data-dense but scannable** — Security tools are information-dense. Use hierarchy, spacing, and color to make dense data scannable.

---

## 2. Color Palette

### Dark Mode (Primary)

| Role | Color | Hex | Usage |
|---|---|---|---|
| **Background** | Deep charcoal | `#0d1117` | Page background |
| **Surface** | Dark slate | `#161b22` | Cards, panels, modals |
| **Surface Elevated** | Slate | `#1c2128` | Hover states, active items |
| **Border** | Subtle gray | `#30363d` | Dividers, card borders |
| **Text Primary** | White | `#f0f6fc` | Headings, primary content |
| **Text Secondary** | Silver | `#8b949e` | Labels, descriptions |
| **Accent (Primary)** | Electric cyan | `#58a6ff` | Links, active states, highlights |
| **Accent (Hover)** | Bright cyan | `#79c0ff` | Hover on accent elements |
| **Critical** | Red | `#f85149` | Critical severity, errors, deletions |
| **High** | Orange | `#d29922` | High severity, warnings |
| **Medium** | Yellow | `#e3b341` | Medium severity, caution |
| **Low** | Green | `#3fb950` | Low severity, success, PQC-ready |
| **Info** | Blue | `#58a6ff` | Informational badges, Tier indicators |
| **PQC-Ready** | Emerald | `#2ea043` | PQC-ready badges, success states |

### Light Mode (Secondary)

| Role | Color | Hex |
|---|---|---|
| **Background** | Off-white | `#f6f8fa` |
| **Surface** | White | `#ffffff` |
| **Surface Elevated** | Light gray | `#f0f2f5` |
| **Border** | Gray | `#d0d7de` |
| **Text Primary** | Near-black | `#1f2328` |
| **Text Secondary** | Gray | `#656d76` |
| **Accent** | Blue | `#0969da` |

---

## 3. Typography

| Element | Font | Weight | Size | Line Height | Letter Spacing |
|---|---|---|---|---|---|
| **Display (Dashboard KPIs)** | Inter | 700 | 48px | 1.1 | -0.02em |
| **Page Title (H1)** | Inter | 600 | 28px | 1.3 | -0.01em |
| **Section Title (H2)** | Inter | 600 | 20px | 1.4 | 0 |
| **Card Title (H3)** | Inter | 600 | 16px | 1.4 | 0 |
| **Body** | Inter | 400 | 14px | 1.6 | 0 |
| **Small / Label** | Inter | 500 | 12px | 1.5 | 0.01em |
| **Badge / Tag** | JetBrains Mono | 500 | 11px | 1.0 | 0.05em |
| **Code / Technical** | JetBrains Mono | 400 | 13px | 1.5 | 0 |
| **Table Header** | Inter | 600 | 12px | 1.0 | 0.05em |
| **Table Cell** | Inter | 400 | 13px | 1.4 | 0 |

**Font Stack:**
- Primary: `'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif`
- Monospace: `'JetBrains Mono', 'Fira Code', 'Consolas', monospace`

---

## 4. Layout Direction

### Grid System

- **Max width:** 1400px (centered)
- **Sidebar width:** 240px (collapsible to 64px icon-only)
- **Content area:** Fluid within max-width constraint
- **Breakpoints:** 1280px (desktop), 1024px (tablet), 768px (mobile — not primary target)

### Page Layout

```
┌─────────┬──────────────────────────────────────────┐
│         │  Breadcrumb / Page Title                  │
│ Sidebar │──────────────────────────────────────────│
│  240px  │  Content area (scrollable)                │
│         │                                           │
│         │  ┌─────────┐ ┌─────────┐ ┌─────────┐     │
│         │  │  Card   │ │  Card   │ │  Card   │     │
│         │  └─────────┘ └─────────┘ └─────────┘     │
│         │                                           │
│         │  ┌───────────────────────────────────┐   │
│         │  │         Table / Chart              │   │
│         │  │                                    │   │
│         │  └───────────────────────────────────┘   │
└─────────┴──────────────────────────────────────────┘
```

### Spacing Scale

| Token | Value | Usage |
|---|---|---|
| `xs` | 4px | Inline gaps, badge padding |
| `sm` | 8px | Tight component spacing |
| `md` | 16px | Standard component padding |
| `lg` | 24px | Section gaps, card padding |
| `xl` | 32px | Page section spacing |
| `2xl` | 48px | Major section dividers |

---

## 5. Component Style

### Buttons

| Type | Style | Usage |
|---|---|---|
| **Primary** | Solid fill (accent color), white text, 8px radius | Primary actions (Run Scan, Save, Create) |
| **Secondary** | Border only, accent text, transparent bg | Secondary actions (Cancel, Export) |
| **Ghost** | No border, text only, accent on hover | Tertiary actions (Learn More, View All) |
| **Danger** | Solid red fill, white text | Destructive actions (Delete, Cancel Scan) |
| **Icon** | Square, no text, tooltip on hover | Toolbar actions (Refresh, Filter, Sort) |

**Button sizes:** Small (28px), Medium (36px — default), Large (44px)

### Badges

| Type | Style | Usage |
|---|---|---|
| **Severity** | Rounded pill, colored bg + white text | Critical (red), High (orange), Medium (yellow), Low (green) |
| **PQC Status** | Rounded pill, colored bg | Vulnerable (red), Transitioning (yellow), Hybrid (blue), PQC-Ready (green) |
| **Status** | Rounded pill | Open (red), In Progress (yellow), Resolved (green), Accepted (gray) |
| **Tier** | Rounded pill, numbered | Tier 0-4 with color coding |
| **Count** | Small circle, accent bg | Notification counts |

### Cards

- **Background:** Surface color with 1px border
- **Border radius:** 8px
- **Shadow:** None in dark mode (use border); subtle in light mode
- **Padding:** 24px
- **Header:** Bold title + optional subtitle + optional action buttons
- **Hover:** Border color shifts to accent

### Tables

- **Header:** Bold, uppercase, letter-spaced, accent background
- **Rows:** Alternating subtle background (zebra striping)
- **Hover:** Row background shifts to elevated surface
- **Sortable columns:** Click header to sort, arrow indicator
- **Selection:** Checkbox column for bulk actions
- **Pagination:** Bottom bar with page numbers, items-per-page selector

### Forms

- **Input fields:** 36px height, 1px border, 6px radius, dark surface bg
- **Focus state:** Accent border + subtle glow
- **Labels:** Above input, 12px, secondary text color
- **Validation:** Inline error message below field, red border
- **Dropdowns:** Same style as inputs, searchable for long lists

---

## 6. Dashboard Structure

### Executive Dashboard (S2)

```
┌─────────────────────────────────────────────────────┐
│  PQC Readiness     │  Risk Distribution  │  HNDL    │
│  Score: 42%        │  [Donut Chart]      │ Timeline │
│  [Circular Gauge]  │                     │ [Bar]    │
├─────────────────────────────────────────────────────┤
│  Top 10 Vulnerable Assets                          │
│  ┌──────────────────────────────────────────────┐  │
│  │ Asset      │ Algorithm │ Risk │ Owner │ Action│  │
│  │ api.bank   │ RSA-2048  │ 92   │ Ops   │ [Fix]│  │
│  │ vpn-01     │ ECDH-P256 │ 87   │ Net   │ [Fix]│  │
│  └──────────────────────────────────────────────┘  │
├──────────────────────────┬──────────────────────────┤
│  Migration Progress      │  Scan Coverage           │
│  [Line Chart - 12 mo]    │  [Horizontal Bars]       │
│                          │                          │
├──────────────────────────┴──────────────────────────┤
│  Drift Alerts (3)           New Discoveries (12)    │
│  [Card with count + link]   [Card with count + link]│
└─────────────────────────────────────────────────────┘
```

### Asset Detail (S5)

```
┌─────────────────────────────────────────────────────┐
│  ← Back to Assets                                   │
│                                                     │
│  api.bank.example.com                    [Re-scan]  │
│  Server │ 10.20.30.40 │ Owner: Payments Team        │
│  Risk Score: 92 (Critical)                          │
│                                                     │
│  [Overview] [Algorithms] [Certificates] [Findings]  │
│  [Dependencies] [History]                           │
│                                                     │
│  ┌──────────────────────────────────────────────┐  │
│  │ Algorithms in use                            │  │
│  │ ┌──────────┬────────┬──────┬──────────────┐ │  │
│  │ │ Algorithm│ Type   │ Size │ PQC Status   │ │  │
│  │ │ RSA-2048 │ Sig    │ 2048 │ Vulnerable   │ │  │
│  │ │ ECDHE    │ KEX    │ P-256│ Vulnerable   │ │  │
│  │ │ AES-256  │ Symm   │ 256  │ Safe         │ │  │
│  │ └──────────┴────────┴──────┴──────────────┘ │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## 7. Mobile Responsiveness

**Target:** Desktop-first, tablet-compatible. Mobile is not a primary target for this product (security analysts work on desktops).

| Breakpoint | Behavior |
|---|---|
| **> 1280px** | Full layout with sidebar |
| **1024-1280px** | Sidebar collapses to icons, content adjusts |
| **768-1024px** | Sidebar hidden (hamburger menu), cards stack vertically |
| **< 768px** | Not supported — show "Please use a desktop or tablet" message |

---

## 8. Data Visualization Guidelines

### Charts

| Chart Type | Usage | Library |
|---|---|---|
| **Donut/Pie** | Risk distribution, algorithm breakdown | Recharts |
| **Line** | Migration progress over time, scan trends | Recharts |
| **Bar** | HNDL timeline, findings by severity | Recharts |
| **Gauge** | PQC readiness score | Custom SVG or Recharts |
| **Force Graph** | Dependency/blast-radius visualization | React Flow or D3 |
| **Heatmap** | Scan coverage by business service | Custom |

### Chart Styling

- Use the severity color palette for risk-related charts
- Use the accent palette for neutral/progressive charts
- Always include tooltips with exact values
- Include legends only when > 2 data series
- Axis labels in monospace font for technical data
- No 3D charts, no gradients, no decorative elements

---

## 9. Icon System

**Icon Library:** Lucide Icons (open-source, MIT license, 1000+ icons)

**Key Icons:**
| Concept | Icon |
|---|---|
| Asset/Server | `server` or `monitor` |
| Certificate | `file-badge` or `shield-check` |
| Algorithm | `key` or `lock` |
| Finding/Alert | `alert-triangle` or `shield-alert` |
| Scan | `radar` or `search` |
| Settings | `settings` |
| User | `user` |
| Dashboard | `layout-dashboard` |
| Report | `file-text` |
| Connector | `plug` or `link` |
| PQC-Ready | `shield-check` (green) |
| Vulnerable | `shield-alert` (red) |

---

## 10. Animation & Motion

| Element | Animation | Duration | Easing |
|---|---|---|---|
| **Page transitions** | Fade in + slide up | 200ms | ease-out |
| **Card hover** | Border color shift | 150ms | ease |
| **Modal open** | Fade in + scale from 0.95 | 200ms | ease-out |
| **Modal close** | Fade out | 150ms | ease-in |
| **Toast notification** | Slide in from right | 300ms | ease-out |
| **Toast dismiss** | Slide out right | 200ms | ease-in |
| **Progress bar** | Smooth width transition | 300ms | ease |
| **Table sort** | No animation (instant) | — | — |
| **Scan live log** | Auto-scroll, no animation | — | — |

**Rule:** Animations should be functional (guide attention, show state changes), not decorative. Disable animations if user has `prefers-reduced-motion`.

---

## 11. Empty States

Every screen has a designed empty state for when no data exists.

**Pattern:**
1. Illustration or icon (centered, muted color)
2. Heading: "No [thing] yet"
3. Description: What to do to populate this screen
4. CTA button: Primary action to take

**Examples:**
- **Dashboard (no scans):** Shield icon + "Run your first scan to discover your cryptographic posture" + [Start Scan] button
- **Assets (empty):** Server icon + "No assets discovered yet" + [Run Scan] button
- **Findings (empty):** Checkmark icon + "No findings — your environment looks PQC-ready"
- **Reports (empty):** File icon + "No reports generated yet" + [Generate Report] button

---

## 12. Accessibility

| Requirement | Standard |
|---|---|
| **Color contrast** | WCAG 2.1 AA (4.5:1 for text, 3:1 for large text) |
| **Keyboard navigation** | All interactive elements reachable via Tab |
| **Screen reader** | ARIA labels on all icons, charts, and interactive elements |
| **Focus indicators** | Visible focus ring on all focusable elements |
| **Reduced motion** | Respect `prefers-reduced-motion` media query |
| **Alt text** | All images and charts have descriptive alt text |

---

## 13. Visual References

The design draws inspiration from:

| Product | What to Borrow |
|---|---|
| **GitHub** | Dark mode palette, table design, badge system |
| **Vercel Dashboard** | Clean layout, typography hierarchy, card design |
| **Linear** | Sidebar navigation, keyboard shortcuts, modal design |
| **Grafana** | Dashboard widget patterns, chart density |
| **Wiz** | Security finding cards, severity badges, asset explorer |
| **Snyk** | Finding detail layout, remediation guidance |

---

## 14. Design Tokens (CSS Custom Properties)

```css
:root {
  /* Colors - Dark Mode */
  --bg-primary: #0d1117;
  --bg-surface: #161b22;
  --bg-elevated: #1c2128;
  --border-default: #30363d;
  --text-primary: #f0f6fc;
  --text-secondary: #8b949e;
  --accent: #58a6ff;
  --accent-hover: #79c0ff;
  --critical: #f85149;
  --high: #d29922;
  --medium: #e3b341;
  --low: #3fb950;
  --info: #58a6ff;

  /* Typography */
  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-mono: 'JetBrains Mono', 'Fira Code', monospace;

  /* Spacing */
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 32px;
  --space-2xl: 48px;

  /* Border Radius */
  --radius-sm: 4px;
  --radius-md: 6px;
  --radius-lg: 8px;
  --radius-full: 9999px;

  /* Shadows (light mode only) */
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
  --shadow-md: 0 4px 6px rgba(0,0,0,0.07);
}
```

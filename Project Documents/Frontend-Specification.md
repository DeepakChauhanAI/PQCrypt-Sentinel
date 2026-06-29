# Frontend Specification Document

**Product:** PQCrypt Sentinel  
**Version:** 1.0  
**Date:** June 2026  
**Status:** Draft  
**Related:** `04-UI-UX-Design-Brief.md` (design system)

---

## Environment Context
- OS: Windows
- Project root: `D:\Project Files\PQC_Scanner`
- Container use: Not assumed for frontend work. Env var defaults and scripts are Windows-friendly.
- Path convention: Backslash paths (`\\`) in any helper scripts. Browser URLs stay forward-slash.

---

## 1. Design System

### 1.1 Core Principles (non-negotiable order)
1. **Clarity over decoration** — no decorative content
2. **Progressive disclosure** — summary first, details on demand
3. **Actionable by default** — every screen answers "what do I do next?"
4. **Dark mode first** — primary theme; light is secondary toggle
5. **Data-dense but scannable** — hierarchy, spacing, and color win

### 1.2 Color Palette
- Source of truth: `04-UI-UX-Design-Brief.md`
- Designs must include both favicon and web app manifest theme colors in `index.html`

---

## 2. Typography
- Source of truth: `04-UI-UX-Design-Brief.md`
- Monospace policy: algorithm names, cipher suites, OIDs, hashes are JetBrains Mono

---

## 3. Layout & Spacing
- Source of truth: `04-UI-UX-Design-Brief.md`
- Sidebar: 240px (collapsible). Collapsed state is 64px icon rail and must be keyboard-discoverable

---

## 4. Component Styles
- Source of truth: `04-UI-UX-Design-Brief.md`
- Severity color mapping:
  - critical: `#f85149`
  - high: `#d29922`
  - medium: `#e3b341`
  - low: `#3fb950`
  - info: `#58a6ff`
  - PQC-Ready: `#2ea043`

---

## 5. Dashboard Layouts
- Source of truth: `04-UI-UX-Design-Brief.md`

---

## 6. Accessibility
- Required: WCAG 2.2 AA for all interactive UI
- Keyboard-accessible rating: ALL interactive elements must be reachable via keyboard

---

## 7. API & Integration Spec
This section defines every external call and expected schema.

### 7.1 Base configuration
- API base URL: `/api/v1`
- Auth: bearer token via `Authorization` header
- Content type: `application/json`
- WebSocket: `/api/v1/ws/scans/{scanId}`

### 7.2 Key endpoints by feature
- Scans: create, list, detail, cancel, rerun
- Findings: list, update status, assign
- Assets: list, detail, related algorithms/certificates/findings
- Reports: generate and download
- Connectors: list, create, test, trigger sync
- Auth: login, refresh, logout

### 7.3 Error contract
Always return a structured envelope with machine-readable code, human message, detail, timestamp, and request ID.


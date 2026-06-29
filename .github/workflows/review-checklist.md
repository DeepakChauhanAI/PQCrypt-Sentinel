# Runtime Security Checklist for Code Reviewers

Use this before merging any PR that touches security-critical code.

---

## Auth Changes

- [ ] No new endpoints added without a `require_roles(...)` or `require_scope(...)` dependency
- [ ] Password hashing uses `bcrypt` with cost ≥ 12 (check for `bcrypt.gensalt(rounds=12)`)
- [ ] JWT secret is read from `SECRET_KEY` env var — never hardcoded
- [ ] Token lifetimes not increased beyond 1h access / 7d refresh
- [ ] No `localStorage` usage for tokens — refresh token must be httpOnly cookie
- [ ] Login endpoint has rate limiting (check Redis-backed rate limiter exists)

---

## Scanner Changes

- [ ] Every new `subprocess` call uses `asyncio.wait_for(..., timeout=...)` — no unbounded calls
- [ ] No shell=True in subprocess — all args are passed as a list
- [ ] Credential paths logged, not credential values
- [ ] SSRF block present: 169.254.169.254 blocked in scanner network
- [ ] New scanner subclass has `access_tier` property set (not defaulted to 0)
- [ ] Scan output passed through `sanitize_output()` before storage

---

## Database Changes

- [ ] New tables/columns include `created_at`, `updated_at`, `deleted_at` unless there is a documented exception
- [ ] All timestamps use `TIMESTAMPTZ`, not naive `TIMESTAMP`
- [ ] New foreign keys use `ondelete="SET NULL"` (never `CASCADE` on user-facing tables)
- [ ] New indexes created in the same migration as the table
- [ ] No raw SQL strings — ORM queries only (check for `text(...)`, `execute(raw_sql)`)
- [ ] JSONB fields have documented expected schema in `Secure-Development-Baseline.md`

---

## New Dependencies

- [ ] `pip-audit` run on the new package: no CRITICAL CVEs
- [ ] Package has active maintainer (last commit within 12 months)
- [ ] Version pinned in `requirements.txt` (no `package>=1.0`, use `package==1.0.5`)
- [ ] License is not AGPL/GPL without legal review
- [ ] Crypto library approval gate passed (see Section 4.1 of baseline doc)
- [ ] Not in the forbidden list: `pycrypto`, `pyopenssl<24.0`, `requests<2.32`

---

## Frontend Changes

- [ ] No API keys, tokens, or secrets in frontend source code or localStorage
- [ ] All API calls use the centralized `api-client.ts` (not inline `fetch`)
- [ ] New API endpoints documented in OpenAPI spec before frontend code calls them
- [ ] Error states display structured error code — no `alert()`, no raw error text
- [ ] No `debugger` statements, no `console.log` of sensitive data in production code

---

## CI/CD Changes

- [ ] New CI step does not bypass existing security gates
- [ ] Secrets in GitHub Actions use `${{ secrets.* }}` references, not hardcoded values
- [ ] New Dockerfile follows the non-root + multi-stage rules from baseline doc

---

## Pre-Merge Final Checks

- [ ] `pre-commit run --all-files` passes locally
- [ ] New code has unit tests; coverage on new code ≥ 80%
- [ ] Any code touching `backend/app/auth/`, `backend/app/scanners/`, or `backend/app/analysis/` has been read by a reviewer

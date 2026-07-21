# RLS Lockdown — Migration Plan (Prerequisites)

Status: **draft, not started.** No SQL has been run. This is the plan for closing
the gaps found during the read-only readiness audit before
`sql-rls-lockdown.sql` (in the `covercare-africa` repo) can be run against
`workers` and `shifts`. `facilities` and `facility_branches` are already
safe to lock down — every live frontend read for those two tables already
matches the policy that would replace it.

---

## 🔴 Standalone security item — fix independently of RLS

**`dashboard-facility.js:732-741` (`showWorkerDetailsById`) and
`dashboard-facility.js:859-866` (`openFacilityRatingModal`) are a live IDOR
today, RLS or no RLS.**

```js
// dashboard-facility.js:734-738
const { data, error } = await _supabase
  .from("workers")
  .select("id, full_name, role, phone, email, city, experience, bio, profile_photo_url, license_verified, identity_verified")
  .eq("id", workerId)
  .single();
```

Both call sites fetch a worker row by an arbitrary client-supplied
`workerId` with **no ownership check at all** — using the anon key, over
the public REST API. Any authenticated user (facility, client, or worker
account) can currently read any other worker's full profile, including
`phone` and `email`, just by guessing/enumerating worker IDs. This is the
same bug class as the `/shift/accept` IDOR fixed on `phase-0-security-fixes`,
just not caught by that audit because it's a frontend-direct read rather
than a backend endpoint.

This should be fixed by adding endpoint **#5 below** (`GET
/worker/:id`) and switching both call sites to use it, **independent of
whether/when the RLS SQL file runs** — it's exploitable right now via the
anon key regardless of RLS status, and will *also* still be exploitable
after RLS ships unless `workers` is one of the locked-down tables (which it
will be) **and** these two call sites are migrated (which is blocked on
this same endpoint anyway). Recommend treating this as its own priority
item, not bundled with the rest of the RLS prep.

---

## Readiness recap (from the read-only audit)

| Table | Verdict |
|---|---|
| facilities | Safe — no migration needed |
| facility_branches | Safe — no migration needed (deliberately public-to-authenticated) |
| workers | Not safe — 4 breakages, see below |
| shifts | Not safe — 3 breakages, see below |
| applications, clients | Out of scope for this SQL file (Phase 2) |

Even the two "safe" tables should not be run tonight per your instruction —
wait for a staging pass on all four before running anything on production.

---

## New backend endpoints needed

### 1. `GET /admin/workers` — bulk admin list
Replaces: `admin.js:113-117` (`loadWorkers()`, raw `select("*")` order by
`created_at`, anon key).

```js
app.get("/admin/workers", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  const { data, error } = await supabase
    .from("workers")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) return res.status(500).json({ success: false, message: "Failed to load workers." });
  return res.json({ success: true, data: data || [] });
});
```
Frontend change: `admin.js` `loadWorkers()` → `ccFetch("/admin/workers")` instead of `_supabase.from("workers")...`.

### 2. `GET /admin/facilities` — bulk admin list
Replaces: `admin.js:255-263` (`loadFacilities()`, same pattern).
Same shape as #1, table `facilities`.

### 3. `GET /admin/shifts` — bulk admin list
Replaces: `admin.js:431-439` (`loadShifts()`, same pattern).
Same shape as #1, table `shifts`.

> Note: `/admin/worker/:id` and `/admin/facility/:id` (single-row lookups)
> already exist in `server.js` — #1-#3 are new because there is currently
> no *bulk list* admin endpoint for any of the three tables.

### 4. `POST /shift/facility-cancel` — facility-initiated cancel
Replaces: `dashboard-facility.js:344-361` (`cancelShift()`):

```js
const { error } = await _supabase
  .from("shifts")
  .update({ status: "cancelled" })
  .eq("id", shiftId)
  .eq("contact_email", facilityEmail);
```

This is **not** the same as the existing `/shift/cancel` (server.js:5262) —
that one is worker-initiated: it reverts the shift to `status: "open"`,
clears `worker_id`/`qr_token`, and tries to find a replacement worker. The
facility-side action is a different transition (`status: "cancelled"`,
terminal) and has no backend endpoint today. The SQL file also defines
**zero UPDATE policy** on `shifts`, so this write would be silently denied
under RLS with no fallback — this is the single most urgent gap to close.

```js
app.post("/shift/facility-cancel", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const shiftId = sanitize(req.body.shift_id);
  if (!shiftId) {
    return res.status(400).json({ success: false, message: "shift_id is required." });
  }

  const { data: shift } = await supabase
    .from("shifts")
    .select("id, contact_email, status")
    .eq("id", shiftId)
    .single();

  if (!shift || shift.contact_email?.toLowerCase() !== user.email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "You can only cancel your own shifts." });
  }

  const { error } = await supabase
    .from("shifts")
    .update({ status: "cancelled" })
    .eq("id", shiftId);

  if (error) {
    return res.status(500).json({ success: false, message: "Failed to cancel shift." });
  }

  return res.json({ success: true, message: "Shift cancelled." });
});
```
Frontend change: `dashboard-facility.js` `cancelShift(shiftId)` → `ccFetch("/shift/facility-cancel", { method: "POST", body: JSON.stringify({ shift_id: shiftId }) })`.

### 5. `GET /worker/:id` — ownership-checked worker detail lookup
Replaces: `dashboard-facility.js:732-741` (`showWorkerDetailsById`) **and**
`dashboard-facility.js:859-866` (`openFacilityRatingModal`). Also closes
the standalone IDOR flagged at the top of this document.

Authorization rule: caller must be either (a) an admin, or (b) a
facility/client that has a legitimate relationship to that worker — mirror
the "allowed set" pattern already used by `/facility/shift-workers`
(server.js:5817-5843), i.e. the worker must be assigned to one of the
caller's own shifts (`shifts.contact_email = caller`).

```js
app.get("/worker/:id", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const workerId = sanitize(req.params.id);

  if (!requireAdmin(req, res, { silent: true })) {
    // Not an admin — verify a legitimate hiring relationship exists.
    const { data: shifts } = await supabase
      .from("shifts")
      .select("worker_id")
      .eq("contact_email", user.email.toLowerCase())
      .eq("worker_id", workerId);

    if (!shifts || shifts.length === 0) {
      return res.status(403).json({ success: false, message: "You can only view workers assigned to your own shifts." });
    }
  }

  const { data: worker, error } = await supabase
    .from("workers")
    .select("id, full_name, role, phone, email, city, experience, bio, profile_photo_url, license_verified, identity_verified")
    .eq("id", workerId)
    .single();

  if (error || !worker) {
    return res.status(404).json({ success: false, message: "Worker not found." });
  }

  return res.json({ success: true, data: worker });
});
```

**Implementation note:** `requireAdmin` today calls `res.status(403).json(...)`
directly when the check fails (see server.js:194), so it can't be probed
silently as sketched above without changing its signature. Two options at
implementation time: (a) add an optional `{ silent: true }` param to
`requireAdmin` that skips writing the response and just returns a boolean,
or (b) inline an `ADMINS.includes(user.email.toLowerCase())` check here
instead of calling `requireAdmin`. Pick whichever keeps `requireAdmin`'s
existing call sites unaffected — this is a decision for whoever implements
this endpoint, not fully resolved in this plan.

Frontend changes:
- `showWorkerDetailsById(workerId)` → `ccFetch("/worker/" + workerId)`, pass `result.data` to `showWorkerDetails(...)`.
- `openFacilityRatingModal(shiftId, workerId)` → `ccFetch("/worker/" + workerId)`, read `.data.full_name` / `.data.email` instead of the direct query.

### 6. `GET /applications/facility/pending` — batch pending applications with worker embed
Replaces: `dashboard-facility.js:196-231` (`loadApplications()`):

```js
const { data: applications } = await _supabase
  .from("applications")
  .select(`*, workers(id, full_name, role, city, experience, license_verified, identity_verified, profile_photo_url, bio)`)
  .in("shift_id", shiftIds)
  .eq("status", "pending")
  .order("created_at", { ascending: false });
```

The existing `/applications/shift/:shift_id` (server.js:2240) is
ownership-checked and does the same embedded join, but only for **one**
shift at a time — `loadApplications()` needs pending applications across
*all* of the facility's own open shifts in a single call. New endpoint:

```js
app.get("/applications/facility/pending", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { data: shifts } = await supabase
    .from("shifts")
    .select("id")
    .eq("contact_email", user.email.toLowerCase())
    .eq("status", "open");

  const shiftIds = (shifts || []).map(s => s.id);
  if (shiftIds.length === 0) return res.json({ success: true, data: [] });

  const { data, error } = await supabase
    .from("applications")
    .select(`*, workers(id, full_name, role, city, experience, license_verified, identity_verified, profile_photo_url, bio)`)
    .in("shift_id", shiftIds)
    .eq("status", "pending")
    .order("created_at", { ascending: false });

  if (error) return res.status(500).json({ success: false, message: "Failed to load applications." });
  return res.json({ success: true, data: data || [] });
});
```
Frontend change: `dashboard-facility.js` `loadApplications(email)` → drop the direct `shifts` + `applications` queries, call `ccFetch("/applications/facility/pending")` instead, keep the existing render logic (it already expects `app.workers` embedded, which this endpoint preserves).

### No new backend work needed — just a frontend call-site swap

**`dashboard-worker.js:611-615` (`loadMyApplications`)** already has an
exact backend match: `GET /applications/worker/:worker_id`
(server.js:2269-2296) is ownership-checked (`worker.email === user.email`)
and already returns `applications` with an embedded
`shifts(id, facility_name, role_needed, city, shift_date, start_time,
duration, pay_rate, status)` — a superset of the fields
`loadMyApplications()` currently selects directly. This is a pure
frontend change, zero backend work:

```js
// before
const { data, error } = await _supabase
  .from("applications")
  .select(`*, shifts(facility_name, role_needed, city, shift_date, start_time, pay_rate)`)
  .eq("worker_id", currentWorker.id)
  .order("created_at", { ascending: false });

// after
const { data: result } = await ccFetch(`/applications/worker/${currentWorker.id}`);
const data = result?.data;
```

---

## Frontend files that change

| File | Change |
|---|---|
| `admin.js` | `loadWorkers()`, `loadFacilities()`, `loadShifts()` → call new `/admin/workers`, `/admin/facilities`, `/admin/shifts` |
| `dashboard-facility.js` | `cancelShift()` → `/shift/facility-cancel`; `showWorkerDetailsById()` and `openFacilityRatingModal()` → `/worker/:id`; `loadApplications()` → `/applications/facility/pending` |
| `dashboard-worker.js` | `loadMyApplications()` → existing `/applications/worker/:worker_id` (no new backend needed) |

No changes needed in: `post-shift.js`, `settings.js`, `finance.js`,
`dashboard-client.js` (all already self-scoped and RLS-compatible), or
`dashboard-worker.js`'s `facility_branches` read at line 469 (intentionally
left as a direct authenticated read per the SQL file's own design).

---

## Before running any part of `sql-rls-lockdown.sql` in production

1. Implement and test endpoints #1-#6 above on this branch/backend.
2. Migrate the 6 frontend call sites listed above to use them.
3. Stand up a **staging Supabase project**, run the full SQL file there.
4. Manually exercise, in staging: admin dashboard (Workers/Facilities/Shifts
   tabs), facility dashboard (cancel shift, view worker detail, rate
   worker, view pending applications), worker dashboard (my applications,
   branch address display on assigned shifts). Watch the browser network
   tab for 401s or **silently empty/null responses** — the RLS failure mode
   observed in the audit doesn't throw, it just returns nothing, so this
   needs deliberate per-flow checking, not just "did the page load."
5. Only after a clean staging pass, run the SQL against production —
   `facilities` and `facility_branches` policies could technically go out
   independently of `workers`/`shifts` if you want to ship the safe half
   first, since the file's DROP/CREATE statements per table are independent
   and idempotent.

Rollback for any single table, if needed post-run (already noted at the
top of `sql-rls-lockdown.sql`):
```sql
ALTER TABLE <table> DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS <policy_name> ON <table>;
```

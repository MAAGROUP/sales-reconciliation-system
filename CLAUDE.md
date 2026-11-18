# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Django 5 app (single app: `salesapp`, project config in `config/`) for reconciling daily restaurant branch sales. It tracks money in OMR (3 decimal places; AED cash is converted using a per-entry exchange rate). The timezone is `Asia/Muscat`. The UI is server-rendered Django templates with no JS build step. Only dependencies: Django and openpyxl (used for the Excel export).

## Commands

```bash
venv\Scripts\activate                      # Windows venv (venv/ is gitignored)
pip install -r requirements.txt
python manage.py migrate
python manage.py create_admin <username> <password>   # bootstrap the first admin
python manage.py runserver                 # http://127.0.0.1:8000/login/

python manage.py test salesapp                                          # all tests
python manage.py test salesapp.tests.WaiterStatusTests                  # one class
python manage.py test salesapp.tests.WaiterStatusTests.test_other_days_do_not_count  # one test

python manage.py makemigrations salesapp   # after any model change
```

There is no linter or formatter configured.

## Configuration

`config/settings.py` reads these settings from environment variables, with dev defaults: `SECRET_KEY`, `DEBUG` (defaults to `'True'`), `ALLOWED_HOSTS`, `HTTPS_ENABLED`, and `DB_ENGINE`/`DB_NAME`/`DB_USER`/`DB_PASSWORD`/`DB_HOST`/`DB_PORT`. Without `DB_ENGINE` it uses local SQLite. Production uses PostgreSQL through these variables, so don't hard-code database settings. `VARIANCE_THRESHOLD` (5) is the difference that counts as a flagged discrepancy. The cache is LocMem and holds the login rate limiter.

## Architecture

Almost all logic is in two large files: `salesapp/models.py` (~600 lines) and `salesapp/views.py` (~3200 lines, function-based views plus many `_private` helpers). `salesapp/urls.py` maps them.

**Roles and access.** `UserProfile.role` is one of `waiter`, `collector`, `audit`, `manager`, `sales_manager` (both view-only), `admin`, or `it`. Every view is guarded by `@role_required(...)` in `decorators.py`. `admin` and `it` (`is_full_access`) always pass. The decorator also rejects any upload over 10 MB for the whole system. `entry_gate` at `/` sends non-waiters to their own role's page (`_redirect_for_role`). Waiters log in at `/login/` with a branch code + password (`branch_login_view`). Everyone else logs in at `/staff-login/`. Each waiter is locked to `profile.branch`.

**The shift lifecycle.** A `ShiftEntry` is one waiter submission for a branch/date/shift (cash denomination counts, visa rows, delivery sources, discounts, attachments). It moves through four stages (`ENTRY_STAGES` / `_entry_stage` in views.py):
1. `awaiting_sales`: Audit reviews the sales figures and sets `is_audited`.
2. `awaiting_collection`: the collector recounts the cash and creates a `CollectorHandover` (one-to-one, `entry.collector`).
3. `awaiting_cash_approval`: Audit reconciles the cash difference (`handover.reconciled`; a note is required if there is a difference).
4. `complete`.

When every shift `1..branch.shifts_per_day` for a day is approved, Audit closes the day with a `DayClose`, which stores the Foodics figure for the **whole day**. Day-level variance = the sum of `sales_actual` for the day's shifts − Foodics. Separately, a waiter can raise a request on an entry (`request_status`: pending/approved/rejected). Rejecting one requires an Audit `request_decision_note`.

**Totals are always computed on the server.** `ShiftEntry.save()` and `CollectorHandover.save()` call `recalculate()`. Never trust totals posted from the browser. Saving a `CollectorHandover` also re-saves its `ShiftEntry`, because once the collector has counted, their cash replaces the waiter's in `final_cash_total`. The waiter's original `cash_total` is kept for the diff. The cash-cancellation amount is informational and is not deducted. `sales_actual` (cash + visa, delivery excluded) is the figure compared against Foodics. When writing new money logic, use `Decimal` and the `_dec`/`_clean_number` helpers.

**Edit history.** On first save, both models capture an `original_snapshot`. Audit corrections are diffed against that snapshot (`_shift_field_diffs`, `_compute_handover_changes`) and displayed as "changed from X to Y". Any significant action should call `log_activity(request, action, description, details=...)`. The `action` must be one of `ActivityLog.ACTION_CHOICES`, and adding a new one requires a migration.

**Business date.** Branches have opening hours (`day_cutoff` → `day_end`), which may run past midnight. `Branch.business_date()` decides which date a submission belongs to. A submission made after closing goes to the next day and is flagged `submitted_late`. Use this method instead of `timezone.localdate()` whenever you need the date of a branch's report.

**Other modules:** `BankDeposit` (+ `BankDepositEvent`/`BankDepositFile`) is the collector's periodic bank deposit covering a date range of branch cash, with excluded branches and a return/approve flow. `WaiterResetLink` provides token-based password reset links for waiters. The daily sales report is available as HTML and as an Excel export (openpyxl). Uploaded files go to `media/` (gitignored).

**Templates.** These are in `salesapp/templates/salesapp/`. Files starting with `_` are partials included by multiple pages, e.g. the shared branch picker, stage filter, and cash/notes cards. Custom filters are in `templatetags/app_filters.py`. The UI text is English. Number inputs accept Arabic/Eastern digits, which views normalize.

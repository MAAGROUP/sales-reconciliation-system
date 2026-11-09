import datetime
from decimal import Decimal
from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from .constants import DENOMS, AED_DENOMS, DELIVERY_SOURCES, SHIFT_CHOICES


def _fmt12(t):
    """A time of day the way people say it: 10:00 AM, 3:30 PM, 12:00 AM."""
    return f'{t.hour % 12 or 12}:{t.minute:02d} {"AM" if t.hour < 12 else "PM"}'


class Branch(models.Model):
    name = models.CharField(max_length=120, unique=True)
    code = models.CharField(max_length=20, unique=True, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    # The branch's business day STARTS at day_cutoff and ENDS at day_end (which may
    # fall on the next calendar day, e.g. 10:00 -> 03:00). day_end left empty means
    # "automatic": one minute before the start, i.e. a full 24-hour day.
    day_cutoff = models.TimeField(default=datetime.time(0, 0))
    day_end = models.TimeField(null=True, blank=True)
    # How many shifts the branch runs per day. The day can be closed (Foodics for the
    # whole day) once shifts 1..N have all been submitted and approved by Audit.
    shifts_per_day = models.PositiveSmallIntegerField(default=3)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    @property
    def auto_end(self):
        return (datetime.datetime.combine(datetime.date(2000, 1, 1), self.day_cutoff) - datetime.timedelta(minutes=1)).time()

    @property
    def effective_end(self):
        return self.day_end if self.day_end is not None else self.auto_end

    @property
    def open_label(self):
        return _fmt12(self.day_cutoff)

    @property
    def close_label(self):
        return _fmt12(self.effective_end)

    @property
    def closes_next_day(self):
        return self.effective_end < self.day_cutoff

    @property
    def has_custom_hours(self):
        """False for a branch nobody has set up (the default 12:00 AM → 11:59 PM)."""
        return not (self.day_cutoff == datetime.time(0, 0) and self.effective_end == datetime.time(23, 59))

    @property
    def day_window(self):
        """'10:00 AM → 3:00 AM (next day)' — the branch's opening hours."""
        return f'{self.open_label} → {self.close_label}' + (' (next day)' if self.closes_next_day else '')

    def business_date(self, now=None):
        """The date a report submitted `now` gets.
        - While the shop is OPEN: the day that is running (a report at 1 AM, after midnight,
          still belongs to the day that opened the morning before).
        - While the shop is CLOSED (after closing, before it opens again): the NEXT day, the one
          that is about to open. Such a report is a late submission (see submitted_late)."""
        from django.utils import timezone
        local = timezone.localtime(now or timezone.now())
        day = local.date()
        t = datetime.time(local.hour, local.minute)
        start, end = self.day_cutoff, self.effective_end
        if self.in_business_hours(now):
            if start <= end:
                return day                                     # a same-day window: the day it is
            return day if t >= start else day - datetime.timedelta(days=1)
        if start <= end:                                       # closed, same-day window
            return day + datetime.timedelta(days=1) if t > end else day
        return day                                             # closed, window that runs past midnight: the gap is before today's opening

    def in_business_hours(self, now=None):
        """True while `now` is between the day's start and end (to the minute)."""
        from django.utils import timezone
        local = timezone.localtime(now or timezone.now())
        t = datetime.time(local.hour, local.minute)
        start, end = self.day_cutoff, self.effective_end
        return (start <= t <= end) if start <= end else (t >= start or t <= end)


class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('waiter', 'Waiter / Branch Accountant'),
        ('collector', 'Collector'),
        ('audit', 'Audit'),
        ('manager', 'Manager (View Only)'),
        ('sales_manager', 'Sales Department Manager (View Only)'),
        ('admin', 'Admin'),
        ('it', 'IT (Full Access)'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    # Only meaningful for the 'waiter' role — locks their entry form to one branch.
    branch = models.ForeignKey(Branch, on_delete=models.SET_NULL, null=True, blank=True, related_name='staff')
    # Only meaningful for the 'waiter' role — the head cashier's name at that branch.
    head_cashier_name = models.CharField(max_length=200, blank=True)
    # Only meaningful for the 'waiter' role — their fingerprint/attendance (punch) ID.
    punch_id = models.CharField(max_length=50, blank=True)
    # Set when a waiter registered themselves through the public link and is
    # still waiting for an admin to approve (activate) the account.
    pending_approval = models.BooleanField(default=False)

    @property
    def is_full_access(self):
        """Admin and IT both get unrestricted access to every page."""
        return self.role in ('admin', 'it')

    def __str__(self):
        return f'{self.user.username} ({self.get_role_display()})'


def _cash_total_from_counts(cash_counts: dict) -> Decimal:
    total = Decimal('0')
    for denom in DENOMS:
        count = Decimal(str(cash_counts.get(denom, 0) or 0))
        total += count * Decimal(denom)
    return total


def _aed_cash_total_from_counts(cash_counts_aed: dict) -> Decimal:
    total = Decimal('0')
    for denom in AED_DENOMS:
        count = Decimal(str(cash_counts_aed.get(denom, 0) or 0))
        total += count * Decimal(denom)
    return total


def _delivery_total_from_data(delivery_data: dict) -> Decimal:
    total = Decimal('0')
    for key, _label in DELIVERY_SOURCES:
        source = delivery_data.get(key, {}) or {}
        total += Decimal(str(source.get('amount', 0) or 0))
    return total


def _delivery_cancel_total_from_data(delivery_data: dict) -> Decimal:
    total = Decimal('0')
    for key, _label in DELIVERY_SOURCES:
        source = delivery_data.get(key, {}) or {}
        total += Decimal(str(source.get('cancel_amount', 0) or 0))
    return total


def _visa_total_from_entries(visa_entries: list) -> Decimal:
    total = Decimal('0')
    for row in visa_entries or []:
        total += Decimal(str(row.get('amount', 0) or 0))
    return total


class ShiftEntry(models.Model):
    """One waiter/branch-accountant submission for a single shift."""

    branch = models.ForeignKey(Branch, on_delete=models.PROTECT, related_name='shift_entries')
    date = models.DateField()
    shift = models.CharField(max_length=1, choices=SHIFT_CHOICES)
    accountant = models.CharField(max_length=200, blank=True)
    # Punch ID of the waiter who submitted this report, saved with it so it stays right
    # even if the waiter's profile changes later.
    submitted_punch = models.CharField(max_length=50, blank=True, default='')
    # True when the waiter submitted while the branch was closed (after closing, before opening) and
    # confirmed it counts as the next day. Shown as 'Late submission' on every dashboard.
    submitted_late = models.BooleanField(default=False)

    # e.g. "AKL-0001" — sequential per branch, so numbering differs branch to branch.
    reference_id = models.CharField(max_length=40, unique=True, blank=True)

    staff_discount = models.DecimalField(max_digits=10, decimal_places=3, default=0)
    # [{"order_no": "123", "amount": "1.500"}, ...] — each discount with its order number. staff_discount is their total.
    discount_entries = models.JSONField(default=list, blank=True)
    staff_discount_attachment = models.FileField(upload_to='discount_attachments/%Y/%m/', blank=True, null=True)
    petty_cash = models.DecimalField(max_digits=10, decimal_places=3, default=0)

    # {"0.05": 4, "0.1": 5, ...} — OMR cash counted.
    cash_counts = models.JSONField(default=dict, blank=True)
    # {"5": 2, "10": 1, ...} — AED cash counted (converted into cash_total using aed_exchange_rate).
    cash_counts_aed = models.JSONField(default=dict, blank=True)
    aed_exchange_rate = models.DecimalField(max_digits=6, decimal_places=4, default=Decimal('0.1000'))
    # Combined OMR total — OMR cash counted + (AED cash counted × aed_exchange_rate).
    cash_total = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    # A cancelled/refunded cash transaction — deducted directly from the final total.
    cash_cancel_order = models.CharField(max_length=200, blank=True, default='')   # order number(s) of the cancelled cash order
    cash_cancel_amount = models.DecimalField(max_digits=10, decimal_places=3, default=0)
    cash_cancel_attachment = models.FileField(upload_to='cancel_attachments/%Y/%m/', blank=True, null=True)

    # [{"serial": "10026512", "amount": 66.4}, ...] — per-machine receipt files live in VisaMachineFile.
    visa_entries = models.JSONField(default=list, blank=True)
    visa_total = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    # {"talabat": {"orders": 60, "amount": 239.52, "cancel_orders": 0, "cancel_amount": 0}, ...}
    delivery_data = models.JSONField(default=dict, blank=True)
    delivery_total = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    # One attachment per delivery source (fixed set, so plain fields rather than a related model).
    delivery_attachment_talabat = models.FileField(upload_to='delivery_attachments/%Y/%m/', blank=True, null=True)
    delivery_attachment_tmdone = models.FileField(upload_to='delivery_attachments/%Y/%m/', blank=True, null=True)
    delivery_attachment_callcenter = models.FileField(upload_to='delivery_attachments/%Y/%m/', blank=True, null=True)

    actual_total = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    expected_foodics = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    variance = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    notes = models.TextField(blank=True)
    notes_attachment = models.FileField(upload_to='notes_attachments/%Y/%m/', blank=True, null=True)
    audit_notes = models.TextField(blank=True)
    is_audited = models.BooleanField(default=False)
    # The collector's own sign-off on the shift (separate from Audit's review): he checks the
    # shift and approves it, one by one or all of the day's shifts at once, with an optional note.
    collector_approved = models.BooleanField(default=False)
    collector_approved_at = models.DateTimeField(null=True, blank=True)
    collector_approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    collector_note = models.TextField(blank=True)
    is_archived = models.BooleanField(default=False)
    # A shift the waiter sent for a day that is already closed (or a shift that was already
    # submitted). It is kept archived (so it counts nowhere) until Audit approves or rejects it.
    request_status = models.CharField(max_length=10, blank=True, default='')   # '' | pending | approved | rejected
    request_reason = models.CharField(max_length=120, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    # Snapshot of the numbers exactly as the waiter submitted them — captured
    # once, on the first save. Later saves (Audit's corrections) never touch
    # this, so the Sales Review card can show "changed from X to Y" against it.
    original_snapshot = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-created_at']

    def delivery_attachment_field(self, key):
        return getattr(self, f'delivery_attachment_{key}', None)

    def recalculate(self):
        """Server-side auto-calculation — never trust client-side totals.
        Cash and delivery totals are stored net of their own cancellations
        (visa has none). actual_total is the full shift figure after the
        discount; the audit's Daily Sales comparison uses sales_actual
        (below), which leaves delivery out."""
        omr_cash = _cash_total_from_counts(self.cash_counts)
        aed_cash = _aed_cash_total_from_counts(self.cash_counts_aed)
        rate = Decimal(str(self.aed_exchange_rate or 0))
        gross_cash = omr_cash + (aed_cash * rate)
        # The cash cancellation is information only: it is NOT deducted from the cash.
        self.cash_total = gross_cash

        if self.discount_entries:
            self.staff_discount = sum((Decimal(str(r.get('amount') or 0)) for r in self.discount_entries), Decimal('0'))

        self.visa_total = _visa_total_from_entries(self.visa_entries)

        gross_delivery = _delivery_total_from_data(self.delivery_data)
        self.delivery_total = gross_delivery - _delivery_cancel_total_from_data(self.delivery_data)

        # Once the collector has counted the cash, HIS figure is the final cash
        # (waiter's own cash_total is kept untouched for the reconciliation diff).
        actual_before_discount = self.final_cash_total + self.visa_total + self.delivery_total
        self.actual_total = actual_before_discount - Decimal(str(self.staff_discount or 0))
        # Daily Sales variance: what the branch sold (cash + visa) vs Foodics.
        self.variance = self.sales_actual - Decimal(str(self.expected_foodics or 0))

    @property
    def delivery_cancel_amount(self):
        """Sum of every delivery source's cancel_amount — kept for templates that
        already read this name (it used to be a stored field, one total shared
        across sources; now each source carries its own cancel figure)."""
        return _delivery_cancel_total_from_data(self.delivery_data)

    @property
    def cash_with_cancel(self):
        """Cash minus the cancelled order — shown for information only, never used in a total."""
        return self.cash_total - Decimal(str(self.cash_cancel_amount or 0))

    @property
    def collector_record(self):
        if not self.pk:
            return None
        try:
            return self.collector
        except Exception:
            return None

    @property
    def final_cash_total(self):
        """Cash after cancellations: the collector's count once he has saved it
        (including any later Audit correction), otherwise the waiter's count."""
        h = self.collector_record
        return h.cash_total if h is not None else self.cash_total

    @property
    def cash_from_collector(self):
        return self.collector_record is not None

    @property
    def sales_actual(self):
        """Cash + visa with delivery left out — the figure Audit compares against
        Foodics in the Daily Sales review. Cancellations and the discount are
        shown for confirmation only: they do NOT change it, so the cash here is
        the cash counted BEFORE the cancelled amount is taken off."""
        return self.final_cash_total + self.visa_total

    @property
    def actual_with_discount(self):
        """Actual (cash + visa) minus the discount — shown for confirmation only."""
        return self.sales_actual - Decimal(str(self.staff_discount or 0))

    @property
    def discount_rows(self):
        """The discounts to show on a form or report: the saved rows, or — for an
        entry saved before order numbers existed — its single total as one row."""
        if self.discount_entries:
            return [{'order_no': r.get('order_no', ''), 'amount': str(r.get('amount', '0'))} for r in self.discount_entries]
        if self.staff_discount:
            return [{'order_no': '', 'amount': str(self.staff_discount)}]
        return []

    def save(self, *args, **kwargs):
        self.recalculate()
        if not self.pk and not self.original_snapshot:
            self.original_snapshot = {
                'cash_counts': dict(self.cash_counts),
                'cash_counts_aed': dict(self.cash_counts_aed),
                'aed_exchange_rate': str(self.aed_exchange_rate),
                'visa_entries': list(self.visa_entries),
                'delivery_data': dict(self.delivery_data),
                'staff_discount': str(self.staff_discount),
                'discount_entries': list(self.discount_entries or []),
                'cash_cancel_amount': str(self.cash_cancel_amount),
                'petty_cash': str(self.petty_cash),
            }
        if not self.reference_id:
            prefix = self.branch.code or f'BR{self.branch.id}'
            existing_count = ShiftEntry.objects.filter(branch=self.branch).count()
            self.reference_id = f'{prefix}-{existing_count + 1:04d}'
        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.branch} / {self.date} / Shift {self.shift}'


class VisaMachineFile(models.Model):
    """A receipt/photo attached to one specific visa machine row on an entry."""
    entry = models.ForeignKey(ShiftEntry, on_delete=models.CASCADE, related_name='visa_files')
    serial = models.CharField(max_length=100, blank=True)
    file = models.FileField(upload_to='visa_attachments/%Y/%m/')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Visa file for {self.serial or "unknown machine"} ({self.entry})'


class NotesFile(models.Model):
    """One of the 'Close Till Foodics' photos / PDFs the waiter uploads with a shift."""
    entry = models.ForeignKey(ShiftEntry, on_delete=models.CASCADE, related_name='notes_files')
    file = models.FileField(upload_to='notes_attachments/%Y/%m/')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Close Till Foodics file ({self.entry})'


class CollectorHandover(models.Model):
    """The collector's independent CASH recount for a shift entry. Visa and
    delivery money never passes through the collector, so only cash is
    counted and compared (against the waiter's cash, net of cancellations)."""

    shift_entry = models.OneToOneField(ShiftEntry, on_delete=models.CASCADE, related_name='collector')
    collector_name = models.CharField(max_length=200, blank=True)

    cash_counts = models.JSONField(default=dict, blank=True)
    cash_counts_aed = models.JSONField(default=dict, blank=True)
    cash_total = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    # cash_total - shift_entry.cash_total  → the Cash Reconciliation difference
    diff_from_waiter = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    # Stage 2 of the audit: Audit confirms the cash matched (or explained the difference).
    reconciled = models.BooleanField(default=False)
    reconciled_at = models.DateTimeField(null=True, blank=True)
    reconciled_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    reconcile_note = models.TextField(blank=True)  # required when the shift is approved with a difference

    # Photo of the cash receipt / handover invoice, uploaded by the collector with the count.
    proof_attachment = models.FileField(upload_to='cash_proofs/%Y/%m/', blank=True, null=True)

    notes = models.TextField(blank=True)
    recounted_at = models.DateTimeField(auto_now=True)

    # Snapshot of the collector's own first count — captured once, so a later
    # correction by Audit can be shown as "changed from X to Y" against it.
    original_snapshot = models.JSONField(default=dict, blank=True)

    def recalculate(self):
        omr = _cash_total_from_counts(self.cash_counts)
        aed = _aed_cash_total_from_counts(self.cash_counts_aed)
        rate = Decimal(str(self.shift_entry.aed_exchange_rate or 0))
        self.cash_total = omr + (aed * rate)
        self.diff_from_waiter = self.cash_total - self.shift_entry.cash_total

    def save(self, *args, **kwargs):
        self.recalculate()
        if not self.pk and not self.original_snapshot:
            self.original_snapshot = {
                'cash_counts': dict(self.cash_counts),
                'cash_counts_aed': dict(self.cash_counts_aed),
            }
        super().save(*args, **kwargs)
        # Keep the shift's final totals / variance in step with the collector's count.
        entry = self.shift_entry
        entry.__dict__.pop('collector', None)
        entry._state.fields_cache.pop('collector', None)
        entry.save()

    def has_difference(self, threshold):
        return abs(self.diff_from_waiter) > threshold

    def __str__(self):
        return f'Handover for {self.shift_entry}'


class BankDeposit(models.Model):
    """The collector's weekly bank deposit of the branches' cash: the period it covers, the amount
    paid in, and the bank receipt(s). Audit approves it; until then the collector can still edit it."""

    date_from = models.DateField()
    date_to = models.DateField()
    deposit_date = models.DateField()
    amount = models.DecimalField(max_digits=12, decimal_places=3)
    note = models.TextField(blank=True)

    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    approved = models.BooleanField(default=False)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    approved_at = models.DateTimeField(null=True, blank=True)
    audit_note = models.TextField(blank=True)
    # True while Audit has sent it back and the collector has not saved a correction yet.
    returned = models.BooleanField(default=False)
    # Branches that are NOT part of this deposit (the collector un-ticked them). Empty = every
    # branch, which is also how deposits saved before this existed are read.
    excluded_branches = models.ManyToManyField('Branch', blank=True, related_name='+')

    class Meta:
        ordering = ['-date_to', '-id']

    def __str__(self):
        return f'Bank deposit {self.date_from} → {self.date_to}'


class BankDepositEvent(models.Model):
    """One line of a deposit's history: created, edited (with what changed), approved or sent back."""
    deposit = models.ForeignKey(BankDeposit, on_delete=models.CASCADE, related_name='events')
    kind = models.CharField(max_length=20)          # created / edited / approved / returned
    username = models.CharField(max_length=150, blank=True)
    note = models.TextField(blank=True)
    details = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at', 'id']

    def __str__(self):
        return f'{self.kind} - {self.deposit}'


class BankDepositFile(models.Model):
    """One receipt (photo or PDF) of a bank deposit."""
    deposit = models.ForeignKey(BankDeposit, on_delete=models.CASCADE, related_name='files')
    file = models.FileField(upload_to='bank_deposits/%Y/%m/')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Receipt for {self.deposit}'


class DayClose(models.Model):
    """Foodics is reported once per business day, not per shift. When every shift of the
    day has been submitted and approved, Audit enters the day's Foodics figure here and
    closes the day. Variance = the day's Sales Actual (all its shifts) - Foodics."""

    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, related_name='day_closes')
    date = models.DateField()
    expected_foodics = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    note = models.TextField(blank=True)
    closed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    closed_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [('branch', 'date')]
        ordering = ['-date', 'branch__name']

    def shift_entries(self):
        return ShiftEntry.objects.filter(branch=self.branch, date=self.date, is_archived=False).order_by('shift')

    @property
    def sales_actual(self):
        return sum((e.sales_actual for e in self.shift_entries()), Decimal('0'))

    @property
    def variance(self):
        return self.sales_actual - Decimal(str(self.expected_foodics or 0))

    @property
    def label(self):
        return f'{self.branch.name} {self.date}'

    def __str__(self):
        return f'Day close {self.label}'


class ActivityLog(models.Model):
    """A simple audit trail of who did what, for accountability. Deliberately
    keeps a text snapshot of the username, so the log entry still makes
    sense even after that account is deleted."""

    ACTION_CHOICES = [
        ('login_success', 'Login Success'),
        ('login_failed', 'Login Failed'),
        ('logout', 'Logout'),
        ('user_created', 'User Created'),
        ('user_edited', 'User Edited'),
        ('user_deleted', 'User Deleted'),
        ('user_activated', 'User Activated'),
        ('user_deactivated', 'User Deactivated'),
        ('account_unlocked', 'Account Unlocked'),
        ('password_link_created', 'Password Link Created'),
        ('password_reset_done', 'Password Reset Done'),
        ('branch_created', 'Branch Created'),
        ('branch_edited', 'Branch Edited'),
        ('branch_deleted', 'Branch Deleted'),
        ('branch_activated', 'Branch Activated'),
        ('branch_deactivated', 'Branch Deactivated'),
        ('entry_edited', 'Shift Entry Edited'),
        ('entry_archived', 'Shift Entry Archived'),
        ('entry_unarchived', 'Shift Entry Unarchived'),
        ('handover_saved', 'Cash Collected'),
        ('entry_audited', 'Daily Sales Reviewed'),
        ('collector_approved', 'Collector Approved'),
        ('day_closed', 'Day Closed'),
        ('cash_reconciled', 'Cash Reconciled'),
        ('bank_deposit_saved', 'Bank Deposit Saved'),
        ('bank_deposit_deleted', 'Bank Deposit Deleted'),
        ('bank_deposit_approved', 'Bank Deposit Approved'),
        ('bank_deposit_reopened', 'Bank Deposit Reopened'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='activity_logs')
    username_snapshot = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    description = models.CharField(max_length=255, blank=True)
    # A short summary of what actually changed in this action (fields
    # corrected, the note written) — shown in the Audit History table.
    details = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.username_snapshot or "unknown"} - {self.get_action_display()} - {self.created_at}'

    @property
    def clean_details(self):
        """`details` for display. Rows saved earlier start with 'Edited by <user>:'
        / 'Corrected by <user>:' (or 'Recorded by <user>: …'); the Who column
        already names the person, so that repeat is dropped here."""
        import re
        text = self.details or ''
        text = re.sub(r'^(?:Edited|Corrected) by [^\n]*?:\s*\n', '', text)
        text = re.sub(r'^Recorded by [^\n:]*?: ', 'Recorded: ', text)
        return text


class WaiterResetLink(models.Model):
    """A one-time link Audit hands to a waiter who forgot the password. Only a hash of the token
    is stored; the link works once, for a limited time, and a newer link replaces the older one."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reset_links')
    token_hash = models.CharField(max_length=64, unique=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f'Reset link for {self.user.username}'

"""Tests for the Audit flow and the branch calendar on the Audit page.

Run with:  python manage.py test salesapp
"""
import datetime

from django.contrib.auth.models import User
from django.test import TestCase

from .models import Branch, CollectorHandover, DayClose, ShiftEntry, UserProfile

ROLES = ('waiter', 'collector', 'audit', 'manager', 'sales_manager', 'admin', 'it')


class AuditFlowTestCase(TestCase):
    """A branch with two shifts per day, yesterday's two shifts submitted (50 RO and 20 RO cash),
    and one user per role."""

    def setUp(self):
        self.branch = Branch.objects.create(name='Test Branch', code='TST', shifts_per_day=2)
        self.today = self.branch.business_date()
        self.day = self.today - datetime.timedelta(days=1)
        self.e1 = ShiftEntry.objects.create(branch=self.branch, date=self.day, shift='1', cash_counts={'10': 5})
        self.e2 = ShiftEntry.objects.create(branch=self.branch, date=self.day, shift='2', cash_counts={'10': 2})
        self.users = {}
        for role in ROLES:
            user = User.objects.create_user(role, password='pw-12345-test')
            UserProfile.objects.create(user=user, role=role, branch=self.branch if role == 'waiter' else None)
            self.users[role] = user

    def login(self, role):
        self.client.force_login(self.users[role])

    def calendar(self, day=None):
        """The branch calendar opened on `day` (default: yesterday)."""
        day = day or self.day
        return self.client.get(f'/dashboard/calendar/?branch={self.branch.id}&month={day:%Y-%m}&day={day.isoformat()}')

    def cell(self, day=None):
        day = day or self.day
        return next(d for d in self.calendar(day).context['days'] if d['date'] == day)

    def stages(self, day=None):
        """{stage key: count} shown on the day's calendar square."""
        return {key: count for key, _label, count in self.cell(day)['chips']}

    def panel(self):
        return self.calendar().context['panel']

    # The steps of a day, as Audit / the collector do them from the calendar.
    def approve_shifts(self):
        return self.client.post('/dashboard/', {'action': 'approve_all', 'entry_id': self.e1.id,
                                                'next': self.panel()['next_foodics']})

    def close_day(self, foodics='70'):
        return self.client.post('/dashboard/', {'action': 'close_day', 'entry_id': self.e1.id,
                                                'day_foodics': foodics, 'next': self.panel()['next_foodics']})

    def collector_counts(self, counts=None):
        """The collector saves their own count for every shift (by default the waiter's count)."""
        for entry, default in ((self.e1, {'10': 5}), (self.e2, {'10': 2})):
            data = {'shift_entry_id': entry.id}
            data.update({f'cdenom_{k}': v for k, v in (counts or {}).get(entry.shift, default).items()})
            self.client.post('/collector/', data)

    def approve_cash(self):
        cash = self.panel()['cash']
        return self.client.post('/cash-reconciliation/action/', {'action': 'approve_matched',
                                                                 'handover_id': cash['ready_ids'],
                                                                 'next': self.panel()['next']})


class CalendarStageTests(AuditFlowTestCase):
    def test_full_day_moves_through_every_stage(self):
        self.login('admin')
        self.assertEqual(self.stages(), {'awaiting_sales': 2})

        self.approve_shifts()
        self.assertEqual(self.stages(), {'awaiting_sales': 2}, 'stays in Sales Review until the day is closed')

        self.close_day()
        self.assertEqual(self.stages(), {'awaiting_collection': 2})

        self.collector_counts()
        self.assertEqual(self.stages(), {'awaiting_cash_approval': 2})

        self.approve_cash()
        self.assertEqual(self.stages(), {'complete': 2})
        self.assertEqual(self.cell()['tone'], 'done')

    def test_missing_counts_from_the_start_date_only(self):
        self.login('audit')
        before = self.day - datetime.timedelta(days=1)
        self.assertNotIn('missing', self.stages(before), 'before the first report nothing is Missing')

        self.branch.start_date = before
        self.branch.save()
        self.assertEqual(self.stages(before).get('missing'), 2)

    def test_today_is_never_missing(self):
        self.login('audit')
        cell = self.cell(self.today)
        self.assertNotIn('missing', dict((k, c) for k, _l, c in cell['chips']))
        self.assertEqual(cell['waiting_today'], 2)

    def test_variance_flag_after_close(self):
        self.login('audit')
        self.approve_shifts()
        self.close_day(foodics='60')          # sales actual 70 - 60 = 10 > 5
        self.assertTrue(self.cell()['flagged'])
        self.assertEqual(self.panel()['variance'], 10)


class CalendarReturnTests(AuditFlowTestCase):
    """Every card sends the user back to the same branch + day on the Audit page."""

    def test_cards_return_to_the_same_day(self):
        self.login('admin')
        foodics_url = self.panel()['next_foodics']
        self.assertIn(f'cal_branch={self.branch.id}', foodics_url)
        self.assertIn('cal_focus=foodics', foodics_url)
        self.assertEqual(self.approve_shifts().url, foodics_url)
        self.assertEqual(self.close_day().url, foodics_url)
        self.collector_counts()
        self.assertEqual(self.approve_cash().url, self.panel()['next'])

    def test_audit_page_without_next_keeps_its_own_return(self):
        self.login('audit')
        response = self.client.post('/dashboard/', {'action': 'approve_all', 'entry_id': self.e1.id})
        self.assertTrue(response.url.startswith('/dashboard/?'))
        self.assertTrue(response.url.endswith('#dayCloseCard'))


class ShiftPageReturnTests(AuditFlowTestCase):
    """On a shift's page in the Audit page, every save comes back to the card it was done on."""

    def test_sales_review_returns_to_its_card(self):
        self.login('audit')
        response = self.client.post(f'/dashboard/?entry_id={self.e1.id}', {'entry_id': self.e1.id})
        self.assertTrue(response.url.endswith('#stepSalesReviewed'), response.url)
        self.assertTrue(ShiftEntry.objects.get(pk=self.e1.pk).is_audited)

    def test_collector_count_correction_returns_to_its_card(self):
        self.login('collector')
        self.collector_counts()
        self.login('audit')
        page = f'/dashboard/?entry_id={self.e1.id}'
        self.assertContains(self.client.get(page), f'value="{page}#collectorCountCard"')
        response = self.client.post('/collector/', {'shift_entry_id': self.e1.id, 'cdenom_10': 4,
                                                    'next': f'{page}#collectorCountCard'})
        self.assertEqual(response.url, f'{page}#collectorCountCard')
        self.assertEqual(ShiftEntry.objects.get(pk=self.e1.pk).final_cash_total, 40)

    def test_waiter_request_decision_returns_to_its_card(self):
        DayClose.objects.create(branch=self.branch, date=self.day, expected_foodics=70)
        request = ShiftEntry.objects.create(branch=self.branch, date=self.day, shift='2', is_archived=True,
                                            request_status='pending', request_reason='Day already closed')
        self.login('audit')
        rejected = self.client.post('/dashboard/', {'action': 'request_decision', 'entry_id': request.id,
                                                    'decision': 'reject', 'reject_note': 'Duplicate'})
        self.assertTrue(rejected.url.endswith('#requestCard'))
        self.assertContains(self.client.get(f'/dashboard/?entry_id={request.id}'), 'id="requestCard"')

        request.request_status = 'pending'
        request.save()
        approved = self.client.post('/dashboard/', {'action': 'request_decision', 'entry_id': request.id,
                                                    'decision': 'approve'})
        self.assertTrue(approved.url.endswith('#stepSalesReviewed'), 'approved: the shift now waits for its review')


class CashCardTests(AuditFlowTestCase):
    def test_locked_until_the_collector_has_every_shift(self):
        self.login('audit')
        CollectorHandover.objects.create(shift_entry=ShiftEntry.objects.get(pk=self.e1.pk), cash_counts={'10': 5})
        cash = self.panel()['cash']
        self.assertFalse(cash['open'])
        self.assertEqual(cash['collected'], 1)

        CollectorHandover.objects.create(shift_entry=ShiftEntry.objects.get(pk=self.e2.pk), cash_counts={'10': 1})
        cash = self.panel()['cash']
        self.assertTrue(cash['open'])
        self.assertEqual(cash['diff_total'], -10)
        self.assertEqual(cash['counts']['ready'], 1)          # shift 2 has a difference: opened on its own
        self.assertEqual(cash['ready_total'], 50)             # what the confirm popup lists

    def test_cash_counts_by_the_collector(self):
        self.login('collector')
        self.collector_counts({'1': {'10': 4}, '2': {'10': 2}})
        entry = ShiftEntry.objects.get(pk=self.e1.pk)
        self.assertEqual(entry.cash_total, 50)            # the waiter's count is kept for the difference
        self.assertEqual(entry.final_cash_total, 40)      # the collector's count is the cash used

    def test_audit_cannot_count_before_the_collector(self):
        self.login('audit')
        self.collector_counts()
        self.assertFalse(CollectorHandover.objects.exists())


class ApprovalStaysTests(AuditFlowTestCase):
    """An approved sales review must not go back to Sales Review when the collector works."""

    def test_collector_count_keeps_the_approval(self):
        self.login('audit')
        self.approve_shifts()
        self.login('collector')
        self.collector_counts({'1': {'10': 4}, '2': {'10': 2}})
        self.assertTrue(all(e.is_audited for e in ShiftEntry.objects.all()))

    def test_collector_approve_handover_keeps_the_approval(self):
        self.login('audit')
        self.approve_shifts()
        self.login('collector')
        self.client.post('/collector/', {'action': 'collector_approve_all', 'shift_entry_id': self.e1.id})
        self.assertEqual(CollectorHandover.objects.count(), 2)
        self.assertTrue(all(e.is_audited for e in ShiftEntry.objects.all()))


class AccessTests(AuditFlowTestCase):
    def test_calendar_roles(self):
        for role in ROLES:
            self.login(role)
            expected = 200 if role in ('audit', 'manager', 'admin', 'it') else 403
            self.assertEqual(self.calendar().status_code, expected, role)

    def test_manager_only_looks(self):
        self.login('manager')
        self.assertNotContains(self.calendar(), '<form')

    def test_main_pages_open(self):
        DayClose.objects.create(branch=self.branch, date=self.day, expected_foodics=70)
        pages = {
            'admin': ['/dashboard/', f'/dashboard/?entry_id={self.e1.id}', '/collector/', f'/collector/?entry_id={self.e1.id}',
                      '/bank-deposits/', '/reports/daily-sales/', '/reports/daily-sales/excel/', '/history/',
                      '/audit-log/', '/users/', '/branches/', f'/branches/{self.branch.id}/edit/', '/settings/cutoff/', '/'],
            'audit': ['/dashboard/', '/settings/waiters/'],
            'manager': ['/dashboard/'],
            'collector': ['/collector/', '/bank-deposits/'],
            'sales_manager': ['/collector/', '/reports/daily-sales/'],
            'waiter': ['/', '/my-history/'],
        }
        for role, urls in pages.items():
            self.login(role)
            for url in urls:
                self.assertEqual(self.client.get(url).status_code, 200, f'{role} {url}')

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import Branch, ShiftEntry, UserProfile


class WaiterStatusTests(TestCase):
    """The Waiter status block on the entry page reflects saved submissions."""

    def setUp(self):
        self.branch = Branch.objects.create(name='Test Branch', code='TST')
        user = User.objects.create_user('waiter1', password='pw-12345-test')
        UserProfile.objects.create(user=user, role='waiter', branch=self.branch)
        self.client.force_login(user)

    def test_not_submitted_before_any_save(self):
        response = self.client.get(reverse('entry'))
        self.assertEqual(response.context['submitted_shifts'], [])
        self.assertContains(response, 'id="waiterStatus"')

    def test_submitted_after_successful_save(self):
        response = self.client.post(reverse('entry'), {'shift': '1'})
        entry = ShiftEntry.objects.get()
        self.assertRedirects(response, f'/?submitted={entry.reference_id}')

        confirmation = self.client.get(response.url)
        self.assertTrue(confirmation.context['submitted_saved'])
        self.assertContains(confirmation, 'stage-status done')

        form = self.client.get(reverse('entry'))
        self.assertEqual(form.context['submitted_shifts'], ['1'])

    def test_other_days_do_not_count(self):
        yesterday = timezone.localdate() - timezone.timedelta(days=1)
        ShiftEntry.objects.create(branch=self.branch, date=yesterday, shift='1')
        response = self.client.get(reverse('entry'))
        self.assertEqual(response.context['submitted_shifts'], [])

    def test_unknown_reference_is_not_green(self):
        response = self.client.get('/?submitted=FAKE-0001')
        self.assertFalse(response.context['submitted_saved'])
        self.assertNotContains(response, 'stage-status done')

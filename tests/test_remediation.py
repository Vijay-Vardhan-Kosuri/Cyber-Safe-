from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model
from apps.organizations.models import Organization, Membership, RoleChoices
from apps.remediation.models import RemediationTask, TaskStatus, TaskPriority

User = get_user_model()

class RemediationWorkflowTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.org = Organization.objects.create(name='Remediation Org', slug='remed-org')

        self.analyst = User.objects.create_user(email='analyst@remed.com', username='analyst@remed.com', password='Pass123!')
        Membership.objects.create(user=self.analyst, organization=self.org, role=RoleChoices.SECURITY_ANALYST)

        self.employee = User.objects.create_user(email='emp@remed.com', username='emp@remed.com', password='Pass123!')
        Membership.objects.create(user=self.employee, organization=self.org, role=RoleChoices.EMPLOYEE)

        self.task = RemediationTask.objects.create(
            organization=self.org,
            title='Configure Hardened SSH',
            description='Disable password login and root access.',
            assigned_to=self.employee,
            reviewer=self.analyst,
            priority=TaskPriority.HIGH,
            due_date=timezone.now().date() + timezone.timedelta(days=7),
            status=TaskStatus.OPEN
        )

    def test_remediation_lifecycle_workflow(self):
        # 1. Employee starts task
        self.client.force_login(self.employee)
        session = self.client.session
        session['active_organization_id'] = self.org.id
        session.save()

        res = self.client.post(reverse('remediation:task_start', args=[self.task.id]))
        self.task.refresh_from_db()
        self.assertEqual(self.task.status, TaskStatus.IN_PROGRESS)

        # 2. Employee submits resolution notes & evidence
        res = self.client.post(reverse('remediation:task_submit', args=[self.task.id]), {
            'resolution_notes': 'Disabled PasswordAuthentication in sshd_config. Keys enforced.',
            'attachment_reference': 'sshd_config.diff'
        })
        self.task.refresh_from_db()
        self.assertEqual(self.task.status, TaskStatus.SUBMITTED_FOR_REVIEW)
        self.assertEqual(self.task.evidence_items.count(), 1)

        # 3. Analyst verifies and closes task
        self.client.force_login(self.analyst)
        session = self.client.session
        session['active_organization_id'] = self.org.id
        session.save()

        res = self.client.post(reverse('remediation:task_verify', args=[self.task.id]), {
            'action': 'verify',
            'feedback': 'Configuration inspected and verified compliant.'
        })
        self.task.refresh_from_db()
        self.assertEqual(self.task.status, TaskStatus.VERIFIED)
        self.assertIsNotNone(self.task.verified_at)

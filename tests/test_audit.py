from django.test import TestCase
from django.contrib.auth import get_user_model
from apps.organizations.models import Organization
from apps.audit.models import AuditEvent
from apps.audit.services import log_audit_event

User = get_user_model()

class AuditLoggingTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='audit@org.com', username='audit@org.com', password='Pass123!')
        self.org = Organization.objects.create(name='Audit Org', slug='audit-org')

    def test_audit_event_logged(self):
        log_audit_event(
            request=None,
            action='POLICY_PUBLISHED',
            organization=self.org,
            actor=self.user,
            details='Published Incident Response Protocol v1.0'
        )
        self.assertEqual(AuditEvent.objects.filter(action='POLICY_PUBLISHED').count(), 1)
        event = AuditEvent.objects.first()
        self.assertEqual(event.actor, self.user)
        self.assertEqual(event.organization, self.org)

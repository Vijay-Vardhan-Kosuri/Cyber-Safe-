from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from apps.organizations.models import Organization, Membership, RoleChoices
from apps.checklists.models import ChecklistCategory, ChecklistTemplate, ChecklistItem, TemplateStatus
from apps.assessments.models import Assessment, AssessmentStatus

User = get_user_model()

class TenantIsolationTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.org1 = Organization.objects.create(name='Org Alpha', slug='org-alpha')
        self.user1 = User.objects.create_user(email='user@alpha.com', username='user@alpha.com', password='Pass123!')
        Membership.objects.create(user=self.user1, organization=self.org1, role=RoleChoices.ORG_ADMIN)

        self.org2 = Organization.objects.create(name='Org Beta', slug='org-beta')
        self.user2 = User.objects.create_user(email='user@beta.com', username='user@beta.com', password='Pass123!')
        Membership.objects.create(user=self.user2, organization=self.org2, role=RoleChoices.ORG_ADMIN)

        self.cat = ChecklistCategory.objects.create(name='Net Sec', slug='net-sec')
        self.tmpl = ChecklistTemplate.objects.create(title='Tmpl Beta', is_global=True, status=TemplateStatus.PUBLISHED)
        self.item = ChecklistItem.objects.create(template=self.tmpl, category=self.cat, control_code='N-01', title='Firewall')

        self.assessment_org2 = Assessment.objects.create(
            organization=self.org2,
            template=self.tmpl,
            title='Org 2 Private Assessment',
            assigned_to=self.user2,
            status=AssessmentStatus.DRAFT
        )

    def test_cross_tenant_access_blocked(self):
        self.client.force_login(self.user1)
        session = self.client.session
        session['active_organization_id'] = self.org1.id
        session.save()

        res = self.client.get(reverse('assessments:assessment_detail', args=[self.assessment_org2.id]))
        self.assertEqual(res.status_code, 404)

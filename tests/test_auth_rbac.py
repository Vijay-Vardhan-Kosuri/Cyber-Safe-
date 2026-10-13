from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from apps.organizations.models import Organization, Membership, RoleChoices, MembershipStatus

User = get_user_model()

class AuthAndRBACTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.superadmin = User.objects.create_superuser(
            email='superadmin@cybersafe.local',
            username='superadmin@cybersafe.local',
            password='AdminPass123!',
            is_platform_admin=True
        )

        self.org = Organization.objects.create(name='Test Org 1', slug='test-org-1')

        # Org Admin
        self.org_admin = User.objects.create_user(
            email='admin@testorg1.com',
            username='admin@testorg1.com',
            password='Password123!'
        )
        Membership.objects.create(
            user=self.org_admin,
            organization=self.org,
            role=RoleChoices.ORG_ADMIN,
            status=MembershipStatus.ACTIVE
        )

        # Employee
        self.employee = User.objects.create_user(
            email='emp@testorg1.com',
            username='emp@testorg1.com',
            password='Password123!'
        )
        Membership.objects.create(
            user=self.employee,
            organization=self.org,
            role=RoleChoices.EMPLOYEE,
            status=MembershipStatus.ACTIVE
        )

    def test_login_successful_redirect(self):
        response = self.client.post(reverse('accounts:login'), {
            'username': 'admin@testorg1.com',
            'password': 'Password123!'
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('accounts:dashboard_redirect'))

    def test_role_based_dashboard_redirects(self):
        # Superadmin redirects to superadmin dashboard
        self.client.force_login(self.superadmin)
        res = self.client.get(reverse('accounts:dashboard_redirect'))
        self.assertRedirects(res, reverse('organizations:superadmin_dashboard'))

        # Org admin redirects to orgadmin dashboard
        self.client.force_login(self.org_admin)
        res = self.client.get(reverse('accounts:dashboard_redirect'))
        self.assertRedirects(res, reverse('organizations:orgadmin_dashboard'))

        # Employee redirects to employee dashboard
        self.client.force_login(self.employee)
        res = self.client.get(reverse('accounts:dashboard_redirect'))
        self.assertRedirects(res, reverse('organizations:employee_dashboard'))

    def test_employee_forbidden_from_orgadmin_dashboard(self):
        self.client.force_login(self.employee)
        session = self.client.session
        session['active_organization_id'] = self.org.id
        session.save()

        res = self.client.get(reverse('organizations:orgadmin_dashboard'))
        self.assertEqual(res.status_code, 403)

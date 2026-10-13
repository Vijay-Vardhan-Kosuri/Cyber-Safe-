from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import ListView, DetailView, CreateView, UpdateView, View, TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.utils import timezone
from django.urls import reverse_lazy, reverse
from django.core.exceptions import PermissionDenied
from django.contrib.auth import get_user_model, login

from .models import Organization, Membership, OrganizationInvitation, RoleChoices, MembershipStatus, SecurityPolicy
from .forms import OrganizationCreateForm, InviteMemberForm, AcceptInvitationForm, SecurityPolicyForm
from .permissions import RoleRequiredMixin, ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_SECURITY_ANALYST, ROLE_EMPLOYEE
from apps.audit.services import log_audit_event
from apps.notifications.models import Notification

User = get_user_model()

# ==========================================
# 4 PRIMARY ROLE DASHBOARDS
# ==========================================

class SuperAdminDashboardView(LoginRequiredMixin, RoleRequiredMixin, TemplateView):
    template_name = 'dashboards/superadmin_dashboard.html'
    allowed_roles = [ROLE_SUPER_ADMIN]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        from apps.checklists.models import ChecklistTemplate
        from apps.audit.models import AuditEvent
        from apps.assessments.models import Assessment

        context['organizations'] = Organization.objects.all().order_by('-created_at')
        context['total_orgs'] = Organization.objects.count()
        context['active_orgs'] = Organization.objects.filter(is_active=True).count()
        context['total_users'] = User.objects.count()
        context['total_assessments'] = Assessment.objects.count()
        context['templates'] = ChecklistTemplate.objects.filter(is_global=True)
        context['recent_audit_events'] = AuditEvent.objects.all().order_by('-timestamp')[:10]
        return context

class OrgAdminDashboardView(LoginRequiredMixin, RoleRequiredMixin, TemplateView):
    template_name = 'dashboards/orgadmin_dashboard.html'
    allowed_roles = [ROLE_ORG_ADMIN]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        org = self.request.active_organization
        if not org:
            return context

        from apps.assessments.models import Assessment
        from apps.remediation.models import RemediationTask

        assessments = Assessment.objects.filter(organization=org)
        tasks = RemediationTask.objects.filter(organization=org)

        context['organization'] = org
        context['members_count'] = org.active_members_count
        context['total_assessments'] = assessments.count()
        context['completed_assessments'] = assessments.filter(status='COMPLETED').count()

        # Score calculation
        completed = assessments.filter(status='COMPLETED')
        if completed.exists():
            avg_score = round(sum(a.score for a in completed) / completed.count(), 1)
        else:
            avg_score = 78.5  # baseline demo score if new
        context['avg_posture_score'] = avg_score

        context['open_tasks_count'] = tasks.exclude(status='VERIFIED').count()
        context['verified_tasks_count'] = tasks.filter(status='VERIFIED').count()
        context['overdue_tasks_count'] = tasks.filter(due_date__lt=timezone.now().date()).exclude(status='VERIFIED').count()
        context['recent_assessments'] = assessments.order_by('-created_at')[:5]
        context['recent_tasks'] = tasks.order_by('-created_at')[:5]
        return context

class AnalystDashboardView(LoginRequiredMixin, RoleRequiredMixin, TemplateView):
    template_name = 'dashboards/analyst_dashboard.html'
    allowed_roles = [ROLE_SECURITY_ANALYST, ROLE_ORG_ADMIN]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        org = self.request.active_organization
        if not org:
            return context

        from apps.assessments.models import Assessment, AssessmentResponse
        from apps.remediation.models import RemediationTask

        context['organization'] = org
        context['awaiting_review_assessments'] = Assessment.objects.filter(organization=org, status='SUBMITTED')
        context['verification_queue'] = RemediationTask.objects.filter(organization=org, status='SUBMITTED_FOR_REVIEW')
        context['high_priority_findings'] = AssessmentResponse.objects.filter(
            assessment__organization=org,
            response='NEEDS_IMPROVEMENT',
            item__priority__in=['HIGH', 'CRITICAL']
        ).select_related('assessment', 'item', 'item__category')[:10]
        context['total_findings'] = AssessmentResponse.objects.filter(
            assessment__organization=org,
            response='NEEDS_IMPROVEMENT'
        ).count()
        return context

class EmployeeDashboardView(LoginRequiredMixin, RoleRequiredMixin, TemplateView):
    template_name = 'dashboards/employee_dashboard.html'
    allowed_roles = [ROLE_EMPLOYEE, ROLE_SECURITY_ANALYST, ROLE_ORG_ADMIN]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        org = self.request.active_organization
        from apps.assessments.models import Assessment
        from apps.remediation.models import RemediationTask

        user = self.request.user
        context['my_assessments'] = Assessment.objects.filter(organization=org, assigned_to=user).order_by('-created_at')
        context['my_tasks'] = RemediationTask.objects.filter(organization=org, assigned_to=user).order_by('due_date')
        context['completed_tasks'] = context['my_tasks'].filter(status='VERIFIED').count()
        context['pending_tasks'] = context['my_tasks'].exclude(status='VERIFIED').count()
        context['overdue_tasks'] = context['my_tasks'].filter(due_date__lt=timezone.now().date()).exclude(status='VERIFIED').count()
        return context

# ==========================================
# WORKFLOW A: INVITATIONS & ONBOARDING
# ==========================================

class InviteMemberView(LoginRequiredMixin, RoleRequiredMixin, View):
    allowed_roles = [ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN]

    def post(self, request):
        org = request.active_organization
        if not org:
            messages.error(request, "No active organization selected.")
            return redirect('accounts:dashboard_redirect')

        form = InviteMemberForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email'].lower()
            role = form.cleaned_data['role']
            dept = form.cleaned_data['department']

            # Check if already a member
            if Membership.objects.filter(organization=org, user__email=email).exists():
                messages.warning(request, f"{email} is already an active member of this organization.")
                return redirect('organizations:member_list')

            invitation, created = OrganizationInvitation.objects.update_or_create(
                organization=org,
                email=email,
                defaults={
                    'role': role,
                    'department': dept,
                    'invited_by': request.user,
                    'is_revoked': False,
                    'expires_at': timezone.now() + timezone.timedelta(days=7),
                }
            )

            log_audit_event(
                request=request,
                action='INVITATION_SENT',
                organization=org,
                actor=request.user,
                details=f"Sent invitation to {email} as {role}"
            )

            invite_url = request.build_absolute_uri(reverse('organizations:accept_invitation', args=[invitation.token]))
            messages.success(request, f"Invitation generated successfully for {email}! Shareable link: {invite_url}")
        else:
            messages.error(request, "Invalid invitation details. Please check the email format.")
        return redirect('organizations:member_list')

class AcceptInvitationView(View):
    def get(self, request, token):
        invitation = get_object_or_404(OrganizationInvitation, token=token)
        if not invitation.is_valid:
            return render(request, 'organizations/invitation_expired.html', {'invitation': invitation})

        form = AcceptInvitationForm()
        return render(request, 'organizations/accept_invitation.html', {
            'invitation': invitation,
            'form': form
        })

    def post(self, request, token):
        invitation = get_object_or_404(OrganizationInvitation, token=token)
        if not invitation.is_valid:
            messages.error(request, "This invitation token has expired or has already been used.")
            return render(request, 'organizations/invitation_expired.html', {'invitation': invitation})

        form = AcceptInvitationForm(request.POST)
        if form.is_valid():
            email = invitation.email.lower()
            user, created = User.objects.get_or_create(email=email, defaults={
                'username': email,
                'first_name': form.cleaned_data['first_name'],
                'last_name': form.cleaned_data['last_name'],
            })
            if not created:
                user.first_name = form.cleaned_data['first_name']
                user.last_name = form.cleaned_data['last_name']

            user.set_password(form.cleaned_data['password'])
            user.save()

            # Create or update membership
            membership, _ = Membership.objects.update_or_create(
                user=user,
                organization=invitation.organization,
                defaults={
                    'role': invitation.role,
                    'department': invitation.department,
                    'status': MembershipStatus.ACTIVE
                }
            )

            # Invalidate invitation
            invitation.accepted_at = timezone.now()
            invitation.save(update_fields=['accepted_at'])

            # Log audit event
            log_audit_event(
                request=request,
                action='INVITATION_ACCEPTED',
                organization=invitation.organization,
                actor=user,
                details=f"Accepted invitation and established credentials for {invitation.organization.name}"
            )

            login(request, user)
            messages.success(request, f"Welcome to {invitation.organization.name}, {user.first_name}! Your workspace is ready.")
            return redirect('accounts:dashboard_redirect')

        return render(request, 'organizations/accept_invitation.html', {
            'invitation': invitation,
            'form': form
        })

class MemberListView(LoginRequiredMixin, RoleRequiredMixin, ListView):
    model = Membership
    template_name = 'organizations/member_list.html'
    context_object_name = 'memberships'
    allowed_roles = [ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN]

    def get_queryset(self):
        org = self.request.active_organization
        if not org:
            return Membership.objects.none()
        return Membership.objects.filter(organization=org).select_related('user')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        org = self.request.active_organization
        context['invite_form'] = InviteMemberForm()
        context['pending_invitations'] = OrganizationInvitation.objects.filter(
            organization=org,
            accepted_at__isnull=True,
            is_revoked=False
        )
        return context

class SwitchOrganizationView(LoginRequiredMixin, View):
    def post(self, request, org_id):
        membership = get_object_or_404(Membership, user=request.user, organization_id=org_id, status=MembershipStatus.ACTIVE)
        request.session['active_organization_id'] = membership.organization.id
        messages.success(request, f"Switched active workspace to {membership.organization.name}.")
        return redirect('accounts:dashboard_redirect')

class ToggleMemberStatusView(LoginRequiredMixin, RoleRequiredMixin, View):
    allowed_roles = [ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN]

    def post(self, request, membership_id):
        org = request.active_organization
        membership = get_object_or_404(Membership, id=membership_id, organization=org)

        if membership.user == request.user:
            messages.error(request, "You cannot suspend your own active membership.")
            return redirect('organizations:member_list')

        if membership.status == MembershipStatus.ACTIVE:
            membership.status = MembershipStatus.SUSPENDED
            msg = f"Suspended membership for {membership.user.full_name}."
            action = 'MEMBER_SUSPENDED'
        else:
            membership.status = MembershipStatus.ACTIVE
            msg = f"Reactivated membership for {membership.user.full_name}."
            action = 'MEMBER_ACTIVATED'

        membership.save(update_fields=['status'])
        log_audit_event(request=request, action=action, organization=org, actor=request.user, details=msg)
        messages.info(request, msg)
        return redirect('organizations:member_list')

class PolicyListView(LoginRequiredMixin, ListView):
    model = SecurityPolicy
    template_name = 'organizations/policies.html'
    context_object_name = 'policies'

    def get_queryset(self):
        org = self.request.active_organization
        return SecurityPolicy.objects.filter(organization=org)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['policy_form'] = SecurityPolicyForm()
        return context

class PolicyCreateView(LoginRequiredMixin, RoleRequiredMixin, View):
    allowed_roles = [ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN]

    def post(self, request):
        org = request.active_organization
        form = SecurityPolicyForm(request.POST)
        if form.is_valid():
            policy = form.save(commit=False)
            policy.organization = org
            policy.created_by = request.user
            policy.save()
            log_audit_event(
                request=request,
                action='POLICY_PUBLISHED',
                organization=org,
                actor=request.user,
                details=f"Published security policy: {policy.title} v{policy.version}"
            )
            messages.success(request, f"Security policy '{policy.title}' published successfully.")
        return redirect('organizations:policy_list')

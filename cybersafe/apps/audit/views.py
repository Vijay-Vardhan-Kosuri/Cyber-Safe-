from django.shortcuts import render
from django.views.generic import ListView
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import AuditEvent
from apps.organizations.permissions import RoleRequiredMixin, ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_SECURITY_ANALYST

class AuditLogListView(LoginRequiredMixin, RoleRequiredMixin, ListView):
    model = AuditEvent
    template_name = 'audit/audit_log.html'
    context_object_name = 'events'
    allowed_roles = [ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_SECURITY_ANALYST]
    paginate_by = 30

    def get_queryset(self):
        user = self.request.user
        org = self.request.active_organization

        if user.is_platform_admin or user.is_superuser:
            qs = AuditEvent.objects.all()
        elif org:
            qs = AuditEvent.objects.filter(organization=org)
        else:
            qs = AuditEvent.objects.none()

        action = self.request.GET.get('action')
        if action:
            qs = qs.filter(action__icontains=action)

        return qs.select_related('actor', 'organization')

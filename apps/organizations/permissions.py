from functools import wraps
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from apps.audit.services import log_audit_event
from .models import RoleChoices, MembershipStatus

ROLE_SUPER_ADMIN = RoleChoices.PLATFORM_SUPER_ADMIN.value
ROLE_ORG_ADMIN = RoleChoices.ORG_ADMIN.value
ROLE_SECURITY_ANALYST = RoleChoices.SECURITY_ANALYST.value
ROLE_EMPLOYEE = RoleChoices.EMPLOYEE.value

def role_required(*allowed_roles):
    """
    Enforces server-side RBAC validation.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('accounts:login')

            if request.user.is_platform_admin or request.user.is_superuser:
                return view_func(request, *args, **kwargs)

            user_role = getattr(request, 'user_role', None)
            if user_role in allowed_roles:
                return view_func(request, *args, **kwargs)

            # Security log unauthorized access attempt
            log_audit_event(
                request=request,
                action='UNAUTHORIZED_ACCESS_ATTEMPT',
                actor=request.user,
                details=f"User attempted access to view requiring roles {allowed_roles}. Current role: {user_role}"
            )
            raise PermissionDenied("You do not have the necessary permissions to access this cybersecurity resource.")
        return _wrapped_view
    return decorator

class RoleRequiredMixin:
    allowed_roles = []

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('accounts:login')

        if request.user.is_platform_admin or request.user.is_superuser:
            return super().dispatch(request, *args, **kwargs)

        user_role = getattr(request, 'user_role', None)
        if user_role in self.allowed_roles:
            return super().dispatch(request, *args, **kwargs)

        log_audit_event(
            request=request,
            action='UNAUTHORIZED_ACCESS_ATTEMPT',
            actor=request.user,
            details=f"Class-based view authorization blocked. Required: {self.allowed_roles}, Has: {user_role}"
        )
        raise PermissionDenied("Access Denied: Your assigned role does not permit this action.")

class TenantIsolationMixin:
    """
    Enforces multi-tenant data isolation by filtering QuerySets by active organization.
    """
    def get_queryset(self):
        qs = super().get_queryset()
        org = getattr(self.request, 'active_organization', None)
        if not org and not (self.request.user.is_platform_admin or self.request.user.is_superuser):
            return qs.none()
        if self.request.user.is_platform_admin and 'all_orgs' in self.request.GET:
            return qs
        if hasattr(qs.model, 'organization'):
            return qs.filter(organization=org)
        return qs

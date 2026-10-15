from .models import Membership, MembershipStatus

class TenantContextMiddleware:
    """
    Identifies the active organization and user's membership role for multi-tenant isolation.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.active_organization = None
        request.active_membership = None
        request.user_role = None

        if request.user.is_authenticated:
            session_org_id = request.session.get('active_organization_id')
            memberships = Membership.objects.filter(
                user=request.user,
                status=MembershipStatus.ACTIVE,
                organization__is_active=True
            ).select_related('organization')

            if session_org_id:
                active_mem = memberships.filter(organization_id=session_org_id).first()
            else:
                active_mem = memberships.first()

            if active_mem:
                request.active_membership = active_mem
                request.active_organization = active_mem.organization
                request.user_role = active_mem.role
                request.session['active_organization_id'] = active_mem.organization.id
            elif request.user.is_platform_admin or request.user.is_superuser:
                request.user_role = 'SUPER_ADMIN'

        response = self.get_response(request)
        return response

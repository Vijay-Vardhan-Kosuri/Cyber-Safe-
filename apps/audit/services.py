def log_audit_event(request, action, organization=None, actor=None, details=""):
    """
    Immutable security audit logging service.
    """
    try:
        from .models import AuditEvent
        from apps.organizations.models import Organization

        ip_addr = None
        user_agent = ""

        if request:
            ip_addr = request.META.get('HTTP_X_FORWARDED_FOR')
            if ip_addr:
                ip_addr = ip_addr.split(',')[0].strip()
            else:
                ip_addr = request.META.get('REMOTE_ADDR')

            user_agent = request.META.get('HTTP_USER_AGENT', '')[:250]

            if not actor and request.user.is_authenticated:
                actor = request.user

            if not organization:
                organization = getattr(request, 'active_organization', None)

        AuditEvent.objects.create(
            actor=actor,
            organization=organization,
            action=action,
            ip_address=ip_addr,
            user_agent=user_agent,
            details=details
        )
    except Exception as e:
        # Logging should never crash an application transaction
        print(f"Audit log exception: {e}")

def cybersafe_context(request):
    context = {
        'PLATFORM_NAME': 'CyberSafe',
        'PLATFORM_TAGLINE': 'Personal & Organizational Cybersecurity Management Platform',
        'THEME_VERSION': 'SharkFest-Europe-ConferenceEdition',
    }
    if request.user.is_authenticated:
        try:
            from apps.organizations.models import Membership
            from apps.notifications.models import Notification
            memberships = Membership.objects.filter(user=request.user, status='ACTIVE').select_related('organization')
            context['user_memberships'] = memberships
            context['active_membership'] = getattr(request, 'active_membership', memberships.first() if memberships.exists() else None)
            context['unread_notifications_count'] = Notification.objects.filter(user=request.user, is_read=False).count()
        except Exception:
            pass
    return context

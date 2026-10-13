from django.contrib import admin
from .models import AuditEvent

@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'action', 'actor', 'organization', 'ip_address')
    list_filter = ('action', 'organization', 'timestamp')
    search_fields = ('action', 'actor__email', 'details', 'ip_address')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

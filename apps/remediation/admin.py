from django.contrib import admin
from .models import RemediationTask, TaskEvidence

class TaskEvidenceInline(admin.TabularInline):
    model = TaskEvidence
    extra = 0

@admin.register(RemediationTask)
class RemediationTaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'organization', 'assigned_to', 'priority', 'status', 'due_date', 'verified_at')
    list_filter = ('status', 'priority', 'organization')
    search_fields = ('title', 'assigned_to__email')
    inlines = [TaskEvidenceInline]

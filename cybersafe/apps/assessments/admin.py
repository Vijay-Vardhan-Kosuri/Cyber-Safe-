from django.contrib import admin
from .models import Assessment, AssessmentResponse

class AssessmentResponseInline(admin.TabularInline):
    model = AssessmentResponse
    extra = 0
    readonly_fields = ('item', 'response', 'notes', 'evidence_reference')

@admin.register(Assessment)
class AssessmentAdmin(admin.ModelAdmin):
    list_display = ('title', 'organization', 'template', 'assigned_to', 'status', 'score', 'risk_level', 'created_at')
    list_filter = ('status', 'risk_level', 'organization')
    search_fields = ('title', 'assigned_to__email')
    inlines = [AssessmentResponseInline]

@admin.register(AssessmentResponse)
class AssessmentResponseAdmin(admin.ModelAdmin):
    list_display = ('assessment', 'item', 'response', 'updated_at')
    list_filter = ('response', 'assessment__organization')
    search_fields = ('item__control_code', 'notes')

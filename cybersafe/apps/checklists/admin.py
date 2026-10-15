from django.contrib import admin
from .models import ChecklistCategory, ChecklistTemplate, ChecklistItem

@admin.register(ChecklistCategory)
class ChecklistCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'order', 'weight', 'icon')
    prepopulated_fields = {'slug': ('name',)}
    ordering = ('order',)

class ChecklistItemInline(admin.TabularInline):
    model = ChecklistItem
    extra = 1

@admin.register(ChecklistTemplate)
class ChecklistTemplateAdmin(admin.ModelAdmin):
    list_display = ('title', 'version', 'is_global', 'organization', 'status', 'audience', 'created_at')
    list_filter = ('is_global', 'status', 'audience')
    search_fields = ('title', 'description')
    inlines = [ChecklistItemInline]

@admin.register(ChecklistItem)
class ChecklistItemAdmin(admin.ModelAdmin):
    list_display = ('control_code', 'title', 'template', 'category', 'priority', 'is_required')
    list_filter = ('priority', 'is_required', 'category', 'template')
    search_fields = ('control_code', 'title', 'description')

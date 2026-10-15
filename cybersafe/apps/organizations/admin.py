from django.contrib import admin
from .models import Organization, Membership, OrganizationInvitation, SecurityPolicy

@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('name', 'domain', 'industry', 'is_active', 'created_at')
    search_fields = ('name', 'domain', 'industry')
    prepopulated_fields = {'slug': ('name',)}

@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ('user', 'organization', 'role', 'status', 'joined_at')
    list_filter = ('role', 'status', 'organization')
    search_fields = ('user__email', 'organization__name')

@admin.register(OrganizationInvitation)
class OrganizationInvitationAdmin(admin.ModelAdmin):
    list_display = ('email', 'organization', 'role', 'created_at', 'expires_at', 'accepted_at')
    list_filter = ('role', 'organization', 'is_revoked')
    search_fields = ('email', 'organization__name')

@admin.register(SecurityPolicy)
class SecurityPolicyAdmin(admin.ModelAdmin):
    list_display = ('title', 'version', 'organization', 'category', 'is_mandatory', 'published_date')
    list_filter = ('organization', 'category', 'is_mandatory')

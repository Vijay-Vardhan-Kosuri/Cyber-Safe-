import uuid
from datetime import timedelta
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.text import slugify

class RoleChoices(models.TextChoices):
    PLATFORM_SUPER_ADMIN = 'SUPER_ADMIN', 'Platform Super Admin'
    ORG_ADMIN = 'ORG_ADMIN', 'Organization Admin'
    SECURITY_ANALYST = 'SECURITY_ANALYST', 'Security Analyst'
    EMPLOYEE = 'EMPLOYEE', 'Employee / Member'

class MembershipStatus(models.TextChoices):
    ACTIVE = 'ACTIVE', 'Active'
    SUSPENDED = 'SUSPENDED', 'Suspended'

class Organization(models.Model):
    name = models.CharField(max_length=200, unique=True, verbose_name="Organization Name")
    slug = models.SlugField(max_length=220, unique=True, blank=True)
    domain = models.CharField(max_length=150, blank=True, help_text="e.g. apexfinancial.com")
    industry = models.CharField(max_length=100, default="Technology & Finance")
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    max_members = models.PositiveIntegerField(default=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    @property
    def active_members_count(self):
        return self.memberships.filter(status=MembershipStatus.ACTIVE).count()

    def __str__(self):
        return self.name

class Membership(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='memberships')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='memberships')
    role = models.CharField(max_length=30, choices=RoleChoices.choices, default=RoleChoices.EMPLOYEE)
    status = models.CharField(max_length=20, choices=MembershipStatus.choices, default=MembershipStatus.ACTIVE)
    department = models.CharField(max_length=100, blank=True, default="Security Operations")
    joined_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'organization')
        ordering = ['organization', 'role', 'user']

    def __str__(self):
        return f"{self.user.full_name} - {self.organization.name} [{self.get_role_display()}]"

class OrganizationInvitation(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='invitations')
    email = models.EmailField(verbose_name="Invited Email")
    role = models.CharField(max_length=30, choices=RoleChoices.choices, default=RoleChoices.EMPLOYEE)
    department = models.CharField(max_length=100, blank=True, default="General")
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    invited_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='sent_invitations')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True, blank=True)
    is_revoked = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(days=7)
        super().save(*args, **kwargs)

    @property
    def is_valid(self):
        return (not self.is_revoked) and (self.accepted_at is None) and (self.expires_at > timezone.now())

    def __str__(self):
        return f"Invite for {self.email} to {self.organization.name} ({self.role})"

class SecurityPolicy(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='policies')
    title = models.CharField(max_length=200)
    version = models.CharField(max_length=20, default="1.0")
    category = models.CharField(max_length=100, default="General Cybersecurity")
    content = models.TextField()
    is_mandatory = models.BooleanField(default=True)
    published_date = models.DateField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)

    class Meta:
        ordering = ['-published_date']

    def __str__(self):
        return f"{self.title} v{self.version} ({self.organization.name})"

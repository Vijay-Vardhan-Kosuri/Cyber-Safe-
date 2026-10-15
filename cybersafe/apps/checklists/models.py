from django.db import models
from django.conf import settings
from django.utils.text import slugify
from apps.organizations.models import Organization

class ChecklistCategory(models.Model):
    name = models.CharField(max_length=150, unique=True)
    slug = models.SlugField(max_length=160, unique=True, blank=True)
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=50, default="bi-shield-check", help_text="Bootstrap Icons class")
    weight = models.FloatField(default=1.0, help_text="Weight multiplier in overall scoring formula")
    order = models.PositiveIntegerField(default=1)

    class Meta:
        verbose_name_plural = "Checklist Categories"
        ordering = ['order', 'name']

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

class TemplateStatus(models.TextChoices):
    DRAFT = 'DRAFT', 'Draft'
    PUBLISHED = 'PUBLISHED', 'Published'
    ARCHIVED = 'ARCHIVED', 'Archived'

class TargetAudience(models.TextChoices):
    ALL = 'ALL', 'All Personnel'
    TECHNICAL = 'TECHNICAL', 'Technical & IT Staff'
    MANAGEMENT = 'MANAGEMENT', 'Leadership & Executive'

class ChecklistTemplate(models.Model):
    title = models.CharField(max_length=200)
    version = models.CharField(max_length=20, default="1.0")
    description = models.TextField()
    is_global = models.BooleanField(
        default=False,
        help_text="Global templates are managed by Super Admins and visible across all organizations."
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='custom_templates',
        help_text="If set, template is scoped to this organization."
    )
    status = models.CharField(max_length=20, choices=TemplateStatus.choices, default=TemplateStatus.DRAFT)
    audience = models.CharField(max_length=30, choices=TargetAudience.choices, default=TargetAudience.ALL)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-is_global', '-created_at']

    @property
    def total_items_count(self):
        return self.items.count()

    def __str__(self):
        scope = "Global" if self.is_global else (self.organization.name if self.organization else "Custom")
        return f"{self.title} v{self.version} [{scope}]"

class PriorityChoices(models.TextChoices):
    LOW = 'LOW', 'Low Priority'
    MEDIUM = 'MEDIUM', 'Medium Priority'
    HIGH = 'HIGH', 'High Priority'
    CRITICAL = 'CRITICAL', 'Critical Priority'

class ChecklistItem(models.Model):
    template = models.ForeignKey(ChecklistTemplate, on_delete=models.CASCADE, related_name='items')
    category = models.ForeignKey(ChecklistCategory, on_delete=models.CASCADE, related_name='items')
    control_code = models.CharField(max_length=50, help_text="e.g. IAM-01, MFA-02")
    title = models.CharField(max_length=255)
    description = models.TextField(help_text="Detailed explanation of the expected cybersecurity practice")
    guidance = models.TextField(help_text="Actionable remediation steps if not implemented")
    priority = models.CharField(max_length=20, choices=PriorityChoices.choices, default=PriorityChoices.MEDIUM)
    is_required = models.BooleanField(default=True)
    order = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ['category__order', 'order', 'control_code']
        unique_together = ('template', 'control_code')

    def __str__(self):
        return f"[{self.control_code}] {self.title}"

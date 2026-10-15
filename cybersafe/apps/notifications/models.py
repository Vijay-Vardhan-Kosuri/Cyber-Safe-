from django.db import models
from django.conf import settings
from apps.organizations.models import Organization

class NotificationCategory(models.TextChoices):
    INVITATION = 'INVITATION', 'Invitation'
    ASSESSMENT = 'ASSESSMENT', 'Assessment'
    REMEDIATION = 'REMEDIATION', 'Remediation'
    DEADLINE = 'DEADLINE', 'Approaching Deadline'
    AUDIT = 'AUDIT', 'Security Alert'

class Notification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    title = models.CharField(max_length=200)
    message = models.TextField()
    category = models.CharField(max_length=30, choices=NotificationCategory.choices, default=NotificationCategory.ASSESSMENT)
    link_url = models.CharField(max_length=255, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.category}] {self.title} -> {self.user.email}"

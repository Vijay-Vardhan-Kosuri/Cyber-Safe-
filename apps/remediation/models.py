from django.db import models
from django.conf import settings
from django.utils import timezone
from apps.organizations.models import Organization
from apps.assessments.models import Assessment
from apps.checklists.models import ChecklistItem

class TaskStatus(models.TextChoices):
    OPEN = 'OPEN', 'Open'
    IN_PROGRESS = 'IN_PROGRESS', 'In Progress'
    SUBMITTED_FOR_REVIEW = 'SUBMITTED_FOR_REVIEW', 'Submitted for Review'
    VERIFIED = 'VERIFIED', 'Verified / Completed'

class TaskPriority(models.TextChoices):
    LOW = 'LOW', 'Low'
    MEDIUM = 'MEDIUM', 'Medium'
    HIGH = 'HIGH', 'High'
    CRITICAL = 'CRITICAL', 'Critical'

class RemediationTask(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='remediation_tasks')
    assessment = models.ForeignKey(Assessment, on_delete=models.SET_NULL, null=True, blank=True, related_name='tasks')
    item = models.ForeignKey(ChecklistItem, on_delete=models.SET_NULL, null=True, blank=True, related_name='remediation_tasks')
    title = models.CharField(max_length=255)
    description = models.TextField(help_text="Detailed corrective action plan")
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='assigned_remediation_tasks'
    )
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_remediation_tasks'
    )
    priority = models.CharField(max_length=20, choices=TaskPriority.choices, default=TaskPriority.HIGH)
    due_date = models.DateField()
    status = models.CharField(max_length=30, choices=TaskStatus.choices, default=TaskStatus.OPEN)
    resolution_notes = models.TextField(blank=True, help_text="Action details provided by the employee upon completion")
    reviewer_feedback = models.TextField(blank=True, help_text="Notes from Security Analyst upon review")
    rejection_reason = models.TextField(blank=True, help_text="Explanation if returned to In Progress")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    verified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['due_date', '-priority']

    @property
    def is_overdue(self):
        if self.status == TaskStatus.VERIFIED:
            return False
        return self.due_date < timezone.now().date()

    def __str__(self):
        return f"[{self.get_priority_display()}] {self.title} ({self.get_status_display()})"

class TaskEvidence(models.Model):
    task = models.ForeignKey(RemediationTask, on_delete=models.CASCADE, related_name='evidence_items')
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    notes = models.TextField()
    attachment_reference = models.CharField(max_length=255, blank=True, help_text="Internal screenshot, log or document ID")
    external_url = models.URLField(blank=True, help_text="External link to ticketing system or commit")
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-submitted_at']

    def __str__(self):
        return f"Evidence for {self.task.title} by {self.uploaded_by.full_name}"

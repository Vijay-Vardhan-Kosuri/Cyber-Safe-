from django.db import models
from django.conf import settings
from apps.organizations.models import Organization
from apps.checklists.models import ChecklistTemplate, ChecklistItem

class AssessmentStatus(models.TextChoices):
    DRAFT = 'DRAFT', 'Draft / In Progress'
    SUBMITTED = 'SUBMITTED', 'Submitted for Review'
    UNDER_REVIEW = 'UNDER_REVIEW', 'Under Review'
    COMPLETED = 'COMPLETED', 'Completed & Scored'

class RiskLevel(models.TextChoices):
    LOW = 'LOW', 'Low Risk / Robust'
    MODERATE = 'MODERATE', 'Moderate Risk / Needs Improvement'
    HIGH = 'HIGH', 'High Risk / Immediate Attention'

class Assessment(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='assessments')
    template = models.ForeignKey(ChecklistTemplate, on_delete=models.PROTECT, related_name='assessments')
    title = models.CharField(max_length=255)
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='assigned_assessments',
        help_text="Member responsible for providing responses"
    )
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_assessments',
        help_text="Security Analyst or Admin reviewing findings"
    )
    status = models.CharField(max_length=30, choices=AssessmentStatus.choices, default=AssessmentStatus.DRAFT)
    score = models.FloatField(default=0.0, help_text="Calculated compliance score (0-100)")
    risk_level = models.CharField(max_length=20, choices=RiskLevel.choices, default=RiskLevel.MODERATE)
    notes = models.TextField(blank=True)
    reviewer_feedback = models.TextField(blank=True)
    started_at = models.DateTimeField(auto_now_add=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    @property
    def total_controls_count(self):
        return self.template.items.count()

    @property
    def completed_responses_count(self):
        return self.responses.exclude(response=ResponseChoices.NOT_ASSESSED).count()

    @property
    def completion_percentage(self):
        total = self.total_controls_count
        if total == 0:
            return 0
        return round((self.completed_responses_count / total) * 100)

    @property
    def compliant_count(self):
        return self.responses.filter(response=ResponseChoices.COMPLIANT).count()

    @property
    def needs_improvement_count(self):
        return self.responses.filter(response=ResponseChoices.NEEDS_IMPROVEMENT).count()

    @property
    def not_applicable_count(self):
        return self.responses.filter(response=ResponseChoices.NOT_APPLICABLE).count()

    def __str__(self):
        return f"{self.title} - {self.organization.name} ({self.get_status_display()})"

class ResponseChoices(models.TextChoices):
    COMPLIANT = 'COMPLIANT', 'Compliant'
    NEEDS_IMPROVEMENT = 'NEEDS_IMPROVEMENT', 'Needs Improvement'
    NOT_APPLICABLE = 'NOT_APPLICABLE', 'Not Applicable'
    NOT_ASSESSED = 'NOT_ASSESSED', 'Not Assessed'

class AssessmentResponse(models.Model):
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='responses')
    item = models.ForeignKey(ChecklistItem, on_delete=models.PROTECT, related_name='responses')
    response = models.CharField(max_length=30, choices=ResponseChoices.choices, default=ResponseChoices.NOT_ASSESSED)
    notes = models.TextField(blank=True, help_text="Justification, context, or tool implementation detail")
    evidence_reference = models.CharField(max_length=255, blank=True, help_text="Reference to internal ticket, wiki, or screenshot")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('assessment', 'item')
        ordering = ['item__category__order', 'item__order']

    def __str__(self):
        return f"{self.assessment.title} - [{self.item.control_code}]: {self.response}"

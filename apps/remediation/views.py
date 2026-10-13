from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import ListView, DetailView, CreateView, View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.utils import timezone
from django.db import transaction

from .models import RemediationTask, TaskEvidence, TaskStatus, TaskPriority
from .forms import RemediationTaskCreateForm, TaskSubmissionForm, TaskVerificationForm
from apps.organizations.permissions import (
    RoleRequiredMixin, TenantIsolationMixin,
    ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_SECURITY_ANALYST, ROLE_EMPLOYEE
)
from apps.assessments.models import AssessmentResponse
from apps.audit.services import log_audit_event
from apps.notifications.models import Notification

class TaskListView(LoginRequiredMixin, TenantIsolationMixin, ListView):
    model = RemediationTask
    template_name = 'remediation/task_list.html'
    context_object_name = 'tasks'

    def get_queryset(self):
        org = self.request.active_organization
        if not org and not self.request.user.is_platform_admin:
            return RemediationTask.objects.none()

        qs = RemediationTask.objects.filter(organization=org).select_related('assigned_to', 'reviewer', 'item')
        user_role = getattr(self.request, 'user_role', None)

        if user_role == ROLE_EMPLOYEE and not self.request.user.is_platform_admin:
            qs = qs.filter(assigned_to=self.request.user)

        # Filters
        status = self.request.GET.get('status')
        if status:
            qs = qs.filter(status=status)
        priority = self.request.GET.get('priority')
        if priority:
            qs = qs.filter(priority=priority)

        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        org = self.request.active_organization
        all_tasks = RemediationTask.objects.filter(organization=org)
        user_role = getattr(self.request, 'user_role', None)
        if user_role == ROLE_EMPLOYEE and not self.request.user.is_platform_admin:
            all_tasks = all_tasks.filter(assigned_to=self.request.user)

        context['total_count'] = all_tasks.count()
        context['open_count'] = all_tasks.filter(status=TaskStatus.OPEN).count()
        context['in_progress_count'] = all_tasks.filter(status=TaskStatus.IN_PROGRESS).count()
        context['submitted_count'] = all_tasks.filter(status=TaskStatus.SUBMITTED_FOR_REVIEW).count()
        context['verified_count'] = all_tasks.filter(status=TaskStatus.VERIFIED).count()
        context['overdue_count'] = all_tasks.filter(due_date__lt=timezone.now().date()).exclude(status=TaskStatus.VERIFIED).count()
        return context

class TaskDetailView(LoginRequiredMixin, DetailView):
    model = RemediationTask
    template_name = 'remediation/task_detail.html'
    context_object_name = 'task'

    def get_queryset(self):
        org = self.request.active_organization
        return RemediationTask.objects.filter(organization=org)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['submission_form'] = TaskSubmissionForm()
        context['verification_form'] = TaskVerificationForm()
        context['evidence_items'] = self.get_object().evidence_items.all()
        return context

class TaskCreateFromFindingView(LoginRequiredMixin, RoleRequiredMixin, View):
    allowed_roles = [ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_SECURITY_ANALYST]

    def post(self, request, finding_id):
        org = request.active_organization
        finding = get_object_or_404(AssessmentResponse, id=finding_id, assessment__organization=org)
        item = finding.item

        finding_notes = finding.notes if finding.notes else "Identified in assessment."
        task_desc = f"Actionable Guidance: {item.guidance}\n\nFinding Context: {finding_notes}"

        task = RemediationTask.objects.create(
            organization=org,
            assessment=finding.assessment,
            item=item,
            title=f"Remediate: {item.title}",
            description=task_desc,
            assigned_to=finding.assessment.assigned_to,
            reviewer=request.user,
            priority=item.priority,
            due_date=timezone.now().date() + timezone.timedelta(days=14),
            status=TaskStatus.OPEN
        )

        Notification.objects.create(
            user=task.assigned_to,
            organization=org,
            title="Remediation Task Assigned",
            message=f"You have been assigned remediation task: '{task.title}'.",
            category='REMEDIATION',
            link_url=f"/remediation/tasks/{task.pk}/"
        )

        log_audit_event(
            request=request,
            action='REMEDIATION_CREATED',
            organization=org,
            actor=request.user,
            details=f"Created remediation task for [{item.control_code}] assigned to {task.assigned_to.email}"
        )

        messages.success(request, f"Remediation task created for [{item.control_code}] and assigned to {task.assigned_to.full_name}.")
        return redirect('assessments:assessment_detail', pk=finding.assessment.pk)

class TaskStartView(LoginRequiredMixin, View):
    def post(self, request, pk):
        org = request.active_organization
        task = get_object_or_404(RemediationTask, pk=pk, organization=org)

        if task.assigned_to != request.user and request.user_role not in [ROLE_ORG_ADMIN, ROLE_SECURITY_ANALYST, ROLE_SUPER_ADMIN]:
            messages.error(request, "You cannot update this task.")
            return redirect('remediation:task_detail', pk=task.pk)

        task.status = TaskStatus.IN_PROGRESS
        task.save(update_fields=['status'])

        log_audit_event(
            request=request,
            action='REMEDIATION_STARTED',
            organization=org,
            actor=request.user,
            details=f"Task '{task.title}' moved to In Progress"
        )
        messages.info(request, "Task status changed to In Progress.")
        return redirect('remediation:task_detail', pk=task.pk)

class TaskSubmitForReviewView(LoginRequiredMixin, View):
    def post(self, request, pk):
        org = request.active_organization
        task = get_object_or_404(RemediationTask, pk=pk, organization=org)

        if task.assigned_to != request.user and request.user_role not in [ROLE_ORG_ADMIN, ROLE_SECURITY_ANALYST, ROLE_SUPER_ADMIN]:
            messages.error(request, "Only the assigned member can submit this task for review.")
            return redirect('remediation:task_detail', pk=task.pk)

        form = TaskSubmissionForm(request.POST)
        if form.is_valid():
            with transaction.atomic():
                task.resolution_notes = form.cleaned_data['resolution_notes']
                task.status = TaskStatus.SUBMITTED_FOR_REVIEW
                task.rejection_reason = ""
                task.save()

                ref = form.cleaned_data.get('attachment_reference', '')
                url = form.cleaned_data.get('external_url', '')
                if ref or url or form.cleaned_data['resolution_notes']:
                    TaskEvidence.objects.create(
                        task=task,
                        uploaded_by=request.user,
                        notes=form.cleaned_data['resolution_notes'],
                        attachment_reference=ref,
                        external_url=url
                    )

                if task.reviewer:
                    Notification.objects.create(
                        user=task.reviewer,
                        organization=org,
                        title="Remediation Awaiting Verification",
                        message=f"{request.user.full_name} submitted '{task.title}' for verification.",
                        category='REMEDIATION',
                        link_url=f"/remediation/tasks/{task.pk}/"
                    )

                log_audit_event(
                    request=request,
                    action='REMEDIATION_SUBMITTED',
                    organization=org,
                    actor=request.user,
                    details=f"Task '{task.title}' submitted for analyst verification."
                )

            messages.success(request, "Remediation submitted for verification. Security Analyst has been notified.")
        else:
            messages.error(request, "Please provide completion notes before submitting.")
        return redirect('remediation:task_detail', pk=task.pk)

class TaskVerifyReviewView(LoginRequiredMixin, RoleRequiredMixin, View):
    allowed_roles = [ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_SECURITY_ANALYST]

    def post(self, request, pk):
        org = request.active_organization
        task = get_object_or_404(RemediationTask, pk=pk, organization=org)

        form = TaskVerificationForm(request.POST)
        if form.is_valid():
            action = form.cleaned_data['action']
            feedback = form.cleaned_data['feedback']

            if action == 'verify':
                task.status = TaskStatus.VERIFIED
                task.verified_at = timezone.now()
                task.reviewer_feedback = feedback
                task.rejection_reason = ""
                task.save()

                Notification.objects.create(
                    user=task.assigned_to,
                    organization=org,
                    title="Remediation Task Verified",
                    message=f"Your remediation for '{task.title}' was verified and closed. Great job!",
                    category='REMEDIATION',
                    link_url=f"/remediation/tasks/{task.pk}/"
                )

                log_audit_event(
                    request=request,
                    action='REMEDIATION_VERIFIED',
                    organization=org,
                    actor=request.user,
                    details=f"Verified remediation '{task.title}'. Notes: {feedback}"
                )
                messages.success(request, f"Task '{task.title}' verified and successfully closed.")

            elif action == 'return':
                task.status = TaskStatus.IN_PROGRESS
                task.rejection_reason = feedback
                task.save()

                Notification.objects.create(
                    user=task.assigned_to,
                    organization=org,
                    title="Remediation Returned for Corrections",
                    message=f"'{task.title}' was returned: {feedback}",
                    category='REMEDIATION',
                    link_url=f"/remediation/tasks/{task.pk}/"
                )

                log_audit_event(
                    request=request,
                    action='REMEDIATION_RETURNED',
                    organization=org,
                    actor=request.user,
                    details=f"Returned remediation '{task.title}' to assignee. Reason: {feedback}"
                )
                messages.warning(request, "Task returned to assignee with explanation.")

        return redirect('remediation:task_detail', pk=task.pk)

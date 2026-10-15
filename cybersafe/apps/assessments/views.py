from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import ListView, DetailView, CreateView, View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.utils import timezone
from django.db import transaction

from .models import Assessment, AssessmentResponse, AssessmentStatus, ResponseChoices, RiskLevel
from .forms import AssessmentCreateForm
from .scoring_service import calculate_assessment_score
from apps.checklists.models import ChecklistTemplate, ChecklistItem, ChecklistCategory
from apps.organizations.permissions import RoleRequiredMixin, TenantIsolationMixin, ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_SECURITY_ANALYST, ROLE_EMPLOYEE
from apps.audit.services import log_audit_event
from apps.notifications.models import Notification

class AssessmentListView(LoginRequiredMixin, TenantIsolationMixin, ListView):
    model = Assessment
    template_name = 'assessments/assessment_list.html'
    context_object_name = 'assessments'

    def get_queryset(self):
        user = self.request.user
        org = self.request.active_organization
        if not org and not user.is_platform_admin:
            return Assessment.objects.none()

        qs = Assessment.objects.filter(organization=org)
        user_role = getattr(self.request, 'user_role', None)

        # Employees only view their own assigned assessments
        if user_role == ROLE_EMPLOYEE and not user.is_platform_admin:
            qs = qs.filter(assigned_to=user)
        return qs.order_by('-created_at')

class AssessmentCreateView(LoginRequiredMixin, RoleRequiredMixin, CreateView):
    model = Assessment
    form_class = AssessmentCreateForm
    template_name = 'assessments/assessment_create.html'
    allowed_roles = [ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_SECURITY_ANALYST]

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['organization'] = self.request.active_organization
        return kwargs

    def form_valid(self, form):
        org = self.request.active_organization
        if not org:
            messages.error(self.request, "Please switch to an active organization first.")
            return redirect('accounts:dashboard_redirect')

        with transaction.atomic():
            assessment = form.save(commit=False)
            assessment.organization = org
            assessment.reviewer = self.request.user
            assessment.status = AssessmentStatus.DRAFT
            assessment.save()

            # Pre-populate responses for all items in the template
            items = assessment.template.items.all()
            responses = [
                AssessmentResponse(
                    assessment=assessment,
                    item=item,
                    response=ResponseChoices.NOT_ASSESSED
                )
                for item in items
            ]
            AssessmentResponse.objects.bulk_create(responses)

            # Create in-app notification for assigned employee
            Notification.objects.create(
                user=assessment.assigned_to,
                organization=org,
                title="New Assessment Assigned",
                message=f"You have been assigned to complete '{assessment.title}'.",
                category='ASSESSMENT',
                link_url=f"/assessments/{assessment.pk}/wizard/"
            )

            log_audit_event(
                request=self.request,
                action='ASSESSMENT_ASSIGNED',
                organization=org,
                actor=self.request.user,
                details=f"Assigned assessment '{assessment.title}' to {assessment.assigned_to.email}"
            )

        messages.success(self.request, f"Assessment '{assessment.title}' initiated with {len(items)} security controls.")
        return redirect('assessments:assessment_detail', pk=assessment.pk)

class AssessmentWizardView(LoginRequiredMixin, View):
    """
    Interactive Checklist Responder supporting Draft-Saving and Final Submission.
    """
    def get(self, request, pk):
        org = request.active_organization
        assessment = get_object_or_404(Assessment, pk=pk, organization=org)

        # Authorization: assigned user, analyst, or org admin
        if assessment.assigned_to != request.user and request.user_role not in [ROLE_ORG_ADMIN, ROLE_SECURITY_ANALYST, ROLE_SUPER_ADMIN]:
            messages.error(request, "You are not authorized to edit this assessment.")
            return redirect('assessments:assessment_list')

        responses = assessment.responses.select_related('item', 'item__category').order_by('item__category__order', 'item__order')

        # Group by category
        categories = {}
        for resp in responses:
            cat = resp.item.category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(resp)

        return render(request, 'assessments/assessment_wizard.html', {
            'assessment': assessment,
            'grouped_responses': categories,
            'response_choices': ResponseChoices.choices,
        })

    def post(self, request, pk):
        org = request.active_organization
        assessment = get_object_or_404(Assessment, pk=pk, organization=org)

        action = request.POST.get('action', 'save_draft')

        with transaction.atomic():
            responses = assessment.responses.select_related('item')
            unanswered_required = []

            for resp in responses:
                field_name = f"resp_{resp.id}"
                notes_name = f"notes_{resp.id}"
                evidence_name = f"evidence_{resp.id}"

                val = request.POST.get(field_name)
                if val:
                    resp.response = val
                resp.notes = request.POST.get(notes_name, '')
                resp.evidence_reference = request.POST.get(evidence_name, '')
                resp.save(update_fields=['response', 'notes', 'evidence_reference'])

                if action == 'submit' and resp.item.is_required and resp.response == ResponseChoices.NOT_ASSESSED:
                    unanswered_required.append(resp.item.control_code)

            if action == 'submit':
                if unanswered_required:
                    messages.error(
                        request,
                        f"Please provide answers for all mandatory controls before final submission. Missing: {', '.join(unanswered_required[:5])}..."
                    )
                    return redirect('assessments:assessment_wizard', pk=assessment.pk)

                # Compute Score & Risk
                score_data = calculate_assessment_score(assessment)
                assessment.score = score_data['overall_score']
                assessment.risk_level = score_data['risk_level']
                assessment.status = AssessmentStatus.SUBMITTED
                assessment.submitted_at = timezone.now()
                assessment.save(update_fields=['score', 'risk_level', 'status', 'submitted_at'])

                # Log audit event
                log_audit_event(
                    request=request,
                    action='ASSESSMENT_SUBMITTED',
                    organization=org,
                    actor=request.user,
                    details=f"Assessment submitted with Posture Score {assessment.score}% ({assessment.risk_level})"
                )

                # Notify reviewer / admins
                if assessment.reviewer:
                    Notification.objects.create(
                        user=assessment.reviewer,
                        organization=org,
                        title="Assessment Submitted for Review",
                        message=f"{request.user.full_name} submitted '{assessment.title}'.",
                        category='ASSESSMENT',
                        link_url=f"/assessments/{assessment.pk}/"
                    )

                messages.success(request, f"Assessment successfully submitted! Calculated Posture Score: {assessment.score}%.")
                return redirect('assessments:assessment_detail', pk=assessment.pk)

            else:
                # Save Draft
                messages.info(request, "Draft progress saved securely.")
                return redirect('assessments:assessment_wizard', pk=assessment.pk)

class AssessmentDetailView(LoginRequiredMixin, DetailView):
    model = Assessment
    template_name = 'assessments/assessment_detail.html'
    context_object_name = 'assessment'

    def get_queryset(self):
        org = self.request.active_organization
        return Assessment.objects.filter(organization=org)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        assessment = self.get_object()
        score_data = calculate_assessment_score(assessment)
        context['score_data'] = score_data
        context['category_breakdown'] = score_data['category_breakdown']
        context['findings'] = assessment.responses.filter(
            response=ResponseChoices.NEEDS_IMPROVEMENT
        ).select_related('item', 'item__category')
        return context

class CompleteAssessmentReviewView(LoginRequiredMixin, RoleRequiredMixin, View):
    allowed_roles = [ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_SECURITY_ANALYST]

    def post(self, request, pk):
        org = request.active_organization
        assessment = get_object_or_404(Assessment, pk=pk, organization=org)
        feedback = request.POST.get('reviewer_feedback', '')

        score_data = calculate_assessment_score(assessment)
        assessment.score = score_data['overall_score']
        assessment.risk_level = score_data['risk_level']
        assessment.status = AssessmentStatus.COMPLETED
        assessment.completed_at = timezone.now()
        assessment.reviewer_feedback = feedback
        assessment.reviewer = request.user
        assessment.save()

        log_audit_event(
            request=request,
            action='ASSESSMENT_COMPLETED',
            organization=org,
            actor=request.user,
            details=f"Completed verification of assessment '{assessment.title}'. Final Score: {assessment.score}%"
        )

        Notification.objects.create(
            user=assessment.assigned_to,
            organization=org,
            title="Assessment Review Completed",
            message=f"Review completed for '{assessment.title}'. Final Score: {assessment.score}%.",
            category='ASSESSMENT',
            link_url=f"/assessments/{assessment.pk}/"
        )

        messages.success(request, f"Assessment finalized with status Completed and Posture Score {assessment.score}%.")
        return redirect('assessments:assessment_detail', pk=assessment.pk)

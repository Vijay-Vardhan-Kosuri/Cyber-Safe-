from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import ListView, DetailView, CreateView, View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.db.models import Q
from .models import ChecklistTemplate, ChecklistItem, ChecklistCategory, TemplateStatus
from .forms import ChecklistTemplateForm, ChecklistItemForm
from apps.organizations.permissions import RoleRequiredMixin, ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_SECURITY_ANALYST
from apps.audit.services import log_audit_event

class TemplateListView(LoginRequiredMixin, ListView):
    model = ChecklistTemplate
    template_name = 'checklists/template_list.html'
    context_object_name = 'templates'

    def get_queryset(self):
        user = self.request.user
        org = getattr(self.request, 'active_organization', None)

        if user.is_platform_admin or user.is_superuser:
            return ChecklistTemplate.objects.all()

        query = Q(is_global=True, status=TemplateStatus.PUBLISHED)
        if org:
            query |= Q(organization=org)
        return ChecklistTemplate.objects.filter(query).distinct()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['categories'] = ChecklistCategory.objects.all()
        return context

class TemplateDetailView(LoginRequiredMixin, DetailView):
    model = ChecklistTemplate
    template_name = 'checklists/template_detail.html'
    context_object_name = 'template'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        template = self.get_object()
        items = template.items.select_related('category').order_by('category__order', 'order')

        # Group items by category for structured review
        grouped_items = {}
        for item in items:
            cat = item.category
            if cat not in grouped_items:
                grouped_items[cat] = []
            grouped_items[cat].append(item)

        context['grouped_items'] = grouped_items
        context['item_form'] = ChecklistItemForm()
        return context

class TemplateCreateView(LoginRequiredMixin, RoleRequiredMixin, CreateView):
    model = ChecklistTemplate
    form_class = ChecklistTemplateForm
    template_name = 'checklists/template_create.html'
    allowed_roles = [ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN]

    def form_valid(self, form):
        template = form.save(commit=False)
        template.created_by = self.request.user
        if self.request.user.is_platform_admin:
            template.is_global = True
            template.organization = None
        else:
            template.is_global = False
            template.organization = self.request.active_organization

        template.status = TemplateStatus.PUBLISHED
        template.save()

        log_audit_event(
            request=self.request,
            action='CHECKLIST_CREATED',
            organization=template.organization,
            actor=self.request.user,
            details=f"Created checklist template: {template.title} v{template.version}"
        )
        messages.success(self.request, f"Checklist template '{template.title}' created successfully.")
        return redirect('checklists:template_detail', pk=template.pk)

class AddItemToTemplateView(LoginRequiredMixin, RoleRequiredMixin, View):
    allowed_roles = [ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN]

    def post(self, request, pk):
        template = get_object_or_404(ChecklistTemplate, pk=pk)
        form = ChecklistItemForm(request.POST)
        if form.is_valid():
            item = form.save(commit=False)
            item.template = template
            item.save()
            messages.success(request, f"Control [{item.control_code}] added to template.")
        else:
            messages.error(request, "Failed to add control. Check control code uniqueness and required fields.")
        return redirect('checklists:template_detail', pk=template.pk)

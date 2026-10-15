from django.shortcuts import render
from django.views.generic import TemplateView

class LandingPageView(TemplateView):
    template_name = 'landing.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        try:
            from apps.organizations.models import Organization
            from apps.checklists.models import ChecklistTemplate, ChecklistCategory
            context['org_count'] = Organization.objects.filter(is_active=True).count()
            context['category_count'] = ChecklistCategory.objects.count()
            context['template_count'] = ChecklistTemplate.objects.filter(status='PUBLISHED').count()
        except Exception:
            context['org_count'] = 2
            context['category_count'] = 10
            context['template_count'] = 3
        return context

class PostureDisclaimerView(TemplateView):
    template_name = 'disclaimer.html'

def custom_403_view(request, exception=None):
    return render(request, 'errors/403.html', {'message': str(exception) if exception else None}, status=403)

def custom_404_view(request, exception=None):
    return render(request, 'errors/404.html', status=404)

def custom_500_view(request):
    return render(request, 'errors/500.html', status=500)

def csrf_failure(request, reason=""):
    return render(request, 'errors/403.html', {'message': f'Security token verification failed: {reason}'}, status=403)

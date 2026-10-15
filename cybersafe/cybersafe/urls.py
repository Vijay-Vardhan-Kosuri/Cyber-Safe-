from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('apps.core.urls')),
    path('accounts/', include('apps.accounts.urls')),
    path('organizations/', include('apps.organizations.urls')),
    path('checklists/', include('apps.checklists.urls')),
    path('assessments/', include('apps.assessments.urls')),
    path('remediation/', include('apps.remediation.urls')),
    path('notifications/', include('apps.notifications.urls')),
    path('analytics/', include('apps.analytics.urls')),
    path('audit/', include('apps.audit.urls')),
]

handler403 = 'apps.core.views.custom_403_view'
handler404 = 'apps.core.views.custom_404_view'
handler500 = 'apps.core.views.custom_500_view'

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

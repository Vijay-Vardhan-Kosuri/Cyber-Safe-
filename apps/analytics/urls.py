from django.urls import path
from .views import AnalyticsOverviewView, AssessmentCSVExportView, RemediationCSVExportView

app_name = 'analytics'

urlpatterns = [
    path('', AnalyticsOverviewView.as_view(), name='overview'),
    path('export/assessment/<int:pk>/', AssessmentCSVExportView.as_view(), name='export_assessment_csv'),
    path('export/remediation/', RemediationCSVExportView.as_view(), name='export_remediation_csv'),
]

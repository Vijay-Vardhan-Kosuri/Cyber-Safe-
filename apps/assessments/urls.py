from django.urls import path
from .views import (
    AssessmentListView, AssessmentCreateView, AssessmentWizardView,
    AssessmentDetailView, CompleteAssessmentReviewView
)

app_name = 'assessments'

urlpatterns = [
    path('', AssessmentListView.as_view(), name='assessment_list'),
    path('new/', AssessmentCreateView.as_view(), name='assessment_create'),
    path('<int:pk>/', AssessmentDetailView.as_view(), name='assessment_detail'),
    path('<int:pk>/wizard/', AssessmentWizardView.as_view(), name='assessment_wizard'),
    path('<int:pk>/review/', CompleteAssessmentReviewView.as_view(), name='assessment_review'),
]

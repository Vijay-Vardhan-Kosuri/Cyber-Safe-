from django.urls import path
from .views import (
    TaskListView, TaskDetailView, TaskCreateFromFindingView,
    TaskStartView, TaskSubmitForReviewView, TaskVerifyReviewView
)

app_name = 'remediation'

urlpatterns = [
    path('', TaskListView.as_view(), name='task_list'),
    path('tasks/<int:pk>/', TaskDetailView.as_view(), name='task_detail'),
    path('create-from-finding/<int:finding_id>/', TaskCreateFromFindingView.as_view(), name='create_from_finding'),
    path('tasks/<int:pk>/start/', TaskStartView.as_view(), name='task_start'),
    path('tasks/<int:pk>/submit/', TaskSubmitForReviewView.as_view(), name='task_submit'),
    path('tasks/<int:pk>/verify/', TaskVerifyReviewView.as_view(), name='task_verify'),
]

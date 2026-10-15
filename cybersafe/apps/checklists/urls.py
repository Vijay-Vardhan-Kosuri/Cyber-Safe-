from django.urls import path
from .views import TemplateListView, TemplateDetailView, TemplateCreateView, AddItemToTemplateView

app_name = 'checklists'

urlpatterns = [
    path('', TemplateListView.as_view(), name='template_list'),
    path('new/', TemplateCreateView.as_view(), name='template_create'),
    path('<int:pk>/', TemplateDetailView.as_view(), name='template_detail'),
    path('<int:pk>/add-item/', AddItemToTemplateView.as_view(), name='add_item'),
]

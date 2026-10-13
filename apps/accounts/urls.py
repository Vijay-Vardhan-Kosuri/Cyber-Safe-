from django.urls import path
from .views import CustomLoginView, CustomLogoutView, DashboardRedirectView, ProfileView

app_name = 'accounts'

urlpatterns = [
    path('login/', CustomLoginView.as_view(), name='login'),
    path('logout/', CustomLogoutView.as_view(), name='logout'),
    path('redirect/', DashboardRedirectView.as_view(), name='dashboard_redirect'),
    path('profile/', ProfileView.as_view(), name='profile'),
]

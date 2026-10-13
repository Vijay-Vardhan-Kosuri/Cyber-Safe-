from django.urls import path
from .views import LandingPageView, PostureDisclaimerView

app_name = 'core'

urlpatterns = [
    path('', LandingPageView.as_view(), name='landing'),
    path('disclaimer/', PostureDisclaimerView.as_view(), name='disclaimer'),
]

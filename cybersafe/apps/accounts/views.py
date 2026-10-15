from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.views import LoginView, LogoutView
from django.views.generic import View, UpdateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.urls import reverse_lazy, reverse
from django.utils import timezone
from datetime import timedelta
from .forms import UserLoginForm, UserProfileForm, UserRegistrationForm
from apps.audit.services import log_audit_event
from django.contrib.auth import get_user_model

User = get_user_model()

class CustomLoginView(LoginView):
    form_class = UserLoginForm
    template_name = 'accounts/login.html'
    redirect_authenticated_user = True

    def form_valid(self, form):
        user = form.get_user()
        if user.is_locked():
            messages.error(self.request, "Account is temporarily locked due to multiple failed login attempts. Please try again later.")
            return self.form_invalid(form)

        user.failed_login_attempts = 0
        user.locked_until = None
        user.save(update_fields=['failed_login_attempts', 'locked_until'])

        login(self.request, user)
        log_audit_event(
            request=self.request,
            action='LOGIN_SUCCESS',
            actor=user,
            details=f"User logged in from {self.request.META.get('REMOTE_ADDR')}"
        )
        messages.success(self.request, f"Welcome back, {user.full_name}!")
        return redirect('accounts:dashboard_redirect')

    def form_invalid(self, form):
        email = form.data.get('username')
        if email:
            try:
                user = User.objects.get(email=email)
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = timezone.now() + timedelta(minutes=15)
                user.save(update_fields=['failed_login_attempts', 'locked_until'])
                log_audit_event(
                    request=self.request,
                    action='LOGIN_FAILED',
                    actor=user,
                    details=f"Failed login attempt {user.failed_login_attempts}"
                )
            except User.DoesNotExist:
                pass
        messages.error(self.request, "Invalid email address or password.")
        return super().form_invalid(form)

class CustomLogoutView(View):
    def get(self, request):
        if request.user.is_authenticated:
            log_audit_event(
                request=request,
                action='LOGOUT',
                actor=request.user,
                details="User logged out gracefully."
            )
            logout(request)
            messages.info(request, "You have been logged out securely.")
        return redirect('core:landing')

    def post(self, request):
        return self.get(request)

class DashboardRedirectView(LoginRequiredMixin, View):
    def get(self, request):
        user = request.user
        if user.is_platform_admin or user.is_superuser:
            return redirect('organizations:superadmin_dashboard')

        active_membership = getattr(request, 'active_membership', None)
        if not active_membership:
            from apps.organizations.models import Membership
            active_membership = Membership.objects.filter(user=user, status='ACTIVE').first()

        if active_membership:
            role = active_membership.role
            if role == 'SUPER_ADMIN':
                return redirect('organizations:superadmin_dashboard')
            elif role == 'ORG_ADMIN':
                return redirect('organizations:orgadmin_dashboard')
            elif role == 'SECURITY_ANALYST':
                return redirect('organizations:analyst_dashboard')
            else:
                return redirect('organizations:employee_dashboard')

        # If user has no organization memberships, show profile
        messages.info(request, "You are currently not associated with an active organization. Please accept an invitation or contact your administrator.")
        return redirect('accounts:profile')

class ProfileView(LoginRequiredMixin, UpdateView):
    model = User
    form_class = UserProfileForm
    template_name = 'accounts/profile.html'
    success_url = reverse_lazy('accounts:profile')

    def get_object(self, queryset=None):
        return self.request.user

    def form_valid(self, form):
        messages.success(self.request, "Your profile has been updated.")
        log_audit_event(
            request=self.request,
            action='PROFILE_UPDATED',
            actor=self.request.user,
            details="User updated personal profile."
        )
        return super().form_valid(form)

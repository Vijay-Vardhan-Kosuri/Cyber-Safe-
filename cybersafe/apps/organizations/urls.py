from django.urls import path
from .views import (
    SuperAdminDashboardView, OrgAdminDashboardView, AnalystDashboardView, EmployeeDashboardView,
    InviteMemberView, AcceptInvitationView, MemberListView, SwitchOrganizationView,
    ToggleMemberStatusView, PolicyListView, PolicyCreateView
)

app_name = 'organizations'

urlpatterns = [
    # Dashboards
    path('dashboard/superadmin/', SuperAdminDashboardView.as_view(), name='superadmin_dashboard'),
    path('dashboard/orgadmin/', OrgAdminDashboardView.as_view(), name='orgadmin_dashboard'),
    path('dashboard/analyst/', AnalystDashboardView.as_view(), name='analyst_dashboard'),
    path('dashboard/employee/', EmployeeDashboardView.as_view(), name='employee_dashboard'),

    # Members & Invitations
    path('members/', MemberListView.as_view(), name='member_list'),
    path('invite/', InviteMemberView.as_view(), name='invite_member'),
    path('invite/accept/<uuid:token>/', AcceptInvitationView.as_view(), name='accept_invitation'),
    path('members/<int:membership_id>/toggle-status/', ToggleMemberStatusView.as_view(), name='toggle_member_status'),
    path('switch/<int:org_id>/', SwitchOrganizationView.as_view(), name='switch_organization'),

    # Policies
    path('policies/', PolicyListView.as_view(), name='policy_list'),
    path('policies/create/', PolicyCreateView.as_view(), name='policy_create'),
]

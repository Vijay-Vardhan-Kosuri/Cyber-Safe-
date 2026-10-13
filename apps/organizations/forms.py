from django import forms
from django.contrib.auth import get_user_model
from .models import Organization, OrganizationInvitation, RoleChoices, SecurityPolicy

User = get_user_model()

class OrganizationCreateForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = ['name', 'domain', 'industry', 'description', 'max_members']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control form-control-dark', 'placeholder': 'e.g. Apex Financial Corp'}),
            'domain': forms.TextInput(attrs={'class': 'form-control form-control-dark', 'placeholder': 'e.g. apexfinancial.com'}),
            'industry': forms.TextInput(attrs={'class': 'form-control form-control-dark', 'placeholder': 'e.g. Financial Services & Banking'}),
            'description': forms.Textarea(attrs={'class': 'form-control form-control-dark', 'rows': 3}),
            'max_members': forms.NumberInput(attrs={'class': 'form-control form-control-dark', 'min': 1}),
        }

class InviteMemberForm(forms.ModelForm):
    role = forms.ChoiceField(
        choices=[
            (RoleChoices.ORG_ADMIN.value, 'Organization Admin'),
            (RoleChoices.SECURITY_ANALYST.value, 'Security Analyst'),
            (RoleChoices.EMPLOYEE.value, 'Employee / Member'),
        ],
        widget=forms.Select(attrs={'class': 'form-select form-select-dark'})
    )

    class Meta:
        model = OrganizationInvitation
        fields = ['email', 'role', 'department']
        widgets = {
            'email': forms.EmailInput(attrs={'class': 'form-control form-control-dark', 'placeholder': 'colleague@organization.com'}),
            'department': forms.TextInput(attrs={'class': 'form-control form-control-dark', 'placeholder': 'e.g. Cloud Infrastructure, Security'}),
        }

class AcceptInvitationForm(forms.Form):
    first_name = forms.CharField(max_length=50, widget=forms.TextInput(attrs={'class': 'form-control form-control-dark'}))
    last_name = forms.CharField(max_length=50, widget=forms.TextInput(attrs={'class': 'form-control form-control-dark'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control form-control-dark', 'placeholder': 'Create strong password'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control form-control-dark', 'placeholder': 'Repeat password'}))

    def clean(self):
        cleaned_data = super().clean()
        p1 = cleaned_data.get('password')
        p2 = cleaned_data.get('confirm_password')
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("Passwords do not match.")
        if p1 and len(p1) < 8:
            raise forms.ValidationError("Password must be at least 8 characters long.")
        return cleaned_data

class SecurityPolicyForm(forms.ModelForm):
    class Meta:
        model = SecurityPolicy
        fields = ['title', 'version', 'category', 'content', 'is_mandatory']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control form-control-dark'}),
            'version': forms.TextInput(attrs={'class': 'form-control form-control-dark'}),
            'category': forms.TextInput(attrs={'class': 'form-control form-control-dark'}),
            'content': forms.Textarea(attrs={'class': 'form-control form-control-dark', 'rows': 6}),
            'is_mandatory': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

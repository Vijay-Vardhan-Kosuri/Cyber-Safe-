from django import forms
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import RemediationTask, TaskEvidence, TaskPriority

User = get_user_model()

class RemediationTaskCreateForm(forms.ModelForm):
    assigned_to = forms.ModelChoiceField(
        queryset=User.objects.none(),
        widget=forms.Select(attrs={'class': 'form-select form-select-dark'})
    )
    due_date = forms.DateField(
        widget=forms.DateInput(attrs={'class': 'form-control form-control-dark', 'type': 'date'}),
        initial=lambda: timezone.now().date() + timezone.timedelta(days=14)
    )

    class Meta:
        model = RemediationTask
        fields = ['title', 'description', 'assigned_to', 'priority', 'due_date']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control form-control-dark'}),
            'description': forms.Textarea(attrs={'class': 'form-control form-control-dark', 'rows': 4}),
            'priority': forms.Select(attrs={'class': 'form-select form-select-dark'}),
        }

    def __init__(self, *args, **kwargs):
        org = kwargs.pop('organization', None)
        super().__init__(*args, **kwargs)
        if org:
            self.fields['assigned_to'].queryset = User.objects.filter(
                memberships__organization=org,
                memberships__status='ACTIVE'
            )

class TaskSubmissionForm(forms.Form):
    resolution_notes = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control form-control-dark',
            'rows': 4,
            'placeholder': 'Describe how this cybersecurity practice was implemented...'
        }),
        required=True
    )
    attachment_reference = forms.CharField(
        max_length=255,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-dark',
            'placeholder': 'e.g. Screenshot-MFA-Enabled.png, IAM Audit Log #4429'
        })
    )
    external_url = forms.URLField(
        required=False,
        widget=forms.URLInput(attrs={
            'class': 'form-control form-control-dark',
            'placeholder': 'https://github.com/org/repo/pull/123 or Jira link'
        })
    )

class TaskVerificationForm(forms.Form):
    action = forms.ChoiceField(
        choices=[('verify', 'Verify & Close Task'), ('return', 'Return with Feedback')],
        widget=forms.RadioSelect(attrs={'class': 'form-check-input'})
    )
    feedback = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control form-control-dark',
            'rows': 3,
            'placeholder': 'Provide verification approval notes or explanation for returning...'
        }),
        required=True
    )

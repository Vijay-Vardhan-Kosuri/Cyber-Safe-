from django import forms
from django.contrib.auth import get_user_model
from .models import Assessment
from apps.checklists.models import ChecklistTemplate

User = get_user_model()

class AssessmentCreateForm(forms.ModelForm):
    template = forms.ModelChoiceField(
        queryset=ChecklistTemplate.objects.filter(status='PUBLISHED'),
        widget=forms.Select(attrs={'class': 'form-select form-select-dark'})
    )
    assigned_to = forms.ModelChoiceField(
        queryset=User.objects.none(),
        widget=forms.Select(attrs={'class': 'form-select form-select-dark'})
    )

    class Meta:
        model = Assessment
        fields = ['title', 'template', 'assigned_to', 'notes']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control form-control-dark', 'placeholder': 'e.g. Q4 Baseline Cybersecurity Assessment'}),
            'notes': forms.Textarea(attrs={'class': 'form-control form-control-dark', 'rows': 3, 'placeholder': 'Optional context or scope remarks'}),
        }

    def __init__(self, *args, **kwargs):
        org = kwargs.pop('organization', None)
        super().__init__(*args, **kwargs)
        if org:
            self.fields['assigned_to'].queryset = User.objects.filter(memberships__organization=org, memberships__status='ACTIVE')

from django import forms
from .models import ChecklistTemplate, ChecklistItem, ChecklistCategory

class ChecklistTemplateForm(forms.ModelForm):
    class Meta:
        model = ChecklistTemplate
        fields = ['title', 'version', 'description', 'audience']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control form-control-dark', 'placeholder': 'e.g. Comprehensive Endpoint & Identity Review'}),
            'version': forms.TextInput(attrs={'class': 'form-control form-control-dark', 'placeholder': '1.0'}),
            'description': forms.Textarea(attrs={'class': 'form-control form-control-dark', 'rows': 4}),
            'audience': forms.Select(attrs={'class': 'form-select form-select-dark'}),
        }

class ChecklistItemForm(forms.ModelForm):
    class Meta:
        model = ChecklistItem
        fields = ['category', 'control_code', 'title', 'description', 'guidance', 'priority', 'is_required']
        widgets = {
            'category': forms.Select(attrs={'class': 'form-select form-select-dark'}),
            'control_code': forms.TextInput(attrs={'class': 'form-control form-control-dark', 'placeholder': 'e.g. NET-04'}),
            'title': forms.TextInput(attrs={'class': 'form-control form-control-dark'}),
            'description': forms.Textarea(attrs={'class': 'form-control form-control-dark', 'rows': 3}),
            'guidance': forms.Textarea(attrs={'class': 'form-control form-control-dark', 'rows': 3}),
            'priority': forms.Select(attrs={'class': 'form-select form-select-dark'}),
            'is_required': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

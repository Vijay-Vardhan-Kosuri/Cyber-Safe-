from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model

User = get_user_model()

class UserLoginForm(AuthenticationForm):
    username = forms.EmailField(
        label="Email Address",
        widget=forms.EmailInput(attrs={
            'class': 'form-control form-control-dark',
            'placeholder': 'name@organization.com',
            'autocomplete': 'email'
        })
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control form-control-dark',
            'placeholder': '••••••••',
            'autocomplete': 'current-password'
        })
    )

class UserRegistrationForm(UserCreationForm):
    first_name = forms.CharField(max_length=50, required=True, widget=forms.TextInput(attrs={'class': 'form-control form-control-dark'}))
    last_name = forms.CharField(max_length=50, required=True, widget=forms.TextInput(attrs={'class': 'form-control form-control-dark'}))
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'class': 'form-control form-control-dark'}))
    job_title = forms.CharField(max_length=100, required=False, widget=forms.TextInput(attrs={'class': 'form-control form-control-dark'}))

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'job_title')

    def clean_email(self):
        email = self.cleaned_data.get('email').lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("An account with this email address already exists.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.username = self.cleaned_data['email']
        if commit:
            user.save()
        return user

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'job_title', 'phone']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control form-control-dark'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control form-control-dark'}),
            'job_title': forms.TextInput(attrs={'class': 'form-control form-control-dark'}),
            'phone': forms.TextInput(attrs={'class': 'form-control form-control-dark'}),
        }

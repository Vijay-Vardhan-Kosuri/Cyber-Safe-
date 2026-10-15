from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

class User(AbstractUser):
    email = models.EmailField(unique=True, verbose_name="Email Address")
    job_title = models.CharField(max_length=120, blank=True, verbose_name="Job Title")
    phone = models.CharField(max_length=30, blank=True, verbose_name="Phone Number")
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    is_platform_admin = models.BooleanField(
        default=False,
        help_text="Designates platform-level super administrator status."
    )
    failed_login_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        ordering = ['-date_joined']

    @property
    def full_name(self):
        name = f"{self.first_name} {self.last_name}".strip()
        return name if name else self.username

    @property
    def initials(self):
        parts = self.full_name.split()
        if len(parts) >= 2:
            return f"{parts[0][0]}{parts[1][0]}".upper()
        return self.username[:2].upper()

    def is_locked(self):
        if self.locked_until and self.locked_until > timezone.now():
            return True
        return False

    def __str__(self):
        return f"{self.full_name} ({self.email})"

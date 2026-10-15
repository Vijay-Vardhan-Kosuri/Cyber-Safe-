from django.test import TestCase
from django.contrib.auth import get_user_model
from apps.organizations.models import Organization, Membership, RoleChoices
from apps.checklists.models import ChecklistCategory, ChecklistTemplate, ChecklistItem, PriorityChoices
from apps.assessments.models import Assessment, AssessmentResponse, ResponseChoices, RiskLevel
from apps.assessments.scoring_service import calculate_assessment_score

User = get_user_model()

class AssessmentScoringTestCase(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name='Scoring Test Org', slug='scoring-org')
        self.user = User.objects.create_user(email='eval@org.com', username='eval@org.com', password='Pass123!')
        Membership.objects.create(user=self.user, organization=self.org, role=RoleChoices.EMPLOYEE)

        self.cat = ChecklistCategory.objects.create(name='Identity', weight=1.0)
        self.tmpl = ChecklistTemplate.objects.create(title='Framework 1', is_global=True)

        self.item1 = ChecklistItem.objects.create(
            template=self.tmpl, category=self.cat, control_code='I-01', title='Password Policy',
            priority=PriorityChoices.MEDIUM, is_required=True
        )
        self.item2 = ChecklistItem.objects.create(
            template=self.tmpl, category=self.cat, control_code='I-02', title='MFA',
            priority=PriorityChoices.CRITICAL, is_required=True
        )
        self.item3 = ChecklistItem.objects.create(
            template=self.tmpl, category=self.cat, control_code='I-03', title='Legacy Token',
            priority=PriorityChoices.LOW, is_required=False
        )

        self.assessment = Assessment.objects.create(
            organization=self.org,
            template=self.tmpl,
            title='Q1 Evaluation',
            assigned_to=self.user
        )

    def test_scoring_formula_calculation(self):
        AssessmentResponse.objects.create(assessment=self.assessment, item=self.item1, response=ResponseChoices.COMPLIANT)
        AssessmentResponse.objects.create(assessment=self.assessment, item=self.item2, response=ResponseChoices.NEEDS_IMPROVEMENT)
        AssessmentResponse.objects.create(assessment=self.assessment, item=self.item3, response=ResponseChoices.NOT_APPLICABLE)

        result = calculate_assessment_score(self.assessment)
        self.assertEqual(result['overall_score'], 33.3)
        self.assertEqual(result['risk_level'], RiskLevel.HIGH)

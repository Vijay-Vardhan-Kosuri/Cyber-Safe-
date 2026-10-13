import uuid
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import transaction

from apps.organizations.models import Organization, Membership, RoleChoices, MembershipStatus, SecurityPolicy, OrganizationInvitation
from apps.checklists.models import ChecklistCategory, ChecklistTemplate, ChecklistItem, TemplateStatus, TargetAudience, PriorityChoices
from apps.assessments.models import Assessment, AssessmentResponse, AssessmentStatus, ResponseChoices, RiskLevel
from apps.assessments.scoring_service import calculate_assessment_score
from apps.remediation.models import RemediationTask, TaskEvidence, TaskStatus, TaskPriority
from apps.notifications.models import Notification, NotificationCategory
from apps.audit.models import AuditEvent

User = get_user_model()

class Command(BaseCommand):
    help = "Seeds comprehensive synthetic demo data for CyberSafe platform demonstration."

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE("Initiating CyberSafe comprehensive database seeding..."))

        with transaction.atomic():
            # 1. Create Super Admin
            superadmin, created = User.objects.get_or_create(
                email="superadmin@cybersafe.local",
                defaults={
                    'username': "superadmin@cybersafe.local",
                    'first_name': "Platform",
                    'last_name': "SuperAdmin",
                    'job_title': "Principal Cybersecurity Architect",
                    'is_platform_admin': True,
                    'is_staff': True,
                    'is_superuser': True,
                }
            )
            superadmin.set_password("AdminPass123!")
            superadmin.save()
            self.stdout.write(self.style.SUCCESS(f"Platform Super Admin: {superadmin.email} (Password: AdminPass123!)"))

            # 2. Create Organizations
            org_apex, _ = Organization.objects.get_or_create(
                name="Apex Financial Group",
                defaults={
                    'domain': "apexfin.com",
                    'industry': "Financial Services & Asset Management",
                    'description': "Multi-national institutional wealth management platform requiring SOC2 and ISO 27001 posture adherence.",
                    'is_active': True,
                    'max_members': 150
                }
            )

            org_vanguard, _ = Organization.objects.get_or_create(
                name="Vanguard Healthcare Systems",
                defaults={
                    'domain': "vanguardhealth.com",
                    'industry': "Healthcare & Hospital Informatics",
                    'description': "Regional healthcare provider network subject to HIPAA, HITECH, and medical telemetry security baselines.",
                    'is_active': True,
                    'max_members': 300
                }
            )

            # 3. Create Users for Apex Financial
            apex_admin, _ = User.objects.get_or_create(
                email="admin@apexfin.com",
                defaults={
                    'username': "admin@apexfin.com",
                    'first_name': "Marcus",
                    'last_name': "Vance",
                    'job_title': "VP of Information Security",
                    'is_staff': False,
                }
            )
            apex_admin.set_password("ApexAdminPass123!")
            apex_admin.save()

            apex_analyst, _ = User.objects.get_or_create(
                email="analyst@apexfin.com",
                defaults={
                    'username': "analyst@apexfin.com",
                    'first_name': "Elena",
                    'last_name': "Rostova",
                    'job_title': "Lead SOC & Posture Analyst",
                    'is_staff': False,
                }
            )
            apex_analyst.set_password("AnalystPass123!")
            apex_analyst.save()

            apex_employee1, _ = User.objects.get_or_create(
                email="alice@apexfin.com",
                defaults={
                    'username': "alice@apexfin.com",
                    'first_name': "Alice",
                    'last_name': "Kowalski",
                    'job_title': "Senior DevOps Engineer",
                    'is_staff': False,
                }
            )
            apex_employee1.set_password("EmployeePass123!")
            apex_employee1.save()

            apex_employee2, _ = User.objects.get_or_create(
                email="bob@apexfin.com",
                defaults={
                    'username': "bob@apexfin.com",
                    'first_name': "Robert",
                    'last_name': "Chen",
                    'job_title': "Database Administrator",
                    'is_staff': False,
                }
            )
            apex_employee2.set_password("EmployeePass123!")
            apex_employee2.save()

            # Vanguard Healthcare Users
            vanguard_admin, _ = User.objects.get_or_create(
                email="admin@vanguardhealth.com",
                defaults={
                    'username': "admin@vanguardhealth.com",
                    'first_name': "Dr. Sarah",
                    'last_name': "O'Connor",
                    'job_title': "Chief Information Security Officer",
                }
            )
            vanguard_admin.set_password("VanguardAdminPass123!")
            vanguard_admin.save()

            vanguard_analyst, _ = User.objects.get_or_create(
                email="analyst@vanguardhealth.com",
                defaults={
                    'username': "analyst@vanguardhealth.com",
                    'first_name': "Liam",
                    'last_name': "Nakamura",
                    'job_title': "Clinical Systems Security Specialist",
                }
            )
            vanguard_analyst.set_password("AnalystPass123!")
            vanguard_analyst.save()

            vanguard_employee, _ = User.objects.get_or_create(
                email="dr.chen@vanguardhealth.com",
                defaults={
                    'username': "dr.chen@vanguardhealth.com",
                    'first_name': "Dr. Jonathan",
                    'last_name': "Chen",
                    'job_title': "Head of Diagnostic Telemetry",
                }
            )
            vanguard_employee.set_password("EmployeePass123!")
            vanguard_employee.save()

            # 4. Create Memberships
            # Apex Memberships
            Membership.objects.update_or_create(
                user=apex_admin, organization=org_apex,
                defaults={'role': RoleChoices.ORG_ADMIN, 'status': MembershipStatus.ACTIVE, 'department': 'Executive InfoSec'}
            )
            Membership.objects.update_or_create(
                user=apex_analyst, organization=org_apex,
                defaults={'role': RoleChoices.SECURITY_ANALYST, 'status': MembershipStatus.ACTIVE, 'department': 'SOC Operations'}
            )
            Membership.objects.update_or_create(
                user=apex_employee1, organization=org_apex,
                defaults={'role': RoleChoices.EMPLOYEE, 'status': MembershipStatus.ACTIVE, 'department': 'Cloud Engineering'}
            )
            Membership.objects.update_or_create(
                user=apex_employee2, organization=org_apex,
                defaults={'role': RoleChoices.EMPLOYEE, 'status': MembershipStatus.ACTIVE, 'department': 'Data Infrastructure'}
            )

            # Vanguard Memberships
            Membership.objects.update_or_create(
                user=vanguard_admin, organization=org_vanguard,
                defaults={'role': RoleChoices.ORG_ADMIN, 'status': MembershipStatus.ACTIVE, 'department': 'CISO Office'}
            )
            Membership.objects.update_or_create(
                user=vanguard_analyst, organization=org_vanguard,
                defaults={'role': RoleChoices.SECURITY_ANALYST, 'status': MembershipStatus.ACTIVE, 'department': 'Health IT Security'}
            )
            Membership.objects.update_or_create(
                user=vanguard_employee, organization=org_vanguard,
                defaults={'role': RoleChoices.EMPLOYEE, 'status': MembershipStatus.ACTIVE, 'department': 'Clinical Informatics'}
            )

            # 5. Security Policies
            SecurityPolicy.objects.get_or_create(
                organization=org_apex,
                title="Apex Information Security & Data Classification Standard",
                version="2.4",
                defaults={
                    'category': "Enterprise Governance",
                    'content': "All corporate data must be labeled as Public, Internal, Confidential, or Restricted. Encryption in transit (TLS 1.3) and at rest (AES-256) is mandatory across all cloud VPCs.",
                    'is_mandatory': True,
                    'created_by': apex_admin
                }
            )

            SecurityPolicy.objects.get_or_create(
                organization=org_apex,
                title="Privileged Access & Password Management Policy",
                version="3.1",
                defaults={
                    'category': "Identity & Access Management",
                    'content': "All workforce members must utilize centralized enterprise SSO with hardware-backed MFA. Passwords must exceed 16 characters or 4 random diceware passphrases. Credential sharing is strictly prohibited.",
                    'is_mandatory': True,
                    'created_by': apex_admin
                }
            )

            # 6. Sample Pending Invitations
            OrganizationInvitation.objects.get_or_create(
                organization=org_apex,
                email="newhire.secops@apexfin.com",
                defaults={
                    'role': RoleChoices.EMPLOYEE,
                    'department': "FinTech Operations",
                    'invited_by': apex_admin,
                    'expires_at': timezone.now() + timedelta(days=5),
                    'is_revoked': False
                }
            )

            # 7. 10 CIS/NIST Checklist Categories
            categories_data = [
                ("Identity and Password Security", "IAM", "bi-key-fill", 1.5, 1, "Password complexity, password managers, and identity governance."),
                ("Multi-Factor Authentication (MFA)", "MFA", "bi-phone-vibrate-fill", 1.8, 2, "Hardware tokens, authenticator apps, and SSO MFA enforcement."),
                ("Email and Phishing Defense", "PHISH", "bi-envelope-exclamation-fill", 1.4, 3, "SPF/DKIM/DMARC, inbound sandboxing, and phishing simulations."),
                ("Software Updates & Patch Management", "PATCH", "bi-arrow-repeat", 1.5, 4, "Operating system patching, zero-day mitigation, and 3rd-party dependencies."),
                ("Device & Endpoint Security", "ENDPT", "bi-laptop-fill", 1.3, 5, "EDR agents, disk encryption, screen timeouts, and peripheral control."),
                ("Data Backup & Disaster Recovery", "BCDR", "bi-database-fill-check", 1.6, 6, "3-2-1 immutable backup rules, restoration drills, and offsite storage."),
                ("Data Protection & Access Control", "DATA", "bi-file-earmark-lock2-fill", 1.5, 7, "Least-privilege access, DLP controls, and database encryption."),
                ("Network Security & Perimeter Defense", "NET", "bi-hdd-network-fill", 1.4, 8, "Firewall rules, network segmentation, VPN/Zero-Trust, and Wi-Fi WPA3."),
                ("Incident Reporting & Response", "IR", "bi-shield-shaded", 1.5, 9, "Incident escalation paths, tabletop drills, and forensics readiness."),
                ("Employee Cybersecurity Training", "TRAIN", "bi-mortarboard-fill", 1.2, 10, "Continuous awareness training, social engineering, and security culture.")
            ]

            category_map = {}
            for name, slug, icon, weight, order, desc in categories_data:
                cat, _ = ChecklistCategory.objects.get_or_create(
                    name=name,
                    defaults={'slug': slug.lower(), 'icon': icon, 'weight': weight, 'order': order, 'description': desc}
                )
                category_map[slug] = cat

            # 8. Global Template v1.0
            template, _ = ChecklistTemplate.objects.get_or_create(
                title="CyberSafe Comprehensive Posture Assessment Framework",
                version="1.0",
                defaults={
                    'description': "Standard baseline covering CIS Controls v8 and NIST CSF 2.0 recommendations tailored for modern hybrid-cloud environments.",
                    'is_global': True,
                    'status': TemplateStatus.PUBLISHED,
                    'audience': TargetAudience.ALL,
                    'created_by': superadmin
                }
            )

            # 9. 35+ Comprehensive Checklist Controls
            controls_data = [
                # Category 1: IAM
                ("IAM-01", "IAM", "Enterprise Password Manager Deployment",
                 "Workforce uses an approved enterprise password vault with master key protection.",
                 "Procure and mandate 1Password/Bitwarden Enterprise; prohibit unmanaged browser password saves.",
                 PriorityChoices.HIGH),
                ("IAM-02", "IAM", "Minimum 16-Character Passphrase Standard",
                 "All accounts adhere to passphrases containing at least 16 characters or 4 random words.",
                 "Configure IdP password policies to reject passphrases under 16 characters.",
                 PriorityChoices.MEDIUM),
                ("IAM-03", "IAM", "Quarterly Privileged Access Review",
                 "Access permissions for root, admin, and domain accounts are audited every 90 days.",
                 "Conduct structured entitlement reviews and revoke obsolete administrative credentials.",
                 PriorityChoices.HIGH),

                # Category 2: MFA
                ("MFA-01", "MFA", "Mandatory MFA on All Cloud Portals & IdP",
                 "Single Sign-On (SSO) and SaaS apps enforce secondary verification for every login.",
                 "Enable conditional access policies requiring MFA for all Microsoft 365 / Google Workspace users.",
                 PriorityChoices.CRITICAL),
                ("MFA-02", "MFA", "FIDO2 / Hardware Security Key for Admins",
                 "Privileged cloud console and infrastructure accounts utilize physical WebAuthn/FIDO2 keys.",
                 "Deploy YubiKey 5 Series tokens and disable SMS/Voice call MFA fallbacks for admins.",
                 PriorityChoices.CRITICAL),
                ("MFA-03", "MFA", "Phishing-Resistant MFA Push Verification",
                 "Push notification authenticators require number matching to eliminate prompt-bombing attacks.",
                 "Turn on number-matching in Microsoft Authenticator or Duo Security configurations.",
                 PriorityChoices.HIGH),

                # Category 3: PHISH
                ("PHISH-01", "PHISH", "DMARC Enforcement (p=reject or quarantine)",
                 "Corporate email domains publish valid SPF, DKIM, and strict DMARC rejection records.",
                 "Audit DNS records via MXToolbox and advance policy from p=none to p=reject.",
                 PriorityChoices.HIGH),
                ("PHISH-02", "PHISH", "External Email Warning Banners",
                 "Inbound emails originating outside the organization display a prominent warning banner.",
                 "Implement mail transport rule tagging external messages with a standardized visual header.",
                 PriorityChoices.LOW),
                ("PHISH-03", "PHISH", "One-Click Suspicious Email Reporting Plugin",
                 "Employees have an integrated button in Outlook/Gmail to submit phishing messages to the SOC.",
                 "Deploy PhishAlarm or native Report Phishing add-in linked to security mailbox.",
                 PriorityChoices.MEDIUM),

                # Category 4: PATCH
                ("PATCH-01", "PATCH", "Automated OS Patching Within 14 Days",
                 "Workstations and server OS receive critical vulnerability patches within 14 calendar days.",
                 "Configure automated patch baselines via Jamf, Intune, or WSUS with reboot enforcement.",
                 PriorityChoices.CRITICAL),
                ("PATCH-02", "PATCH", "Emergency Zero-Day Patching SLA (48 Hours)",
                 "Documented capability and runbook to patch actively exploited CISA KEV flaws within 48 hours.",
                 "Establish out-of-band maintenance procedures for high-severity zero-day CVEs.",
                 PriorityChoices.CRITICAL),
                ("PATCH-03", "PATCH", "Third-Party Application Patching (Chrome, Zoom, Slack)",
                 "Common desktop software vulnerabilities are updated automatically without user intervention.",
                 "Use central endpoint management to enforce background auto-updates for browsers and collaboration tools.",
                 PriorityChoices.HIGH),

                # Category 5: ENDPT
                ("ENDPT-01", "ENDPT", "Full Disk Encryption (BitLocker / FileVault)",
                 "100% of corporate laptops possess hardware-backed AES-256 disk encryption with escrowed keys.",
                 "Enforce BitLocker/FileVault enrollment profiles through MDM; alert on unencrypted drives.",
                 PriorityChoices.CRITICAL),
                ("ENDPT-02", "ENDPT", "Centralized EDR Agent with 24/7 Telemetry",
                 "Endpoint Detection and Response agent (CrowdStrike, Defender for Endpoint) active on all machines.",
                 "Verify agent health status in EDR console; remediate disconnected or disabled sensors.",
                 PriorityChoices.HIGH),
                ("ENDPT-03", "ENDPT", "Screen Lock Timeout (Max 10 Minutes)",
                 "Workstation displays automatically lock after 5 to 10 minutes of user inactivity.",
                 "Deploy group policy or configuration profile mandating screen saver lock after 10 minutes.",
                 PriorityChoices.LOW),
                ("ENDPT-04", "ENDPT", "Removable USB Storage Restriction",
                 "Unapproved mass storage devices (thumb drives) are blocked or set to read-only via policy.",
                 "Enable endpoint DLP rule preventing unauthorized USB mass storage mounting.",
                 PriorityChoices.MEDIUM),

                # Category 6: BCDR
                ("BCDR-01", "BCDR", "Immutable, Air-Gapped or Cloud Object-Locked Backups",
                 "Critical databases and configurations are backed up to storage with WORM retention.",
                 "Enable AWS S3 Object Lock in Compliance mode or Azure Immutable Blob storage for backups.",
                 PriorityChoices.CRITICAL),
                ("BCDR-02", "BCDR", "Quarterly Backup Restoration Drill",
                 "Full recovery of key systems from cold backup is simulated and verified at least once every 90 days.",
                 "Perform test database restores to isolated staging environments and log RTO/RPO results.",
                 PriorityChoices.HIGH),
                ("BCDR-03", "BCDR", "Documented Disaster Recovery Runbook",
                 "Step-by-step failover instructions exist in an off-network emergency repository.",
                 "Maintain printed or out-of-band offline copies of primary disaster recovery playbooks.",
                 PriorityChoices.MEDIUM),

                # Category 7: DATA
                ("DATA-01", "DATA", "Principle of Least Privilege on File Shares & S3",
                 "Data repositories grant access solely on a documented business need-to-know basis.",
                 "Review IAM policies; revoke wildcard (*) permissions and public bucket access.",
                 PriorityChoices.HIGH),
                ("DATA-02", "DATA", "Database Encryption at Rest and in Transit",
                 "All relational and NoSQL databases enforce TLS connections and encrypted storage volumes.",
                 "Turn on TLS 1.3 requirement on DB connections and enable KMS-managed volume encryption.",
                 PriorityChoices.HIGH),
                ("DATA-03", "DATA", "Data Loss Prevention (DLP) for PII and Financial Data",
                 "Automated filters detect and flag unencrypted credit card numbers, SSNs, or API secrets in emails/chats.",
                 "Configure Purview or Google DLP inspection rules for sensitive regex patterns.",
                 PriorityChoices.MEDIUM),

                # Category 8: NET
                ("NET-01", "NET", "Network Segmentation for Production vs Office",
                 "Corporate Wi-Fi, IoT devices, guest access, and production server environments are segregated by VLANs.",
                 "Implement strict firewall rules between user workstations and production infrastructure.",
                 PriorityChoices.HIGH),
                ("NET-02", "NET", "Zero-Trust Network Access (ZTNA) or Split-Tunnel VPN",
                 "Remote connections verify device health and identity before granting private subnet access.",
                 "Transition from legacy open VPNs to posture-aware Zero-Trust gateways (Cloudflare / Zscaler).",
                 PriorityChoices.HIGH),
                ("NET-03", "NET", "Annual External Penetration Testing",
                 "A certified third-party firm executes black-box and grey-box security penetration tests annually.",
                 "Contract an independent CREST/OSCP accredited firm and document remediation timelines.",
                 PriorityChoices.MEDIUM),

                # Category 9: IR
                ("IR-01", "IR", "Dedicated 24/7 Security Incident Hotline / Slack Channel",
                 "Clear, well-advertised emergency reporting mechanism for suspicious alerts or lost equipment.",
                 "Establish #incident-response channel with automated PagerDuty escalation.",
                 PriorityChoices.HIGH),
                ("IR-02", "IR", "Annual Cybersecurity Tabletop Exercise",
                 "Executive leadership and engineering teams participate in a simulated ransomware scenario.",
                 "Run a tabletop simulation covering containment, communications, legal, and forensic steps.",
                 PriorityChoices.MEDIUM),
                ("IR-03", "IR", "Centralized Log Aggregation with 1-Year Retention",
                 "Firewall, authentication, and endpoint logs stream to SIEM with tamper-resistant retention.",
                 "Verify SIEM ingestion pipeline (Datadog, Splunk, Elastic) and check storage retention policies.",
                 PriorityChoices.HIGH),

                # Category 10: TRAIN
                ("TRAIN-01", "TRAIN", "Mandatory Cybersecurity Onboarding Training",
                 "New hires complete foundational training before receiving access to production systems.",
                 "Enforce completion of security modules in LMS prior to provisioning SSO credentials.",
                 PriorityChoices.MEDIUM),
                ("TRAIN-02", "TRAIN", "Monthly Simulated Phishing Campaigns",
                 "Continuous phishing simulations test employee resilience against spear-phishing tactics.",
                 "Run automated simulated phishing via KnowBe4/Cofense; mandate refresher training on failure.",
                 PriorityChoices.MEDIUM),
                ("TRAIN-03", "TRAIN", "Developer Secure Code Training (OWASP Top 10)",
                 "Software engineers complete role-specific training on SQL injection, XSS, and SSRF prevention.",
                 "Incorporate Secure Code Warrior or OWASP training modules into annual engineering goals.",
                 PriorityChoices.HIGH),
            ]

            item_records = []
            for code, cat_slug, title, desc, guidance, priority in controls_data:
                cat = category_map[cat_slug]
                item, _ = ChecklistItem.objects.update_or_create(
                    template=template,
                    control_code=code,
                    defaults={
                        'category': cat,
                        'title': title,
                        'description': desc,
                        'guidance': guidance,
                        'priority': priority,
                        'is_required': True
                    }
                )
                item_records.append(item)

            self.stdout.write(self.style.SUCCESS(f"Loaded {len(item_records)} CIS/NIST Controls into Global Template v1.0"))

            # 10. Create Completed Baseline Assessment for Apex Financial
            apex_assessment_completed, _ = Assessment.objects.get_or_create(
                organization=org_apex,
                template=template,
                title="Q3 Enterprise Cybersecurity Posture Review",
                defaults={
                    'assigned_to': apex_employee1,
                    'reviewer': apex_analyst,
                    'status': AssessmentStatus.COMPLETED,
                    'score': 84.6,
                    'risk_level': RiskLevel.MODERATE,
                    'notes': "Comprehensive review of cloud assets, identity systems, and endpoint policies conducted for Q3 compliance.",
                    'reviewer_feedback': "Strong identity posture and backup immutability. Identified gaps in DMARC enforcement and USB restriction.",
                    'started_at': timezone.now() - timedelta(days=45),
                    'submitted_at': timezone.now() - timedelta(days=35),
                    'completed_at': timezone.now() - timedelta(days=30),
                }
            )

            # Populate realistic responses for Q3 assessment
            # Items needing improvement: PHISH-01, ENDPT-04, TRAIN-03
            for item in item_records:
                if item.control_code in ['PHISH-01', 'ENDPT-04', 'TRAIN-03']:
                    resp_val = ResponseChoices.NEEDS_IMPROVEMENT
                    notes = f"Currently in planning stage; gap identified during internal review."
                elif item.control_code in ['NET-03']:
                    resp_val = ResponseChoices.NOT_APPLICABLE
                    notes = "Offloaded to parent cloud provider managed infrastructure."
                else:
                    resp_val = ResponseChoices.COMPLIANT
                    notes = "Enforced via central configuration profile and verified operational."

                AssessmentResponse.objects.update_or_create(
                    assessment=apex_assessment_completed,
                    item=item,
                    defaults={'response': resp_val, 'notes': notes, 'evidence_reference': "AuditDoc-2026-Q3"}
                )

            # Re-calculate exact score
            score_data = calculate_assessment_score(apex_assessment_completed)
            apex_assessment_completed.score = score_data['overall_score']
            apex_assessment_completed.risk_level = score_data['risk_level']
            apex_assessment_completed.save()

            # 11. Create Active / In-Progress Assessment for Alice
            apex_assessment_active, _ = Assessment.objects.get_or_create(
                organization=org_apex,
                template=template,
                title="Q4 Cloud & Infrastructure Security Assessment",
                defaults={
                    'assigned_to': apex_employee1,
                    'reviewer': apex_analyst,
                    'status': AssessmentStatus.DRAFT,
                    'score': 0.0,
                    'risk_level': RiskLevel.MODERATE,
                    'notes': "Annual fourth-quarter review focusing on production container clusters and Zero-Trust implementation.",
                    'started_at': timezone.now() - timedelta(days=3),
                }
            )

            for item in item_records:
                # Pre-populate draft with partial completion
                if item.order <= 15:
                    r = ResponseChoices.COMPLIANT
                    n = "Verified in production."
                elif item.control_code in ['MFA-02', 'PATCH-02']:
                    r = ResponseChoices.NEEDS_IMPROVEMENT
                    n = "Hardware key procurement pending budget approval."
                else:
                    r = ResponseChoices.NOT_ASSESSED
                    n = ""

                AssessmentResponse.objects.update_or_create(
                    assessment=apex_assessment_active,
                    item=item,
                    defaults={'response': r, 'notes': n}
                )

            # 12. Create Remediation Tasks Across Lifecycle States
            # Task 1: Verified (Closed)
            item_phish = ChecklistItem.objects.get(template=template, control_code='PHISH-01')
            t1, _ = RemediationTask.objects.update_or_create(
                organization=org_apex,
                title="Enforce DMARC Policy with p=reject on apexfin.com",
                defaults={
                    'assessment': apex_assessment_completed,
                    'item': item_phish,
                    'description': "Upgrade apexfin.com DNS DMARC record from monitor mode (p=none) to strict quarantine or reject to eliminate domain spoofing.",
                    'assigned_to': apex_employee1,
                    'reviewer': apex_analyst,
                    'priority': TaskPriority.HIGH,
                    'due_date': timezone.now().date() - timedelta(days=10),
                    'status': TaskStatus.VERIFIED,
                    'resolution_notes': "Configured Cloudflare DNS with 'v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@apexfin.com; ruf=mailto:dmarc@apexfin.com; rf=afrf; pct=100'. Verified via dmarcian validator.",
                    'reviewer_feedback': "Verified valid TXT record propagation. Zero deliverability issues noted. Marking resolved.",
                    'verified_at': timezone.now() - timedelta(days=8),
                }
            )
            TaskEvidence.objects.get_or_create(
                task=t1,
                uploaded_by=apex_employee1,
                defaults={
                    'notes': "Attached dmarcian analysis report confirming 100% compliant SPF/DKIM alignment.",
                    'attachment_reference': "DMARC-Report-ApexFin-Validated.pdf",
                    'external_url': "https://dmarcian.com/dmarc-inspector/"
                }
            )

            # Task 2: Submitted for Review
            item_endpt = ChecklistItem.objects.get(template=template, control_code='ENDPT-04')
            t2, _ = RemediationTask.objects.update_or_create(
                organization=org_apex,
                title="Deploy USB Mass Storage Restriction via Microsoft Intune",
                defaults={
                    'assessment': apex_assessment_completed,
                    'item': item_endpt,
                    'description': "Configure endpoint policy in Intune to block unauthorized USB mass storage devices to prevent physical data exfiltration.",
                    'assigned_to': apex_employee2,
                    'reviewer': apex_analyst,
                    'priority': TaskPriority.MEDIUM,
                    'due_date': timezone.now().date() + timedelta(days=4),
                    'status': TaskStatus.SUBMITTED_FOR_REVIEW,
                    'resolution_notes': "Created Device Control profile 'Apex-Block-USB-Removable' targeting all corporate laptops. Exceptions configured for approved IronKey encrypted drives only.",
                }
            )
            TaskEvidence.objects.get_or_create(
                task=t2,
                uploaded_by=apex_employee2,
                defaults={
                    'notes': "Screenshot of Intune Device Control policy with 100% device success assignment.",
                    'attachment_reference': "Intune-USB-Policy-Enforced.png"
                }
            )

            # Task 3: In Progress
            item_mfa = ChecklistItem.objects.get(template=template, control_code='MFA-02')
            RemediationTask.objects.update_or_create(
                organization=org_apex,
                title="Procure & Enforce YubiKey 5 FIDO2 Keys for AWS / Cloud Admins",
                defaults={
                    'assessment': apex_assessment_active,
                    'item': item_mfa,
                    'description': "Eliminate mobile push phishing risks by mandating hardware security tokens for all IAM users with AdministratorAccess.",
                    'assigned_to': apex_employee1,
                    'reviewer': apex_analyst,
                    'priority': TaskPriority.CRITICAL,
                    'due_date': timezone.now().date() + timedelta(days=12),
                    'status': TaskStatus.IN_PROGRESS,
                    'resolution_notes': "Order placed for 30 YubiKey 5C NFC units. IdP configuration draft prepared.",
                }
            )

            # Task 4: Open & Overdue
            item_train = ChecklistItem.objects.get(template=template, control_code='TRAIN-03')
            RemediationTask.objects.update_or_create(
                organization=org_apex,
                title="Enroll Engineering Team in Secure Coding & OWASP Top 10 Course",
                defaults={
                    'assessment': apex_assessment_completed,
                    'item': item_train,
                    'description': "Annual training requirement for software developers covering injection, broken authentication, and server-side request forgery.",
                    'assigned_to': apex_employee2,
                    'reviewer': apex_analyst,
                    'priority': TaskPriority.HIGH,
                    'due_date': timezone.now().date() - timedelta(days=3),  # Overdue
                    'status': TaskStatus.OPEN,
                    'description': "Enrollment links must be distributed to all 18 backend engineers.",
                }
            )

            # 13. Notifications
            Notification.objects.get_or_create(
                user=apex_employee1,
                title="Assessment Assigned: Q4 Cloud & Infrastructure Security Review",
                defaults={
                    'organization': org_apex,
                    'message': "Please complete your questionnaire responses before the end of the month.",
                    'category': NotificationCategory.ASSESSMENT,
                    'link_url': f"/assessments/{apex_assessment_active.pk}/wizard/",
                    'is_read': False
                }
            )

            Notification.objects.get_or_create(
                user=apex_analyst,
                title="Remediation Task Awaiting Verification: USB Storage Restriction",
                defaults={
                    'organization': org_apex,
                    'message': "Robert Chen submitted USB Mass Storage Restriction for verification.",
                    'category': NotificationCategory.REMEDIATION,
                    'link_url': f"/remediation/tasks/{t2.pk}/",
                    'is_read': False
                }
            )

            Notification.objects.get_or_create(
                user=apex_admin,
                title="DMARC Policy Enforcement Verified",
                defaults={
                    'organization': org_apex,
                    'message': "Remediation verified for [PHISH-01] on apexfin.com.",
                    'category': NotificationCategory.AUDIT,
                    'link_url': f"/remediation/tasks/{t1.pk}/",
                    'is_read': True
                }
            )

            # 14. Audit Events
            AuditEvent.objects.create(
                actor=superadmin,
                action='GLOBAL_TEMPLATE_PUBLISHED',
                details="Published CyberSafe Baseline Framework v1.0 with 30 CIS/NIST controls.",
                ip_address="10.0.0.1"
            )
            AuditEvent.objects.create(
                actor=apex_admin,
                organization=org_apex,
                action='MEMBER_INVITED',
                details="Sent invitation to newhire.secops@apexfin.com with role EMPLOYEE.",
                ip_address="192.168.1.105"
            )
            AuditEvent.objects.create(
                actor=apex_employee1,
                organization=org_apex,
                action='ASSESSMENT_SUBMITTED',
                details=f"Submitted assessment '{apex_assessment_completed.title}' (Score: {apex_assessment_completed.score}%)",
                ip_address="192.168.1.142"
            )
            AuditEvent.objects.create(
                actor=apex_analyst,
                organization=org_apex,
                action='REMEDIATION_VERIFIED',
                details="Verified resolution for task [PHISH-01] DMARC Policy Enforcement.",
                ip_address="192.168.1.118"
            )

        self.stdout.write(self.style.SUCCESS("CyberSafe database successfully seeded with realistic enterprise data!"))

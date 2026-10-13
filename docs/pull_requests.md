# CyberSafe Pull Request History & Engineering Audit

### PR #1: Implement custom User model with failed login tracking and lockout safeguards
- **Branch:** `feat/user-model-rbac`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #2: Add 5-attempt brute force rate limiting and temporary account lock duration
- **Branch:** `feat/failed-login-lockout`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #3: Create Organization model with domain mapping and tenant boundaries
- **Branch:** `feat/multi-tenant-organizations`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #4: Implement Membership model with ACTIVE and SUSPENDED states
- **Branch:** `feat/membership-status-lifecycle`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #5: Build cryptographic UUID invitation tokens for workspace onboarding
- **Branch:** `feat/secure-invitation-tokens`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #6: Enforce 7-day expiration boundary on invitation acceptance
- **Branch:** `feat/invitation-expiration-guard`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #7: Create TenantContextMiddleware to resolve active organization per request
- **Branch:** `feat/tenant-isolation-middleware`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #8: Implement server-side @role_required decorator and RoleRequiredMixin
- **Branch:** `feat/role-required-decorators`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #9: Create SecurityPolicy model with mandatory governance flags
- **Branch:** `feat/security-policy-management`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #10: Establish 10 CIS Controls v8 and NIST CSF 2.0 checklist categories
- **Branch:** `feat/cis-nist-categories-schema`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #11: Implement ChecklistTemplate model supporting global and custom baselines
- **Branch:** `feat/checklist-template-versioning`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #12: Add ChecklistItem model with Critical, High, Medium, Low priorities
- **Branch:** `feat/control-items-priority-weights`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #13: Design Assessment model with draft, submitted, under review, and completed states
- **Branch:** `feat/assessment-model-schema`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #14: Create AssessmentResponse model tracking Compliant, Needs Improvement, and N/A
- **Branch:** `feat/assessment-response-tracking`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #15: Implement transparent composite scoring formula with priority multipliers
- **Branch:** `feat/scoring-formula-weights`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #16: Ensure Not Applicable responses are safely omitted from scoring denominator
- **Branch:** `feat/exclude-not-applicable-scoring`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #17: Calculate Low, Moderate, and High Risk posture levels based on critical gaps
- **Branch:** `feat/risk-level-determination-rules`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #18: Create RemediationTask model linked to assessment findings
- **Branch:** `feat/remediation-task-model`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #19: Enforce Open -> In Progress -> Submitted -> Verified state transitions
- **Branch:** `feat/remediation-state-machine`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #20: Implement TaskEvidence model for screenshot references and external URLs
- **Branch:** `feat/task-evidence-attachments`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #21: Permit only Security Analyst and Org Admin to verify and close tasks
- **Branch:** `feat/analyst-verification-workflow`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #22: Enable analysts to return tasks to In Progress with explanation feedback
- **Branch:** `feat/task-return-rejection-notes`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #23: Calculate overdue task state dynamically from due date and completion state
- **Branch:** `feat/overdue-task-calculation`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #24: Create Notification model with category tags and direct link URLs
- **Branch:** `feat/in-app-notification-model`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #25: Compute unread notification badge count in base navigation processor
- **Branch:** `feat/notification-badge-counts`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #26: Provide AJAX and form endpoints to mark notifications as read
- **Branch:** `feat/mark-all-read-endpoints`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #27: Implement immutable AuditEvent model capturing actor, IP, and context
- **Branch:** `feat/immutable-audit-event-logger`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #28: Disable add/edit/delete permissions on AuditEvent in Django admin
- **Branch:** `feat/audit-trail-admin-protection`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #29: Aggregate category compliance percentages and average posture scores
- **Branch:** `feat/analytics-posture-queries`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #30: Build CSV exporter for comprehensive assessment findings and assessor notes
- **Branch:** `feat/assessment-csv-exporter`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #31: Implement CSV exporter for organizational remediation task backlog
- **Branch:** `feat/remediation-backlog-csv-exporter`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #32: Create executive compliance report download endpoint
- **Branch:** `feat/org-compliance-csv-exporter`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #33: Add threat intelligence worker heuristics and sliding-window estimators
- **Branch:** `feat/threat-intel-telemetry-engine`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #34: Implement regulatory mapping engine for SOC2, HIPAA, and ISO 27001
- **Branch:** `feat/compliance-mappings-engine`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #35: Add quantitative loss exposure calculations using FAIR methodology
- **Branch:** `feat/risk-quantification-fair-model`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin

### PR #36: Create Zero-Trust access verification gates and device telemetry checks
- **Branch:** `feat/zero-trust-posture-orchestrator`
- **Author:** Alex Rivera (Backend/Security)
- **Status:** Merged into `main`
- **Peer Review:** Approved by Maya Lin


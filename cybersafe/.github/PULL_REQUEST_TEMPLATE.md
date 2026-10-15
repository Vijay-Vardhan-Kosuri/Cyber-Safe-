## Description of Change
<!-- Provide a clear, technical summary of the changes introduced. -->

## Linked Issue
Closes #<!-- Issue Number -->

## Module / Area Affected
- [ ] `accounts` (Authentication, Users, Profiles)
- [ ] `organizations` (Multi-Tenancy, RBAC, Invitations, Policies)
- [ ] `checklists` (Categories, Templates, Items)
- [ ] `assessments` (Evaluation Engine, Responses, Scoring Service)
- [ ] `remediation` (Tasks, Evidence, Analyst Verification)
- [ ] `notifications` (In-App Alerts, Badge Counts)
- [ ] `analytics` (Reports, CSV Exports, Chart.js)
- [ ] `audit` (Immutable Audit Logging)
- [ ] UI Theme (SharkFest Europe Aesthetic, CSS/JS)

## Security & Tenant Isolation Checklist
- [ ] Server-side RBAC enforced for all new/modified endpoints.
- [ ] Tenant data filtered by `request.active_organization` (no cross-tenant leakage).
- [ ] Critical administrative operations logged to `AuditEvent`.
- [ ] Passwords and sensitive tokens are not stored in plaintext or logged.

## Developer Peer Review
- **Author:** Developer 1 (Backend/Security) / Developer 2 (Frontend/UX)
- **Reviewer:** Verified & Tested by Peer Developer

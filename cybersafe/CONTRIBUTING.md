# CyberSafe — Two-Developer Collaboration Guide

This document outlines the software engineering workflow, repository conventions, role boundaries, and branch management strategies for the two developers collaborating on **CyberSafe**.

---

## 1. Developer Role Division

### Developer 1: Backend, Database & Cybersecurity Architecture
- **Primary Focus:**
  - Django project settings, security middleware, and ORM schemas.
  - Multi-tenant data isolation and centralized RBAC decorators/mixins (`permissions.py`).
  - Transparent scoring engine formula (`scoring_service.py`).
  - Remediation state machine (`Open -> In Progress -> Submitted -> Verified`).
  - Immutable audit logging services (`log_audit_event`).
  - Database seed scripts (`seed_cyber_data.py`) and automated unit/integration test suites.

### Developer 2: Frontend, UX & Integration Architecture
- **Primary Focus:**
  - Implementation of the **SharkFest Europe conference aesthetic** (Midnight Navy `#050b14`, Oceanic Blue `#0066cc`, Electric Cyan `#00f0ff`, Crisp White `#f8fafc`).
  - Public landing page with technical hero, live data counters, workflow timeline, and posture limitation disclaimer.
  - Role-specific dashboard layouts for all 4 primary roles.
  - Interactive assessment wizard with dynamic progress bar and draft autosave.
  - Remediation Kanban board, evidence upload modals, and Analyst verification drawers.
  - Chart.js radar, bar, and gauge visualizations.

### Shared Responsibilities
- Conducting formal code reviews on all pull requests.
- Verifying cross-organization isolation and tenant boundaries.
- Running automated test suites before merging into `main`.
- Maintaining documentation, release notes, and architecture diagrams.

---

## 2. Git Branching Strategy

| Branch Type | Format | Example |
| :--- | :--- | :--- |
| **Main / Release** | `main` | Production-ready code |
| **Feature Branches** | `feature/<module>-<description>` | `feature/assessments-scoring-engine` |
| **Security Fixes** | `security/<cve-or-rule>` | `security/enforce-tenant-object-check` |
| **Bug Fixes** | `fix/<issue-id>-<description>` | `fix/14-invitation-token-expiry` |
| **UI & Theme** | `ui/<screen-name>` | `ui/sharkfest-theme-dashboard` |

---

## 3. Commit Message Standards

Follow the Conventional Commits specification:
- `feat(module): description` (e.g., `feat(remediation): implement analyst verification state transition`)
- `fix(module): description` (e.g., `fix(tenant): prevent cross-organization assessment leakage`)
- `sec(auth): description` (e.g., `sec(accounts): add 5-attempt account lockout safeguards`)
- `ui(theme): description` (e.g., `ui(dashboards): apply SharkFest midnight-cyan palette to KPI cards`)
- `test(core): description` (e.g., `test(assessments): verify scoring calculation excludes N/A items`)
- `docs(readme): description` (e.g., `docs(er): add database entity relationship diagram`)

---

## 4. 100+ Commit Target Milestone Roadmap

To demonstrate sustained, professional engineering over the development lifecycle, commits are organized across 6 major milestones:

1. **Milestone 1: Project Setup & Core Schema (Commits 1–18)**
   - Initial project structure, requirements, settings, Docker Compose, custom User, Organization, and Membership models.
2. **Milestone 2: Multi-Tenant RBAC & Onboarding (Commits 19–35)**
   - Tenant middleware, permission mixins, login/logout, cryptographic invitation tokens, and member management.
3. **Milestone 3: CIS/NIST Checklists & Assessment Engine (Commits 36–55)**
   - 10 checklist categories, versioned templates, interactive response wizard, and scoring service.
4. **Milestone 4: Remediation State Machine & Evidence (Commits 56–72)**
   - Task lifecycle states, evidence records, analyst verification/return workflow, and in-app notifications.
5. **Milestone 5: SharkFest Europe UI & Dashboards (Commits 73–88)**
   - Conference aesthetic CSS theme, SVG packet textures, Chart.js radar charts, and 4 role dashboards.
6. **Milestone 6: Analytics, Audit, Tests & Documentation (Commits 89–105+)**
   - CSV exporters, immutable audit trails, comprehensive test suite, CI workflows, and README.

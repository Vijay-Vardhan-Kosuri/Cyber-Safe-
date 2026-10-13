/**
 * CyberSafe Remediation Task Board & State Machine Coordinator
 * Handles client-side task sorting, filter toggles, evidence modal validation, and audit sync.
 */

class RemediationWorkflowCoordinator {
    constructor() {
        this.tasks = [];
        this.activeFilter = 'ALL';
        this.init();
    }

    init() {
        this.cacheDom();
        this.bindEvents();
    }

    cacheDom() {
        this.taskContainer = document.getElementById('remediationTasksGrid');
        this.filterButtons = document.querySelectorAll('[data-task-filter]');
        this.evidenceModal = document.getElementById('evidenceSubmissionModal');
    }

    bindEvents() {
        if (this.filterButtons) {
            this.filterButtons.forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const filter = e.currentTarget.getAttribute('data-task-filter');
                    this.applyFilter(filter);
                });
            });
        }
    }

    applyFilter(status) {
        this.activeFilter = status;
        const taskCards = document.querySelectorAll('.task-card-item');
        taskCards.forEach(card => {
            const cardStatus = card.getAttribute('data-status');
            if (status === 'ALL' || cardStatus === status) {
                card.style.display = 'block';
            } else {
                card.style.display = 'none';
            }
        });
    }

    validateEvidenceInput(notes, url) {
        const errors = [];
        if (!notes || notes.trim().length < 10) {
            errors.push('Resolution remarks must contain at least 10 characters detailing the remediation.');
        }
        if (url && !/^https?:\/\/.+/i.test(url)) {
            errors.push('Evidence artifact reference must be a valid HTTPS URL.');
        }
        return {
            valid: errors.length === 0,
            errors
        };
    }

    computeDaysOverdue(dueDateString) {
        if (!dueDateString) return 0;
        const due = new Date(dueDateString);
        const now = new Date();
        const diffMs = now - due;
        return Math.floor(diffMs / (1000 * 60 * 60 * 24));
    }
}

window.RemediationWorkflowCoordinator = RemediationWorkflowCoordinator;

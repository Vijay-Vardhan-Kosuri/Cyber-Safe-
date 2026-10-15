/**
 * CyberSafe Frontend Interactions & Autosave
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize Bootstrap Tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

    // 2. Assessment Wizard Progress Tracker & Green Selected State
    const wizardForm = document.getElementById('assessment-wizard-form');
    if (wizardForm) {
        const totalRadios = wizardForm.querySelectorAll('.response-radio');
        const progressBar = document.getElementById('wizard-progress-bar');
        const progressCount = document.getElementById('wizard-progress-count');

        function updateProgressAndStyles() {
            const answeredItems = new Set();
            const uniqueQuestions = new Set();

            totalRadios.forEach(r => {
                uniqueQuestions.add(r.name);
                const label = r.closest('.response-option');
                if (r.checked) {
                    if (label) {
                        label.classList.add('is-selected', 'active-green');
                    }
                    if (r.value !== 'NOT_ASSESSED') {
                        answeredItems.add(r.name);
                    }
                } else {
                    if (label) {
                        label.classList.remove('is-selected', 'active-green');
                    }
                }
            });

            const completed = answeredItems.size;
            const total = uniqueQuestions.size;
            const pct = total > 0 ? Math.round((completed / total) * 100) : 0;

            if (progressBar) {
                progressBar.style.width = pct + '%';
                progressBar.setAttribute('aria-valuenow', pct);
            }
            if (progressCount) {
                progressCount.textContent = pct + '%';
            }
        }

        // Option card click handling
        document.querySelectorAll('.response-option').forEach(label => {
            label.addEventListener('click', function () {
                const radio = this.querySelector('input[type="radio"]');
                if (radio) {
                    const group = this.closest('.response-radio-group') || this.closest('.row');
                    if (group) {
                        group.querySelectorAll('.response-option').forEach(opt => {
                            opt.classList.remove('is-selected', 'active-green');
                            const otherRadio = opt.querySelector('input[type="radio"]');
                            if (otherRadio && otherRadio !== radio) {
                                otherRadio.checked = false;
                            }
                        });
                    }
                    radio.checked = true;
                    this.classList.add('is-selected', 'active-green');
                    radio.dispatchEvent(new Event('change', { bubbles: true }));
                    updateProgressAndStyles();
                }
            });
        });

        totalRadios.forEach(r => r.addEventListener('change', updateProgressAndStyles));
        updateProgressAndStyles();
    }

    // 3. Auto-dismiss Alert Messages after 5 seconds
    const autoAlerts = document.querySelectorAll('.alert-dismissible');
    autoAlerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            bsAlert.close();
        }, 6000);
    });
});

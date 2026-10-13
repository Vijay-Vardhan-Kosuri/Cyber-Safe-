/**
 * CyberSafe Frontend Interactions & Autosave
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize Bootstrap Tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

    // 2. Assessment Wizard Progress Tracker
    const wizardForm = document.getElementById('assessment-wizard-form');
    if (wizardForm) {
        const totalRadios = wizardForm.querySelectorAll('.response-radio');
        const progressBar = document.getElementById('wizard-progress-bar');
        const progressCount = document.getElementById('wizard-progress-count');

        function updateProgress() {
            const answeredItems = new Set();
            totalRadios.forEach(r => {
                if (r.checked && r.value !== 'NOT_ASSESSED') {
                    answeredItems.add(r.name);
                }
            });

            const uniqueQuestions = new Set(Array.from(totalRadios).map(r => r.name)).size;
            const completed = answeredItems.size;
            const pct = uniqueQuestions > 0 ? Math.round((completed / uniqueQuestions) * 100) : 0;

            if (progressBar) {
                progressBar.style.width = pct + '%';
                progressBar.setAttribute('aria-valuenow', pct);
            }
            if (progressCount) {
                progressCount.textContent = `${completed} / ${uniqueQuestions} (${pct}%)`;
            }
        }

        totalRadios.forEach(r => r.addEventListener('change', updateProgress));
        updateProgress();
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
